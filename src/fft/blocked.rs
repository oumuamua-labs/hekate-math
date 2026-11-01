// SPDX-License-Identifier: Apache-2.0
// This file is part of the hekate-math project.
// Copyright (C) 2026 Andrei Kochergin <andrei@oumuamua.dev>
// Copyright (C) 2026 Oumuamua Labs <info@oumuamua.dev>.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Level groups for the parallel transforms:
//! several levels of butterflies per pass over memory.

use crate::{Flat, HardwareField};

pub(super) const PARALLEL_THRESHOLD_BYTES: usize = 1 << 20;
pub(super) const GROUP_LEVELS: usize = 5;
pub(super) const LEAVES_PER_THREAD: usize = 8;

const ROWS: usize = 1 << GROUP_LEVELS;
const GATHER_BYTES: usize = 1 << 14;

/// Levels lo..hi of a transform, run over 2^hi-element
/// spans seen as 2^(hi-lo) rows of 2^lo elements.
pub(super) struct Group<'a, K> {
    pub(super) lo: usize,
    pub(super) hi: usize,
    pub(super) forward: bool,
    pub(super) kernel: &'a K,
}

impl<K> Group<'_, K> {
    /// Runs the group on each span of `data`, span i being
    /// span first + i of the transform; `twiddle(l, b)`
    /// is the twiddle of block b of level l.
    pub(super) fn spans<F, T, W>(&self, data: &mut [T], first: usize, budget: usize, twiddle: &W)
    where
        F: HardwareField,
        T: Copy + Default + Send,
        K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
        W: Fn(usize, usize) -> Flat<F> + Sync,
    {
        let span = 1usize << self.hi;
        let count = data.len() >> self.hi;

        if count >= 2 && budget >= 2 {
            let (left, right) = data.split_at_mut((count / 2) * span);

            rayon::join(
                || self.spans(left, first, budget / 2, twiddle),
                || self.spans(right, first + count / 2, budget - budget / 2, twiddle),
            );

            return;
        }

        for (i, blk) in data.chunks_exact_mut(span).enumerate() {
            let mut tws = [Flat::from_raw(F::ZERO); ROWS];
            for l in self.lo..self.hi {
                let d = self.hi - 1 - l;
                for q in 0..1usize << d {
                    tws[(1 << d) - 1 + q] = twiddle(l, ((first + i) << d) + q);
                }
            }

            self.span(blk, &tws, budget);
        }
    }

    /// Runs the group on one span, block q of level
    /// hi - 1 - d twiddled by `tws[2^d - 1 + q]`.
    fn span<F, T>(&self, blk: &mut [T], tws: &[Flat<F>; ROWS], budget: usize)
    where
        F: HardwareField,
        T: Copy + Default + Send,
        K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
    {
        let mut rows: [&mut [T]; ROWS] = core::array::from_fn(|_| Default::default());
        for (slot, row) in rows.iter_mut().zip(blk.chunks_exact_mut(1 << self.lo)) {
            *slot = row;
        }

        self.columns(rows, tws, budget);
    }

    fn columns<'r, F, T>(&self, mut rows: [&'r mut [T]; ROWS], tws: &[Flat<F>; ROWS], budget: usize)
    where
        F: HardwareField,
        T: Copy + Default + Send,
        K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
    {
        let nrows = 1usize << (self.hi - self.lo);
        let width = rows[0].len();
        let band = (gather_len(size_of::<T>()) / ROWS).max(1);

        if width >= 2 * band && budget >= 2 {
            let mut right: [&'r mut [T]; ROWS] = core::array::from_fn(|_| Default::default());
            for (row, slot) in rows[..nrows].iter_mut().zip(right.iter_mut()) {
                let (a, b) = core::mem::take(row).split_at_mut(width / 2);

                *row = a;
                *slot = b;
            }

            rayon::join(
                || self.columns(rows, tws, budget / 2),
                || self.columns(right, tws, budget - budget / 2),
            );

            return;
        }

        let rows = &mut rows[..nrows];

        match size_of::<T>() {
            0..=4 => self.bands::<F, T, { gather_len(4) }>(rows, tws),
            5..=8 => self.bands::<F, T, { gather_len(8) }>(rows, tws),
            9..=16 => self.bands::<F, T, { gather_len(16) }>(rows, tws),
            17..=32 => self.bands::<F, T, { gather_len(32) }>(rows, tws),
            _ => self.bands::<F, T, { gather_len(64) }>(rows, tws),
        }
    }

    // The buffer stays out of the recursive frames above.
    #[inline(never)]
    fn bands<F, T, const N: usize>(&self, rows: &mut [&mut [T]], tws: &[Flat<F>; ROWS])
    where
        F: HardwareField,
        T: Copy + Default,
        K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
    {
        let width = rows[0].len();
        let band = (N / ROWS).min(width);

        let mut gather = [T::default(); N];

        let buf = &mut gather[..rows.len() * band];

        for c in (0..width).step_by(band) {
            for (dst, row) in buf.chunks_exact_mut(band).zip(rows.iter()) {
                dst.copy_from_slice(&row[c..c + band]);
            }

            self.levels(buf, band, tws);

            for (src, row) in buf.chunks_exact(band).zip(rows.iter_mut()) {
                row[c..c + band].copy_from_slice(src);
            }
        }
    }

    fn levels<F, T>(&self, buf: &mut [T], band: usize, tws: &[Flat<F>; ROWS])
    where
        F: HardwareField,
        K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
    {
        let depth = self.hi - self.lo;

        for step in 0..depth {
            let d = if self.forward { step } else { depth - 1 - step };
            let half = band << (depth - 1 - d);

            for (q, blk) in buf.chunks_exact_mut(2 * half).enumerate() {
                let (top, bottom) = blk.split_at_mut(half);
                (self.kernel)(top, bottom, tws[(1 << d) - 1 + q]);
            }
        }
    }
}

const fn gather_len(size: usize) -> usize {
    match size {
        0..=4 => GATHER_BYTES / 4,
        5..=8 => GATHER_BYTES / 8,
        9..=16 => GATHER_BYTES / 16,
        17..=32 => GATHER_BYTES / 32,
        _ => GATHER_BYTES / 64,
    }
}
