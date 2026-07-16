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

//! Gao–Mateer additive FFT (Cantor basis).

use crate::{BinaryFieldExtras, Flat, HardwareField, PackedFlat};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ops::{Add, AddAssign, Mul};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

const MAX_LEVELS: usize = 64;

#[cfg(feature = "parallel")]
const TILE: usize = 1024;

#[cfg(feature = "parallel")]
const PARALLEL_THRESHOLD_BYTES: usize = 1 << 20;

#[cfg(feature = "parallel")]
const MIN_PAR_BLOCKS: usize = 16;

/// Error returned by the additive-FFT transforms.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FftError {
    BadLength { expected: usize, got: usize },
}

impl core::fmt::Display for FftError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FftError::BadLength { expected, got } => {
                write!(f, "AdditiveFft data length {got}, expected {expected}")
            }
        }
    }
}

impl core::error::Error for FftError {}

/// In-place additive FFT over a 2^log_n subspace of a binary
/// tower field. Transforms return `Err(FftError::BadLength)`
/// unless data.len() == 2^log_n; on success the buffer
/// is overwritten in place.
pub struct AdditiveFft<F> {
    log_n: u32,

    // twiddles[t] = Σ_{bit i of t} β_{i+1},
    // flat basis.
    twiddles: Box<[Flat<F>]>,
}

impl<F: BinaryFieldExtras + HardwareField> AdditiveFft<F> {
    /// Derives the Cantor basis (via solve_quadratic) and
    /// the twiddle schedule for transform size 2^log_n.
    /// This one-time allocation is the only heap use;
    /// the transforms are in-place.
    ///
    /// # Panics
    /// If log_n is not in 1..=min(F::BITS, 63),
    /// or F admits no Cantor basis of that size.
    pub fn new(log_n: u32) -> Self {
        assert!(
            (1..=F::BITS).contains(&(log_n as usize)) && log_n < usize::BITS,
            "AdditiveFft: log_n must be in 1..=min(F::BITS, 63)"
        );

        let dim = log_n as usize;

        let mut lift: Vec<Flat<F>> = Vec::with_capacity(dim - 1);
        let mut beta = F::ONE;

        for _ in 1..dim {
            beta = F::solve_quadratic(beta).expect("field admits no Cantor basis of this size");
            lift.push(beta.to_hardware());
        }

        let half = 1usize << (log_n - 1);

        let mut twiddles = Vec::with_capacity(half);
        for t in 0..half {
            let mut acc = Flat::from_raw(F::ZERO);
            let mut bits = t;

            while bits != 0 {
                let j = bits.trailing_zeros() as usize;
                acc += lift[j];
                bits &= bits - 1;
            }

            twiddles.push(acc);
        }

        Self {
            log_n,
            twiddles: twiddles.into_boxed_slice(),
        }
    }

    /// Forward: novel-basis coefficients to evaluations.
    pub fn forward_scalar(&self, data: &mut [Flat<F>]) -> Result<(), FftError> {
        self.forward_coset_scalar(data, Flat::from_raw(F::ZERO))
    }

    /// Inverse: evaluations to novel-basis coefficients.
    pub fn inverse_scalar(&self, data: &mut [Flat<F>]) -> Result<(), FftError> {
        self.inverse_coset_scalar(data, Flat::from_raw(F::ZERO))
    }

    /// Forward over the coset offset + W_log_n.
    pub fn forward_coset_scalar(
        &self,
        data: &mut [Flat<F>],
        offset: Flat<F>,
    ) -> Result<(), FftError> {
        self.check_len(data.len())?;
        self.fwd_levels(data, offset, fwd_butterflies);

        Ok(())
    }

    /// Inverse over the coset offset + W_log_n.
    pub fn inverse_coset_scalar(
        &self,
        data: &mut [Flat<F>],
        offset: Flat<F>,
    ) -> Result<(), FftError> {
        self.check_len(data.len())?;
        self.inv_levels(data, offset, inv_butterflies);

        Ok(())
    }

    /// Forward, F::WIDTH column-lanes per element in lockstep.
    pub fn forward(&self, data: &mut [PackedFlat<F>]) -> Result<(), FftError> {
        self.forward_coset(data, Flat::from_raw(F::ZERO))
    }

    /// Inverse, F::WIDTH column-lanes per element in lockstep.
    pub fn inverse(&self, data: &mut [PackedFlat<F>]) -> Result<(), FftError> {
        self.inverse_coset(data, Flat::from_raw(F::ZERO))
    }

    /// Packed forward over the coset offset + W_log_n.
    pub fn forward_coset(
        &self,
        data: &mut [PackedFlat<F>],
        offset: Flat<F>,
    ) -> Result<(), FftError> {
        self.check_len(data.len())?;
        self.fwd_levels(data, offset, fwd_butterflies);

        Ok(())
    }

    /// Packed inverse over the coset offset + W_log_n.
    pub fn inverse_coset(
        &self,
        data: &mut [PackedFlat<F>],
        offset: Flat<F>,
    ) -> Result<(), FftError> {
        self.check_len(data.len())?;
        self.inv_levels(data, offset, inv_butterflies);

        Ok(())
    }

    fn check_len(&self, got: usize) -> Result<(), FftError> {
        let expected = 1usize << self.log_n;
        if got != expected {
            return Err(FftError::BadLength { expected, got });
        }

        Ok(())
    }

    // Every depth-ℓ node shares the coset σ^ℓ(offset),
    // σ(x) = x^2 + x; a level's butterflies tile into
    // contiguous 2s-blocks (s = 2^ℓ), block b pairing
    // (blk[r], blk[r+s]) with twiddle coset + twiddles[b].
    fn fwd_levels<T, K>(&self, data: &mut [T], offset: Flat<F>, kernel: K)
    where
        T: Send,
        K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
    {
        let levels = self.log_n as usize;

        let mut chain = [Flat::from_raw(F::ZERO); MAX_LEVELS];
        let mut c = offset;

        for slot in chain.iter_mut().take(levels) {
            *slot = c;
            c = c * c + c;
        }

        for l in (0..levels).rev() {
            pass(data, &self.twiddles, chain[l], 1usize << l, &kernel);
        }
    }

    // No β^-1 anywhere:
    // paired points differ by β_0 = 1.
    fn inv_levels<T, K>(&self, data: &mut [T], offset: Flat<F>, kernel: K)
    where
        T: Send,
        K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
    {
        let mut c = offset;
        for l in 0..self.log_n as usize {
            pass(data, &self.twiddles, c, 1usize << l, &kernel);
            c = c * c + c;
        }
    }
}

// data.len() is 2^log_n (check_len), every level
// tiles exactly; kernel gets a block's aligned halves.
fn pass<F, T, K>(data: &mut [T], twiddles: &[Flat<F>], coset: Flat<F>, s: usize, kernel: &K)
where
    F: HardwareField,
    T: Send,
    K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
{
    let block = 2 * s;
    let tws = &twiddles[..data.len() / block];

    #[cfg(feature = "parallel")]
    if size_of_val(data) >= PARALLEL_THRESHOLD_BYTES {
        if block <= TILE {
            assert!(
                data.len().is_multiple_of(TILE),
                "parallel tiling drops a tail: data.len()={} not a multiple of TILE={TILE}",
                data.len()
            );

            // Many small blocks: tile-spans
            // of whole blocks per work item.
            data.par_chunks_exact_mut(TILE)
                .zip(tws.par_chunks_exact(TILE / block))
                .for_each(|(span, span_tws)| blocks_serial(span, span_tws, coset, s, kernel));
        } else if tws.len() >= MIN_PAR_BLOCKS {
            // Mid levels: one block per work item.
            data.par_chunks_exact_mut(block)
                .zip(tws.par_iter())
                .for_each(|(blk, &t)| {
                    let (lo, hi) = blk.split_at_mut(s);
                    kernel(lo, hi, coset + t);
                });
        } else {
            // Deepest levels, too few blocks to spread:
            // split each block's halves into aligned tiles.
            for (blk, &t) in data.chunks_exact_mut(block).zip(tws) {
                let tw = coset + t;
                let (lo, hi) = blk.split_at_mut(s);

                lo.par_chunks_mut(TILE)
                    .zip(hi.par_chunks_mut(TILE))
                    .for_each(|(l, h)| kernel(l, h, tw));
            }
        }

        return;
    }

    blocks_serial(data, tws, coset, s, kernel);
}

fn blocks_serial<F, T, K>(data: &mut [T], tws: &[Flat<F>], coset: Flat<F>, s: usize, kernel: &K)
where
    F: HardwareField,
    K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
{
    for (blk, &t) in data.chunks_exact_mut(2 * s).zip(tws) {
        let (lo, hi) = blk.split_at_mut(s);
        kernel(lo, hi, coset + t);
    }
}

fn fwd_butterflies<F, T>(lo: &mut [T], hi: &mut [T], tw: Flat<F>)
where
    F: HardwareField,
    T: Copy + Add<Output = T> + Mul<Flat<F>, Output = T>,
{
    for (p, q) in lo.iter_mut().zip(hi.iter_mut()) {
        let qv = *q;
        let v = *p + qv * tw;

        *p = v;
        *q = v + qv;
    }
}

fn inv_butterflies<F, T>(lo: &mut [T], hi: &mut [T], tw: Flat<F>)
where
    F: HardwareField,
    T: Copy + AddAssign + Add<Output = T> + Mul<Flat<F>, Output = T>,
{
    for (p, q) in lo.iter_mut().zip(hi.iter_mut()) {
        let qv = *p + *q;
        *p += qv * tw;
        *q = qv;
    }
}
