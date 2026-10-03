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

use super::{CantorBasis, CantorError};
use crate::{BinaryFieldExtras, Flat, HardwareField, PackedFlat};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ops::{Add, AddAssign, Mul};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

const MAX_LEVELS: usize = 64;

#[cfg(feature = "parallel")]
const TILE_LOG: usize = 10;

#[cfg(feature = "parallel")]
const TILE: usize = 1 << TILE_LOG;

#[cfg(feature = "parallel")]
const PARALLEL_THRESHOLD_BYTES: usize = 1 << 20;

/// Error returned by `AdditiveFft`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FftError {
    BadLength { expected: usize, got: usize },
    BadLogN { log_n: u32, max: u32 },
    TwiddleAlloc { log_n: u32 },
}

impl core::fmt::Display for FftError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FftError::BadLength { expected, got } => {
                write!(f, "AdditiveFft data length {got}, expected {expected}")
            }
            FftError::BadLogN { log_n, max } => {
                write!(f, "AdditiveFft log_n {log_n}, expected 1..={max}")
            }
            FftError::TwiddleAlloc { log_n } => {
                write!(
                    f,
                    "AdditiveFft log_n {log_n}: twiddle table allocation failed"
                )
            }
        }
    }
}

impl core::error::Error for FftError {}

/// In-place additive FFT over a 2^log_n
/// subspace of a binary tower field.
pub struct AdditiveFft<F> {
    log_n: u32,

    // twiddles[t] = Σ_{bit i of t} β_{i+1},
    // flat basis.
    twiddles: Box<[Flat<F>]>,
}

impl<F: BinaryFieldExtras + HardwareField> AdditiveFft<F> {
    /// Derives the Cantor basis (via solve_quadratic)
    /// and the twiddle schedule for transform size 2^log_n.
    ///
    /// # Errors
    /// `BadLogN` unless log_n is in 1..=min(F::BITS, 63)
    /// and F admits a Cantor basis of that size;
    /// `TwiddleAlloc` if the 2^(log_n-1)-entry
    /// twiddle table cannot be allocated.
    pub fn new(log_n: u32) -> Result<Self, FftError> {
        let max = F::BITS.min(usize::BITS as usize - 1) as u32;

        if log_n == 0 || log_n > max {
            return Err(FftError::BadLogN { log_n, max });
        }

        let basis = CantorBasis::<F>::new(log_n as usize).map_err(|e| match e {
            CantorError::ChainEnds { at } => FftError::BadLogN {
                log_n,
                max: at as u32,
            },
            _ => FftError::BadLogN { log_n, max },
        })?;

        let half = 1usize << (log_n - 1);

        let mut twiddles = Vec::new();
        twiddles
            .try_reserve_exact(half)
            .map_err(|_| FftError::TwiddleAlloc { log_n })?;

        twiddles.push(Flat::from_raw(F::ZERO));

        for &beta in &basis.betas()[1..] {
            for t in 0..twiddles.len() {
                let tw = twiddles[t] + beta;
                twiddles.push(tw);
            }
        }

        Ok(Self {
            log_n,
            twiddles: twiddles.into_boxed_slice(),
        })
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

    /// Every depth-ℓ node shares the coset σ^ℓ(offset),
    /// σ(x) = x^2 + x; a level's butterflies tile into
    /// contiguous 2s-blocks (s = 2^ℓ), block b pairing
    /// (blk[r], blk[r+s]) with twiddle coset + twiddles[b].
    fn fwd_levels<T, K>(&self, data: &mut [T], offset: Flat<F>, kernel: K)
    where
        T: Send,
        K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
    {
        let levels = self.log_n as usize;
        let chain = coset_chain(offset, levels);

        #[cfg(feature = "parallel")]
        if parallel_eligible(data) {
            // One pool entry per transform: from outside the pool,
            // each parallel pass would inject and block on its own.
            rayon::scope(|_| fwd_parallel(data, &self.twiddles, &chain[..levels], &kernel));
            return;
        }

        for l in (0..levels).rev() {
            pass(data, &self.twiddles, chain[l], 1usize << l, &kernel);
        }
    }

    /// No β^-1 anywhere:
    /// paired points differ by β_0 = 1.
    fn inv_levels<T, K>(&self, data: &mut [T], offset: Flat<F>, kernel: K)
    where
        T: Send,
        K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
    {
        #[cfg(feature = "parallel")]
        if parallel_eligible(data) {
            let levels = self.log_n as usize;
            let chain = coset_chain(offset, levels);

            // One pool entry per transform: from outside the pool,
            // each parallel pass would inject and block on its own.
            rayon::scope(|_| inv_parallel(data, &self.twiddles, &chain[..levels], &kernel));

            return;
        }

        let mut c = offset;
        for l in 0..self.log_n as usize {
            pass(data, &self.twiddles, c, 1usize << l, &kernel);
            c = c * c + c;
        }
    }
}

fn coset_chain<F: HardwareField>(offset: Flat<F>, levels: usize) -> [Flat<F>; MAX_LEVELS] {
    let mut chain = [Flat::from_raw(F::ZERO); MAX_LEVELS];
    let mut c = offset;

    for slot in chain.iter_mut().take(levels) {
        *slot = c;
        c = c * c + c;
    }

    chain
}

/// data.len() is 2^log_n (check_len), every level
/// tiles exactly; kernel gets a block's aligned halves.
fn pass<F, T, K>(data: &mut [T], twiddles: &[Flat<F>], coset: Flat<F>, s: usize, kernel: &K)
where
    F: HardwareField,
    T: Send,
    K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
{
    let tws = &twiddles[..data.len() / (2 * s)];

    blocks_serial(data, tws, coset, s, kernel);
}

#[cfg(feature = "parallel")]
fn parallel_eligible<T>(data: &[T]) -> bool {
    size_of_val(data) >= PARALLEL_THRESHOLD_BYTES && data.len() >= TILE
}

#[cfg(feature = "parallel")]
fn fwd_parallel<F, T, K>(data: &mut [T], twiddles: &[Flat<F>], chain: &[Flat<F>], kernel: &K)
where
    F: HardwareField,
    T: Send,
    K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
{
    for l in (TILE_LOG..chain.len()).rev() {
        wide_pass(data, twiddles, chain[l], 1usize << l, kernel);
    }

    data.par_chunks_exact_mut(TILE)
        .enumerate()
        .for_each(|(i, tile)| {
            for l in (0..TILE_LOG).rev() {
                tile_pass(tile, i, twiddles, chain[l], l, kernel);
            }
        });
}

#[cfg(feature = "parallel")]
fn inv_parallel<F, T, K>(data: &mut [T], twiddles: &[Flat<F>], chain: &[Flat<F>], kernel: &K)
where
    F: HardwareField,
    T: Send,
    K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
{
    data.par_chunks_exact_mut(TILE)
        .enumerate()
        .for_each(|(i, tile)| {
            for (l, &coset) in chain[..TILE_LOG].iter().enumerate() {
                tile_pass(tile, i, twiddles, coset, l, kernel);
            }
        });

    for (l, &coset) in chain.iter().enumerate().skip(TILE_LOG) {
        wide_pass(data, twiddles, coset, 1usize << l, kernel);
    }
}

#[cfg(feature = "parallel")]
fn tile_pass<F, T, K>(
    tile: &mut [T],
    i: usize,
    twiddles: &[Flat<F>],
    coset: Flat<F>,
    l: usize,
    kernel: &K,
) where
    F: HardwareField,
    K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
{
    let per = TILE >> (l + 1);

    blocks_serial(
        tile,
        &twiddles[i * per..(i + 1) * per],
        coset,
        1usize << l,
        kernel,
    );
}

#[cfg(feature = "parallel")]
fn wide_pass<F, T, K>(data: &mut [T], twiddles: &[Flat<F>], coset: Flat<F>, s: usize, kernel: &K)
where
    F: HardwareField,
    T: Send,
    K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
{
    let tws = &twiddles[..data.len() / (2 * s)];

    data.par_chunks_exact_mut(2 * s)
        .zip(tws.par_iter())
        .for_each(|(blk, &t)| {
            let tw = coset + t;
            let (lo, hi) = blk.split_at_mut(s);

            lo.par_chunks_mut(TILE)
                .zip(hi.par_chunks_mut(TILE))
                .for_each(|(l, h)| kernel(l, h, tw));
        });
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
