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

#[cfg(feature = "parallel")]
use super::blocked::{GROUP_LEVELS, Group, LEAVES_PER_THREAD, PARALLEL_THRESHOLD_BYTES};
use super::{CantorBasis, CantorError};
use crate::{BinaryFieldExtras, Flat, HardwareField, PackableField, PackedFlat};
use alloc::boxed::Box;
use alloc::vec::Vec;
use core::ops::{Add, AddAssign, Mul};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

const MAX_LEVELS: usize = 64;
const LOW_LOG: usize = 10;

#[cfg(feature = "parallel")]
const TILE_BYTES: usize = 1 << 16;

/// Error returned by `AdditiveFft`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FftError {
    /// The slice length `got` is not 2^log_n = `expected`.
    BadLength {
        /// 2^log_n, the length the transform needs.
        expected: usize,

        /// The length of the slice passed in.
        got: usize,
    },

    /// `log_n` is outside `1..=max`, the sizes `F` supports.
    BadLogN {
        /// The `log_n` passed to `new`.
        log_n: u32,

        /// The largest `log_n` that `F` supports on this target.
        max: u32,
    },

    /// Allocating the twiddle table failed.
    TwiddleAlloc {
        /// The `log_n` passed to `new`.
        log_n: u32,
    },

    /// The `stride` passed to [`LdePlan::run`] is `got`,
    /// under the `width` lanes one point occupies.
    BadStride {
        /// `F::WIDTH`.
        width: usize,

        /// The `stride` passed in.
        got: usize,
    },

    /// The `scratch` passed to [`LdePlan::run`] has length
    /// `got`, under the 2 * 2^log_n it needs.
    ShortScratch {
        /// 2 * 2^log_n.
        need: usize,

        /// The length of the `scratch` passed in.
        got: usize,
    },

    /// The `out` passed to [`LdePlan::run`] has length `got`,
    /// under the end of the last lane the plan writes.
    ShortOut {
        /// `(cosets * 2^log_n - 1) * stride + F::WIDTH`,
        /// `usize::MAX` when that overflows.
        need: usize,

        /// The length of the `out` passed in.
        got: usize,
    },
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
            FftError::BadStride { width, got } => {
                write!(f, "LdePlan stride {got}, needs at least {width}")
            }
            FftError::ShortScratch { need, got } => {
                write!(f, "LdePlan scratch length {got}, needs {need}")
            }
            FftError::ShortOut { need, got } => {
                write!(f, "LdePlan out length {got}, needs {need}")
            }
        }
    }
}

impl core::error::Error for FftError {}

/// One block LDE: the inverse transform of 2^log_n packed
/// points and the forward transforms on fixed cosets, built
/// by [`AdditiveFft::lde_plan`], run by [`LdePlan::run`].
pub struct LdePlan<F> {
    log_n: u32,
    cosets: usize,
    tw: Twiddles<F>,
    chains: Box<[Flat<F>]>,
}

/// In-place additive FFT over a 2^log_n
/// subspace of a binary tower field.
///
/// # Examples
///
/// ```
/// use hekate_math::{AdditiveFft, Block16, Flat, HardwareField};
///
/// let log_n = 10;
/// let fft = AdditiveFft::<Block16>::new(log_n)?;
///
/// let coeffs: Vec<Flat<Block16>> = (0..1u32 << log_n)
///     .map(|i| Block16::from(i).to_hardware())
///     .collect();
///
/// let mut data = coeffs.clone();
/// fft.forward_scalar(&mut data)?;
/// fft.inverse_scalar(&mut data)?;
///
/// assert_eq!(data, coeffs);
/// # Ok::<(), hekate_math::FftError>(())
/// ```
pub struct AdditiveFft<F> {
    log_n: u32,
    tw: Twiddles<F>,
}

impl<F: BinaryFieldExtras + HardwareField> AdditiveFft<F> {
    /// Derives the Cantor basis (via solve_quadratic)
    /// and the twiddle schedule for transform size 2^log_n.
    ///
    /// # Errors
    /// `BadLogN` unless log_n is in 1..=min(F::BITS, usize::BITS - 1)
    /// and F admits a Cantor basis of that size;
    /// `TwiddleAlloc` if the twiddle table cannot be allocated.
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

        let low_log = (log_n as usize - 1).min(LOW_LOG);

        let mut low = Vec::new();

        low.try_reserve_exact(1 << low_log)
            .map_err(|_| FftError::TwiddleAlloc { log_n })?;

        low.push(Flat::from_raw(F::ZERO));

        for &beta in &basis.betas()[1..=low_log] {
            for t in 0..low.len() {
                let tw = low[t] + beta;
                low.push(tw);
            }
        }

        Ok(Self {
            log_n,
            tw: Twiddles {
                low: low.into_boxed_slice(),
                basis,
            },
        })
    }

    /// Evaluates in place: novel-basis coefficients of f become
    /// `data[j] = f(point(j))`, point as in [`CantorBasis::point`].
    ///
    /// # Errors
    /// `BadLength` unless `data.len() == 2^log_n`.
    pub fn forward_scalar(&self, data: &mut [Flat<F>]) -> Result<(), FftError> {
        self.forward_coset_scalar(data, Flat::from_raw(F::ZERO))
    }

    /// Interpolates in place: the inverse of [`Self::forward_scalar`].
    ///
    /// # Errors
    /// `BadLength` unless `data.len() == 2^log_n`.
    pub fn inverse_scalar(&self, data: &mut [Flat<F>]) -> Result<(), FftError> {
        self.inverse_coset_scalar(data, Flat::from_raw(F::ZERO))
    }

    /// Evaluates in place on the coset `offset + W_log_n`:
    /// `data[j] = f(offset + point(j))`.
    ///
    /// # Errors
    /// `BadLength` unless `data.len() == 2^log_n`.
    pub fn forward_coset_scalar(
        &self,
        data: &mut [Flat<F>],
        offset: Flat<F>,
    ) -> Result<(), FftError> {
        self.check_len(data.len())?;
        self.fwd_levels(data, offset, fwd_butterflies);

        Ok(())
    }

    /// Interpolates in place: the inverse of
    /// [`Self::forward_coset_scalar`] at the same `offset`.
    ///
    /// # Errors
    /// `BadLength` unless `data.len() == 2^log_n`.
    pub fn inverse_coset_scalar(
        &self,
        data: &mut [Flat<F>],
        offset: Flat<F>,
    ) -> Result<(), FftError> {
        self.check_len(data.len())?;
        self.inv_levels(data, offset, inv_butterflies);

        Ok(())
    }

    /// Runs [`Self::forward_scalar`] on each of the `F::WIDTH`
    /// lanes: lane l of `data[j]` is element j of input l.
    ///
    /// # Errors
    /// `BadLength` unless `data.len() == 2^log_n`.
    pub fn forward(&self, data: &mut [PackedFlat<F>]) -> Result<(), FftError> {
        self.forward_coset(data, Flat::from_raw(F::ZERO))
    }

    /// Runs [`Self::inverse_scalar`] on each of the `F::WIDTH` lanes.
    ///
    /// # Errors
    /// `BadLength` unless `data.len() == 2^log_n`.
    pub fn inverse(&self, data: &mut [PackedFlat<F>]) -> Result<(), FftError> {
        self.inverse_coset(data, Flat::from_raw(F::ZERO))
    }

    /// Runs [`Self::forward_coset_scalar`] on each of the `F::WIDTH` lanes.
    ///
    /// # Errors
    /// `BadLength` unless `data.len() == 2^log_n`.
    pub fn forward_coset(
        &self,
        data: &mut [PackedFlat<F>],
        offset: Flat<F>,
    ) -> Result<(), FftError> {
        self.check_len(data.len())?;
        self.fwd_levels(data, offset, fwd_butterflies);

        Ok(())
    }

    /// Runs [`Self::inverse_coset_scalar`] on each of the `F::WIDTH` lanes.
    ///
    /// # Errors
    /// `BadLength` unless `data.len() == 2^log_n`.
    pub fn inverse_coset(
        &self,
        data: &mut [PackedFlat<F>],
        offset: Flat<F>,
    ) -> Result<(), FftError> {
        self.check_len(data.len())?;
        self.inv_levels(data, offset, inv_butterflies);

        Ok(())
    }

    /// Builds the plan that runs [`Self::inverse`] and then
    /// [`Self::forward_coset`] at each of `offsets` on one
    /// block of packed points; see [`LdePlan::run`].
    ///
    /// # Errors
    /// `TwiddleAlloc` if the plan's tables cannot be allocated.
    pub fn lde_plan(&self, offsets: &[Flat<F>]) -> Result<LdePlan<F>, FftError> {
        let levels = self.log_n as usize;

        let alloc = |_| FftError::TwiddleAlloc { log_n: self.log_n };

        let mut low = Vec::new();
        low.try_reserve_exact(self.tw.low.len()).map_err(alloc)?;
        low.extend_from_slice(&self.tw.low);

        let len = offsets
            .len()
            .checked_mul(levels)
            .ok_or(FftError::TwiddleAlloc { log_n: self.log_n })?;

        let mut chains = Vec::new();
        chains.try_reserve_exact(len).map_err(alloc)?;

        for &offset in offsets {
            let mut c = offset;
            for _ in 0..levels {
                chains.push(c);

                c = c * c + c;
            }
        }

        Ok(LdePlan {
            log_n: self.log_n,
            cosets: offsets.len(),
            tw: Twiddles {
                low: low.into_boxed_slice(),
                basis: self.tw.basis.clone(),
            },
            chains: chains.into_boxed_slice(),
        })
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
    /// (`blk[r]`, `blk[r+s]`) with twiddle `coset + tw.at(b)`.
    fn fwd_levels<T, K>(&self, data: &mut [T], offset: Flat<F>, kernel: K)
    where
        T: Copy + Default + Send,
        K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
    {
        let levels = self.log_n as usize;
        let chain = coset_chain(offset, levels);

        #[cfg(feature = "parallel")]
        if parallel_eligible(data) {
            // One pool entry per transform: from outside the pool,
            // each parallel pass would inject and block on its own.
            rayon::scope(|_| fwd_parallel(data, &self.tw, &chain[..levels], &kernel));
            return;
        }

        for l in (0..levels).rev() {
            self.tw.blocks(data, 0, chain[l], 1usize << l, &kernel);
        }
    }

    /// No β^-1 anywhere:
    /// paired points differ by β_0 = 1.
    fn inv_levels<T, K>(&self, data: &mut [T], offset: Flat<F>, kernel: K)
    where
        T: Copy + Default + Send,
        K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
    {
        #[cfg(feature = "parallel")]
        if parallel_eligible(data) {
            let levels = self.log_n as usize;
            let chain = coset_chain(offset, levels);

            // One pool entry per transform: from outside the pool,
            // each parallel pass would inject and block on its own.
            rayon::scope(|_| inv_parallel(data, &self.tw, &chain[..levels], &kernel));

            return;
        }

        let mut c = offset;
        for l in 0..self.log_n as usize {
            self.tw.blocks(data, 0, c, 1usize << l, &kernel);

            c = c * c + c;
        }
    }
}

impl<F: BinaryFieldExtras + HardwareField> LdePlan<F> {
    /// Runs the plan on one block: the inverse of `data` into the
    /// first half of `scratch` (any content on entry), then point u
    /// of coset j unpacked to `out[(j * n + u) * stride..][..F::WIDTH]`.
    ///
    /// # Errors
    /// `BadLength` unless `data.len() == n`, `ShortScratch` under `2n`,
    /// `BadStride` if `stride < F::WIDTH`, `ShortOut` unless `out`
    /// reaches the end of the last lane written.
    pub fn run(
        &self,
        data: &[PackedFlat<F>],
        scratch: &mut [PackedFlat<F>],
        out: &mut [Flat<F>],
        stride: usize,
    ) -> Result<(), FftError> {
        let n = 1usize << self.log_n;
        let levels = self.log_n as usize;
        let width = <Flat<F> as PackableField>::WIDTH;

        if data.len() != n {
            return Err(FftError::BadLength {
                expected: n,
                got: data.len(),
            });
        }

        if scratch.len() < 2 * n {
            return Err(FftError::ShortScratch {
                need: 2 * n,
                got: scratch.len(),
            });
        }

        if stride < width {
            return Err(FftError::BadStride { width, got: stride });
        }

        let need = match self.cosets {
            0 => 0,
            c => c
                .checked_mul(n)
                .and_then(|points| (points - 1).checked_mul(stride))
                .and_then(|last| last.checked_add(width))
                .unwrap_or(usize::MAX),
        };

        if out.len() < need {
            return Err(FftError::ShortOut {
                need,
                got: out.len(),
            });
        }

        let zero = Flat::from_raw(F::ZERO);
        let (a, b) = scratch.split_at_mut(n);
        let b = &mut b[..n];

        inv_bottom_into(&self.tw, data, a);

        for l in 1..levels {
            self.tw.blocks(a, 0, zero, 1usize << l, &inv_butterflies);
        }

        for (j, chain) in self.chains.chunks_exact(levels).enumerate() {
            let rows = &mut out[j * n * stride..];

            if levels == 1 {
                fwd_bottom_into(&self.tw, a, chain[0], rows, stride);
                continue;
            }

            fwd_top_into(a, b, chain[levels - 1]);

            for l in (1..levels - 1).rev() {
                self.tw
                    .blocks(b, 0, chain[l], 1usize << l, &fwd_butterflies);
            }

            fwd_bottom_into(&self.tw, b, chain[0], rows, stride);
        }

        Ok(())
    }
}

struct Twiddles<F> {
    // low[t] = Σ_{bit i of t} β_{i+1}, flat basis
    low: Box<[Flat<F>]>,
    basis: CantorBasis<F>,
}

impl<F: BinaryFieldExtras + HardwareField> Twiddles<F> {
    #[cfg(feature = "parallel")]
    fn at(&self, b: usize) -> Flat<F> {
        let low_log = self.low.len().trailing_zeros() as usize;
        let high = self.basis.beta_sum(b >> low_log, low_log + 1);

        self.low[b & (self.low.len() - 1)] + high
    }

    /// Runs `kernel` on blocks b0.. of one level,
    /// block b with twiddle `coset + at(b)`.
    fn blocks<T, K>(&self, data: &mut [T], b0: usize, coset: Flat<F>, s: usize, kernel: &K)
    where
        K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
    {
        let len = self.low.len();
        let low_log = len.trailing_zeros() as usize;
        let nb = data.len() / (2 * s);

        let mut done = 0;
        while done < nb {
            let b = b0 + done;
            let u = b & (len - 1);
            let take = (len - u).min(nb - done);

            let high = self.basis.beta_sum(b >> low_log, low_log + 1);
            let blk = &mut data[2 * s * done..2 * s * (done + take)];

            blocks_serial(blk, &self.low[u..u + take], coset + high, s, kernel);

            done += take;
        }
    }

    fn for_each_block(&self, coset: Flat<F>, nb: usize, mut f: impl FnMut(usize, Flat<F>)) {
        let len = self.low.len();
        let low_log = len.trailing_zeros() as usize;

        let mut done = 0;
        while done < nb {
            let take = len.min(nb - done);
            let high = coset + self.basis.beta_sum(done >> low_log, low_log + 1);

            for (i, &t) in self.low[..take].iter().enumerate() {
                f(done + i, high + t);
            }

            done += take;
        }
    }
}

pub(super) fn fwd_butterflies<F, T>(lo: &mut [T], hi: &mut [T], tw: Flat<F>)
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

fn coset_chain<F: HardwareField>(offset: Flat<F>, levels: usize) -> [Flat<F>; MAX_LEVELS] {
    let mut chain = [Flat::from_raw(F::ZERO); MAX_LEVELS];
    let mut c = offset;

    for slot in chain.iter_mut().take(levels) {
        *slot = c;
        c = c * c + c;
    }

    chain
}

#[cfg(feature = "parallel")]
fn parallel_eligible<T>(data: &[T]) -> bool {
    size_of_val(data) >= PARALLEL_THRESHOLD_BYTES
}

#[cfg(feature = "parallel")]
fn fwd_parallel<F, T, K>(data: &mut [T], tw: &Twiddles<F>, chain: &[Flat<F>], kernel: &K)
where
    F: BinaryFieldExtras + HardwareField,
    T: Copy + Default + Send,
    K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
{
    let levels = chain.len();
    let tile_log = tile_log::<T>().min(levels);
    let budget = rayon::current_num_threads() * LEAVES_PER_THREAD;

    let twiddle = |l: usize, b: usize| chain[l] + tw.at(b);

    let mut hi = levels;
    while hi > tile_log {
        let lo = hi.saturating_sub(GROUP_LEVELS).max(tile_log);
        let group = Group {
            lo,
            hi,
            forward: true,
            kernel,
        };

        group.spans(data, 0, budget, &twiddle);

        hi = lo;
    }

    data.par_chunks_exact_mut(1 << tile_log)
        .enumerate()
        .for_each(|(i, tile)| {
            for l in (0..tile_log).rev() {
                tw.blocks(tile, i << (tile_log - l - 1), chain[l], 1usize << l, kernel);
            }
        });
}

#[cfg(feature = "parallel")]
fn inv_parallel<F, T, K>(data: &mut [T], tw: &Twiddles<F>, chain: &[Flat<F>], kernel: &K)
where
    F: BinaryFieldExtras + HardwareField,
    T: Copy + Default + Send,
    K: Fn(&mut [T], &mut [T], Flat<F>) + Sync,
{
    let levels = chain.len();
    let tile_log = tile_log::<T>().min(levels);
    let budget = rayon::current_num_threads() * LEAVES_PER_THREAD;

    let twiddle = |l: usize, b: usize| chain[l] + tw.at(b);

    data.par_chunks_exact_mut(1 << tile_log)
        .enumerate()
        .for_each(|(i, tile)| {
            for (l, &coset) in chain[..tile_log].iter().enumerate() {
                tw.blocks(tile, i << (tile_log - l - 1), coset, 1usize << l, kernel);
            }
        });

    let mut lo = tile_log;
    while lo < levels {
        let hi = (lo + GROUP_LEVELS).min(levels);
        let group = Group {
            lo,
            hi,
            forward: false,
            kernel,
        };

        group.spans(data, 0, budget, &twiddle);

        lo = hi;
    }
}

#[cfg(feature = "parallel")]
fn tile_log<T>() -> usize {
    (TILE_BYTES / size_of::<T>().max(1)).max(1).ilog2() as usize
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

fn inv_bottom_into<F>(tw: &Twiddles<F>, src: &[PackedFlat<F>], dst: &mut [PackedFlat<F>])
where
    F: BinaryFieldExtras + HardwareField,
{
    let (pairs, _) = src.as_chunks::<2>();
    let (slots, _) = dst.as_chunks_mut::<2>();

    tw.for_each_block(Flat::from_raw(F::ZERO), pairs.len(), |b, t| {
        let qv = pairs[b][0] + pairs[b][1];

        slots[b][0] = pairs[b][0] + qv * t;
        slots[b][1] = qv;
    });
}

fn fwd_top_into<F: HardwareField>(src: &[PackedFlat<F>], dst: &mut [PackedFlat<F>], tw: Flat<F>) {
    let s = src.len() / 2;
    let (lo, hi) = src.split_at(s);
    let (dlo, dhi) = dst.split_at_mut(s);

    for (((&p, &q), dl), dh) in lo.iter().zip(hi).zip(dlo).zip(dhi) {
        let v = p + q * tw;

        *dl = v;
        *dh = v + q;
    }
}

fn fwd_bottom_into<F>(
    tw: &Twiddles<F>,
    src: &[PackedFlat<F>],
    coset: Flat<F>,
    out: &mut [Flat<F>],
    stride: usize,
) where
    F: BinaryFieldExtras + HardwareField,
{
    let width = <Flat<F> as PackableField>::WIDTH;
    let (pairs, _) = src.as_chunks::<2>();

    tw.for_each_block(coset, pairs.len(), |b, t| {
        let q = pairs[b][1];
        let v = pairs[b][0] + q * t;
        let at = 2 * b * stride;

        <Flat<F> as PackableField>::unpack(v, &mut out[at..at + width]);
        <Flat<F> as PackableField>::unpack(v + q, &mut out[at + stride..at + stride + width]);
    });
}
