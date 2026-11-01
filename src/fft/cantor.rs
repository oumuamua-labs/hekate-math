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

//! The Cantor basis of a binary tower field, its domain
//! points, and pruned novel-basis evaluation at sorted indices.

#[cfg(feature = "parallel")]
use super::additive::fwd_butterflies;
#[cfg(feature = "parallel")]
use super::blocked::{GROUP_LEVELS, Group, LEAVES_PER_THREAD, PARALLEL_THRESHOLD_BYTES};
use crate::{BinaryFieldExtras, Flat, HardwareField};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

const MAX_DIM: usize = 64;

#[cfg(feature = "parallel")]
const NODE_BYTES: usize = 1 << 16;
#[cfg(feature = "parallel")]
const PASS_BYTES: usize = 1 << 17;
#[cfg(feature = "parallel")]
const CHUNK_BYTES: usize = 1 << 15;

/// Error returned by `CantorBasis`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CantorError {
    /// `dim` is outside `1..=max`, `max = min(F::BITS, 64)`.
    BadDim {
        /// The `dim` passed to `new`.
        dim: usize,

        /// `min(F::BITS, 64)`.
        max: usize,
    },

    /// β_at does not exist: x^2 + x = β_{at-1} has no root.
    ChainEnds {
        /// Index of the first β the chain lacks.
        at: usize,
    },

    /// The coefficient count `got` is not a power of two.
    BadCoeffLength {
        /// `coeffs.len()`.
        got: usize,
    },

    /// `index >= 2^dim`, outside the domain.
    IndexOutOfRange {
        /// The rejected domain index.
        index: usize,

        /// The basis dimension.
        dim: usize,
    },

    /// `indices[at] < indices[at - 1]`.
    UnsortedIndices {
        /// The first position where `indices` decreases.
        at: usize,
    },

    /// `scratch.len()` is `got`, under `need = coeffs.len() - 1`.
    ShortScratch {
        /// `coeffs.len() - 1`.
        need: usize,

        /// `scratch.len()`.
        got: usize,
    },

    /// `out.len()` is `got`; `indices.len()` is `expected`.
    BadOutLength {
        /// `indices.len()`.
        expected: usize,

        /// `out.len()`.
        got: usize,
    },
}

impl core::fmt::Display for CantorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CantorError::BadDim { dim, max } => {
                write!(f, "CantorBasis dimension {dim}, expected 1..={max}")
            }
            CantorError::ChainEnds { at } => {
                write!(f, "CantorBasis chain has no element {at}")
            }
            CantorError::BadCoeffLength { got } => {
                write!(
                    f,
                    "CantorBasis coefficient count {got} is not a power of two"
                )
            }
            CantorError::IndexOutOfRange { index, dim } => {
                write!(
                    f,
                    "CantorBasis index {index} needs more than {dim} basis elements"
                )
            }
            CantorError::UnsortedIndices { at } => {
                write!(f, "CantorBasis indices decrease at position {at}")
            }
            CantorError::ShortScratch { need, got } => {
                write!(f, "CantorBasis scratch length {got}, needs {need}")
            }
            CantorError::BadOutLength { expected, got } => {
                write!(f, "CantorBasis output length {got}, expected {expected}")
            }
        }
    }
}

impl core::error::Error for CantorError {}

/// Cantor basis β_0 = 1, β_{i-1} = β_i^2 + β_i
/// (Cantor 1989), flat. Index j is the point Σ β_i
/// over set bits i of j, as `AdditiveFft` orders outputs.
#[derive(Clone)]
pub struct CantorBasis<F> {
    dim: usize,
    betas: [Flat<F>; MAX_DIM],
}

impl<F: BinaryFieldExtras + HardwareField> CantorBasis<F> {
    /// Derives β_0..β_{dim-1} with `solve_quadratic`.
    ///
    /// # Errors
    /// `BadDim` unless `1 <= dim <= min(F::BITS, 64)`;
    /// `ChainEnds` if some β_i has no successor.
    pub fn new(dim: usize) -> Result<Self, CantorError> {
        let max = F::BITS.min(MAX_DIM);

        if dim == 0 || dim > max {
            return Err(CantorError::BadDim { dim, max });
        }

        let mut betas = [Flat::from_raw(F::ZERO); MAX_DIM];
        let mut beta = F::ONE;

        betas[0] = beta.to_hardware();

        for (at, slot) in betas.iter_mut().enumerate().take(dim).skip(1) {
            beta = F::solve_quadratic(beta).ok_or(CantorError::ChainEnds { at })?;
            *slot = beta.to_hardware();
        }

        Ok(Self { dim, betas })
    }

    /// Returns β_0..β_{dim-1} in the flat basis.
    pub fn betas(&self) -> &[Flat<F>] {
        &self.betas[..self.dim]
    }

    /// Returns the domain point of `index`:
    /// Σ β_i over its set bits i.
    ///
    /// # Errors
    /// `IndexOutOfRange` if `index >= 2^dim`.
    pub fn point(&self, index: usize) -> Result<Flat<F>, CantorError> {
        self.check_index(index)?;

        Ok(self.beta_sum(index, 0))
    }

    /// Writes `out[i] = f(shift + point(indices[i]))`, f having
    /// novel-basis `coeffs`: `forward_coset_scalar` of
    /// zero-extended `coeffs`, read at sorted `indices`.
    ///
    /// # Errors
    /// A non-power-of-two `coeffs.len()`, `out` not as
    /// long as `indices`, `scratch` under
    /// `coeffs.len() - 1`, decreasing or out-of-range indices.
    pub fn evaluate_at(
        &self,
        coeffs: &[Flat<F>],
        shift: Flat<F>,
        indices: &[usize],
        scratch: &mut [Flat<F>],
        out: &mut [Flat<F>],
    ) -> Result<(), CantorError> {
        let k = coeffs.len();

        if !k.is_power_of_two() {
            return Err(CantorError::BadCoeffLength { got: k });
        }

        if out.len() != indices.len() {
            return Err(CantorError::BadOutLength {
                expected: indices.len(),
                got: out.len(),
            });
        }

        if scratch.len() < k - 1 {
            return Err(CantorError::ShortScratch {
                need: k - 1,
                got: scratch.len(),
            });
        }

        if let Some(at) = indices.windows(2).position(|w| w[1] < w[0]) {
            return Err(CantorError::UnsortedIndices { at: at + 1 });
        }

        if let Some(&last) = indices.last() {
            self.check_index(last)?;
        }

        let log_k = k.trailing_zeros() as usize;

        if log_k == 0 {
            out.fill(coeffs[0]);
            return Ok(());
        }

        let mut cosets = [Flat::from_raw(F::ZERO); MAX_DIM];
        let mut c = shift;

        for slot in cosets.iter_mut().take(log_k) {
            *slot = c;
            c = c * c + c;
        }

        #[cfg(feature = "parallel")]
        if size_of_val(coeffs) >= PARALLEL_THRESHOLD_BYTES {
            rayon::scope(|_| self.evaluate_parallel(coeffs, log_k, indices, &cosets, scratch, out));
            return Ok(());
        }

        let mut rest = indices;
        let mut rest_out = out;

        while let Some(&first) = rest.first() {
            let class = first >> log_k;
            let len = rest.partition_point(|&j| j >> log_k == class);

            let (head, tail) = rest.split_at(len);
            let (head_out, tail_out) = core::mem::take(&mut rest_out).split_at_mut(len);

            self.fold(coeffs, log_k - 1, head, &cosets, scratch, head_out);

            rest = tail;
            rest_out = tail_out;
        }

        Ok(())
    }

    pub(super) fn beta_sum(&self, bits: usize, first: usize) -> Flat<F> {
        let mut acc = Flat::from_raw(F::ZERO);
        let mut rest = bits;

        while rest != 0 {
            acc += self.betas[first + rest.trailing_zeros() as usize];
            rest &= rest - 1;
        }

        acc
    }

    fn check_index(&self, index: usize) -> Result<(), CantorError> {
        match index.checked_shr(self.dim as u32) {
            Some(high) if high != 0 => Err(CantorError::IndexOutOfRange {
                index,
                dim: self.dim,
            }),
            _ => Ok(()),
        }
    }

    fn fold(
        &self,
        a: &[Flat<F>],
        level: usize,
        indices: &[usize],
        cosets: &[Flat<F>],
        scratch: &mut [Flat<F>],
        out: &mut [Flat<F>],
    ) {
        let s = 1usize << level;
        let (lo, hi) = a.split_at(s);

        let split = indices.partition_point(|&j| (j >> level) & 1 == 0);
        let (left, right) = indices.split_at(split);
        let (left_out, right_out) = out.split_at_mut(split);

        let mut tw = cosets[level] + self.beta_sum(indices[0] >> (level + 1), 1);
        if left.is_empty() {
            tw += self.betas[0];
        }

        let (below, mine) = scratch.split_at_mut(s - 1);
        let buf = &mut mine[..s];

        for ((slot, &p), &q) in buf.iter_mut().zip(lo).zip(hi) {
            *slot = p + q * tw;
        }

        if level == 0 {
            let right_value = if left.is_empty() {
                buf[0]
            } else {
                buf[0] + hi[0]
            };

            left_out.fill(buf[0]);
            right_out.fill(right_value);

            return;
        }

        if !left.is_empty() {
            self.fold(buf, level - 1, left, cosets, below, left_out);

            if right.is_empty() {
                return;
            }

            for (slot, &q) in buf.iter_mut().zip(hi) {
                *slot += q;
            }
        }

        self.fold(buf, level - 1, right, cosets, below, right_out);
    }

    #[cfg(feature = "parallel")]
    fn evaluate_parallel(
        &self,
        coeffs: &[Flat<F>],
        log_k: usize,
        indices: &[usize],
        cosets: &[Flat<F>],
        scratch: &mut [Flat<F>],
        out: &mut [Flat<F>],
    ) {
        let mut rest = indices;
        let mut rest_out = out;

        while let Some(&first) = rest.first() {
            let class = first >> log_k;
            let len = rest.partition_point(|&j| j >> log_k == class);

            let (head, tail) = rest.split_at(len);
            let (head_out, tail_out) = core::mem::take(&mut rest_out).split_at_mut(len);

            self.root(coeffs, log_k - 1, head, cosets, scratch, head_out);

            rest = tail;
            rest_out = tail_out;
        }
    }

    /// Evaluates one class from `coeffs`: its two children in
    /// turn in `scratch[..2^level]`, the rest as their mirror.
    #[cfg(feature = "parallel")]
    fn root(
        &self,
        coeffs: &[Flat<F>],
        level: usize,
        indices: &[usize],
        cosets: &[Flat<F>],
        scratch: &mut [Flat<F>],
        out: &mut [Flat<F>],
    ) {
        if level == 0 {
            return self.fold(coeffs, level, indices, cosets, scratch, out);
        }

        let s = 1usize << level;
        let (lo, hi) = coeffs.split_at(s);

        let split = indices.partition_point(|&j| (j >> level) & 1 == 0);

        let (left, right) = indices.split_at(split);
        let (left_out, right_out) = out.split_at_mut(split);

        let tw = cosets[level] + self.beta_sum(indices[0] >> (level + 1), 1);
        let (buf, mirror) = scratch[..2 * s - 1].split_at_mut(s);

        if !left.is_empty() {
            halve(buf, lo, hi, tw);
            self.node(buf, mirror, level - 1, left, cosets, left_out);
        }

        if !right.is_empty() {
            halve(buf, lo, hi, tw + self.betas[0]);
            self.node(buf, mirror, level - 1, right, cosets, right_out);
        }
    }

    /// Evaluates the node in `buf` (2^(level+1) values, `mirror`
    /// its scratch): serial fold under `NODE_BYTES`, a level
    /// group if half its descendants are live, else one level.
    #[cfg(feature = "parallel")]
    fn node(
        &self,
        buf: &mut [Flat<F>],
        mirror: &mut [Flat<F>],
        level: usize,
        indices: &[usize],
        cosets: &[Flat<F>],
        out: &mut [Flat<F>],
    ) {
        if level == 0 || size_of_val(buf) < NODE_BYTES {
            return self.fold(buf, level, indices, cosets, mirror, out);
        }

        let b = indices[0] >> (level + 1);
        let r = GROUP_LEVELS.min(level);

        if dense(indices, level + 1 - r, r) {
            let budget = rayon::current_num_threads() * LEAVES_PER_THREAD;

            let twiddle = |l: usize, block: usize| cosets[l] + self.beta_sum(block, 1);

            let group = Group {
                lo: level + 1 - r,
                hi: level + 1,
                forward: true,
                kernel: &fwd_butterflies::<F, Flat<F>>,
            };

            group.spans(buf, b, budget, &twiddle);

            return self.descend(buf, mirror, level - r, indices, cosets, out);
        }

        let s = 1usize << level;
        let split = indices.partition_point(|&j| (j >> level) & 1 == 0);

        let (left, right) = indices.split_at(split);
        let (left_out, right_out) = out.split_at_mut(split);

        let tw = cosets[level] + self.beta_sum(b, 1);

        let (lo, hi) = buf.split_at_mut(s);
        let (mirror_lo, mirror_hi) = mirror.split_at_mut(s);

        match (left.is_empty(), right.is_empty()) {
            (false, false) => {
                butterflies(lo, hi, tw);

                rayon::join(
                    || self.node(lo, mirror_lo, level - 1, left, cosets, left_out),
                    || self.node(hi, mirror_hi, level - 1, right, cosets, right_out),
                );
            }
            (false, true) => {
                absorb(lo, hi, tw);
                self.node(lo, mirror_lo, level - 1, left, cosets, left_out);
            }
            (true, _) => {
                absorb(lo, hi, tw + self.betas[0]);
                self.node(lo, mirror_lo, level - 1, right, cosets, right_out);
            }
        }
    }

    /// Evaluates each node of `level` that `buf` holds,
    /// halving `buf` and `mirror` by index bit.
    #[cfg(feature = "parallel")]
    fn descend(
        &self,
        buf: &mut [Flat<F>],
        mirror: &mut [Flat<F>],
        level: usize,
        indices: &[usize],
        cosets: &[Flat<F>],
        out: &mut [Flat<F>],
    ) {
        if indices.is_empty() {
            return;
        }

        if buf.len() == 2 << level {
            return self.node(buf, mirror, level, indices, cosets, out);
        }

        let half = buf.len() / 2;
        let bit = half.trailing_zeros() as usize;
        let split = indices.partition_point(|&j| (j >> bit) & 1 == 0);

        let (buf_lo, buf_hi) = buf.split_at_mut(half);
        let (mirror_lo, mirror_hi) = mirror.split_at_mut(half);
        let (left, right) = indices.split_at(split);
        let (left_out, right_out) = out.split_at_mut(split);

        rayon::join(
            || self.descend(buf_lo, mirror_lo, level, left, cosets, left_out),
            || self.descend(buf_hi, mirror_hi, level, right, cosets, right_out),
        );
    }
}

/// Reports whether the indices reach at least half
/// of the 2^r keys `j >> shift` they range over.
#[cfg(feature = "parallel")]
fn dense(indices: &[usize], shift: usize, r: usize) -> bool {
    let need = 1usize << (r - 1);

    let mut live = 0;
    let mut rest = indices;

    while let Some(&first) = rest.first() {
        live += 1;

        if live >= need {
            return true;
        }

        let key = first >> shift;
        rest = &rest[rest.partition_point(|&j| j >> shift == key)..];
    }

    false
}

#[cfg(feature = "parallel")]
fn halve<F: HardwareField>(buf: &mut [Flat<F>], lo: &[Flat<F>], hi: &[Flat<F>], tw: Flat<F>) {
    let body = |b: &mut [Flat<F>], x: &[Flat<F>], y: &[Flat<F>]| {
        for ((slot, &p), &q) in b.iter_mut().zip(x).zip(y) {
            *slot = p + q * tw;
        }
    };

    if size_of_val(buf) < PASS_BYTES {
        return body(buf, lo, hi);
    }

    let chunk = chunk_len::<F>();

    buf.par_chunks_mut(chunk)
        .zip(lo.par_chunks(chunk))
        .zip(hi.par_chunks(chunk))
        .for_each(|((b, x), y)| body(b, x, y));
}

#[cfg(feature = "parallel")]
fn absorb<F: HardwareField>(lo: &mut [Flat<F>], hi: &[Flat<F>], tw: Flat<F>) {
    let body = |x: &mut [Flat<F>], y: &[Flat<F>]| {
        for (p, &q) in x.iter_mut().zip(y) {
            *p += q * tw;
        }
    };

    if size_of_val(lo) < PASS_BYTES {
        return body(lo, hi);
    }

    let chunk = chunk_len::<F>();

    lo.par_chunks_mut(chunk)
        .zip(hi.par_chunks(chunk))
        .for_each(|(x, y)| body(x, y));
}

#[cfg(feature = "parallel")]
fn butterflies<F: HardwareField>(lo: &mut [Flat<F>], hi: &mut [Flat<F>], tw: Flat<F>) {
    if size_of_val(lo) < PASS_BYTES {
        return fwd_butterflies(lo, hi, tw);
    }

    let chunk = chunk_len::<F>();

    lo.par_chunks_mut(chunk)
        .zip(hi.par_chunks_mut(chunk))
        .for_each(|(x, y)| fwd_butterflies(x, y, tw));
}

#[cfg(feature = "parallel")]
fn chunk_len<F>() -> usize {
    (CHUNK_BYTES / size_of::<Flat<F>>().max(1)).max(1)
}
