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
        self.fwd_scalar(data, 0, 1, self.log_n, offset);

        Ok(())
    }

    /// Inverse over the coset offset + W_log_n.
    pub fn inverse_coset_scalar(
        &self,
        data: &mut [Flat<F>],
        offset: Flat<F>,
    ) -> Result<(), FftError> {
        self.check_len(data.len())?;
        self.inv_scalar(data, 0, 1, self.log_n, offset);

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
        self.fwd_packed(data, 0, 1, self.log_n, offset);

        Ok(())
    }

    /// Packed inverse over the coset offset + W_log_n.
    pub fn inverse_coset(
        &self,
        data: &mut [PackedFlat<F>],
        offset: Flat<F>,
    ) -> Result<(), FftError> {
        self.check_len(data.len())?;
        self.inv_packed(data, 0, 1, self.log_n, offset);

        Ok(())
    }

    fn check_len(&self, got: usize) -> Result<(), FftError> {
        let expected = 1usize << self.log_n;

        if got != expected {
            return Err(FftError::BadLength { expected, got });
        }

        Ok(())
    }

    // Decimation-in-time radix-2 butterfly (Gao–Mateer).
    // σ(x) = x^2 + x maps W_d two-to-one onto W_{d-1}; the
    // pair (2t, 2t+1) differs by β_0 = 1, the twiddle is
    // coset + twiddles[t] and the odd output is just + q.
    // Strided recursion keeps the output in natural order.
    fn fwd_scalar(&self, data: &mut [Flat<F>], off: usize, stride: usize, d: u32, coset: Flat<F>) {
        if d == 0 {
            return;
        }

        let half = 1usize << (d - 1);
        let child = coset * coset + coset;

        self.fwd_scalar(data, off, stride * 2, d - 1, child);
        self.fwd_scalar(data, off + stride, stride * 2, d - 1, child);

        for t in 0..half {
            let tw = coset + self.twiddles[t];
            let i0 = off + 2 * t * stride;
            let i1 = i0 + stride;

            let p = data[i0];
            let q = data[i1];
            let lo = p + tw * q;

            data[i0] = lo;
            data[i1] = lo + q;
        }
    }

    // Inverse butterfly:
    // q = o0 + o1, then p = o0 + tw*q.
    // No β^-1 needed (pairs differ by β_0 = 1).
    fn inv_scalar(&self, data: &mut [Flat<F>], off: usize, stride: usize, d: u32, coset: Flat<F>) {
        if d == 0 {
            return;
        }

        let half = 1usize << (d - 1);
        let child = coset * coset + coset;

        for t in 0..half {
            let tw = coset + self.twiddles[t];
            let i0 = off + 2 * t * stride;
            let i1 = i0 + stride;

            let o0 = data[i0];
            let o1 = data[i1];
            let q = o0 + o1;

            data[i0] = o0 + tw * q;
            data[i1] = q;
        }

        self.inv_scalar(data, off, stride * 2, d - 1, child);
        self.inv_scalar(data, off + stride, stride * 2, d - 1, child);
    }

    fn fwd_packed(
        &self,
        data: &mut [PackedFlat<F>],
        off: usize,
        stride: usize,
        d: u32,
        coset: Flat<F>,
    ) {
        if d == 0 {
            return;
        }

        let half = 1usize << (d - 1);
        let child = coset * coset + coset;

        self.fwd_packed(data, off, stride * 2, d - 1, child);
        self.fwd_packed(data, off + stride, stride * 2, d - 1, child);

        for t in 0..half {
            let tw = coset + self.twiddles[t];
            let i0 = off + 2 * t * stride;
            let i1 = i0 + stride;

            let p = data[i0];
            let q = data[i1];
            let lo = F::add_hardware_packed(p, F::mul_hardware_scalar_packed(q, tw));

            data[i0] = lo;
            data[i1] = F::add_hardware_packed(lo, q);
        }
    }

    fn inv_packed(
        &self,
        data: &mut [PackedFlat<F>],
        off: usize,
        stride: usize,
        d: u32,
        coset: Flat<F>,
    ) {
        if d == 0 {
            return;
        }

        let half = 1usize << (d - 1);
        let child = coset * coset + coset;

        for t in 0..half {
            let tw = coset + self.twiddles[t];
            let i0 = off + 2 * t * stride;
            let i1 = i0 + stride;

            let o0 = data[i0];
            let o1 = data[i1];
            let q = F::add_hardware_packed(o0, o1);

            data[i0] = F::add_hardware_packed(o0, F::mul_hardware_scalar_packed(q, tw));
            data[i1] = q;
        }

        self.inv_packed(data, off, stride * 2, d - 1, child);
        self.inv_packed(data, off + stride, stride * 2, d - 1, child);
    }
}
