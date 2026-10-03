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

//! Systematic Reed–Solomon encoding on the additive FFT.

use super::{AdditiveFft, FftError};
use crate::{BinaryFieldExtras, Flat, HardwareField, PackedFlat};

/// Error returned by the Reed–Solomon encoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum RsError {
    /// `log_k` is outside `1..log_n`.
    BadRate {
        /// The `log_k` passed to `new`.
        log_k: u32,

        /// The `log_n` passed to `new`.
        log_n: u32,
    },

    /// `log_n` exceeds `max_log_n`, the largest size `F` supports.
    FieldTooSmall {
        /// The `log_n` passed to `new`.
        log_n: u32,

        /// The largest `log_n` that `F` supports on this target.
        max_log_n: u32,
    },

    /// `msg` or `out` has length `got`; it needs `expected`, k or n.
    BadLength {
        /// k for `msg`, n for `out`.
        expected: usize,

        /// The length of the rejected buffer.
        got: usize,
    },

    /// Allocating a 2^log_size-point twiddle table failed.
    TwiddleAlloc {
        /// The `log_k` or `log_n` of the failing transform.
        log_size: u32,
    },
}

impl core::fmt::Display for RsError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            RsError::BadRate { log_k, log_n } => {
                write!(
                    f,
                    "ReedSolomon rate: log_k {log_k} must satisfy 1 <= log_k < log_n {log_n}"
                )
            }
            RsError::FieldTooSmall { log_n, max_log_n } => {
                write!(
                    f,
                    "ReedSolomon log_n {log_n} exceeds the maximum {max_log_n} \
                     = min(field degree, usize::BITS - 1)"
                )
            }
            RsError::BadLength { expected, got } => {
                write!(f, "ReedSolomon buffer length {got}, expected {expected}")
            }
            RsError::TwiddleAlloc { log_size } => {
                write!(
                    f,
                    "ReedSolomon 2^{log_size}-point twiddle table allocation failed"
                )
            }
        }
    }
}

impl core::error::Error for RsError {}

impl From<FftError> for RsError {
    fn from(e: FftError) -> Self {
        match e {
            FftError::BadLength { expected, got } => RsError::BadLength { expected, got },
            FftError::BadLogN { log_n, max } => RsError::FieldTooSmall {
                log_n,
                max_log_n: max,
            },
            FftError::TwiddleAlloc { log_n } => RsError::TwiddleAlloc { log_size: log_n },
        }
    }
}

/// Systematic Reed–Solomon `[n, k, n-k+1]` encoder
/// over the additive-FFT subspaces `W_k ⊂ W_n`:
/// `encode(msg)[..k] == msg` (Lin–Chung–Han 2014).
pub struct ReedSolomon<F> {
    fft_k: AdditiveFft<F>,
    fft_n: AdditiveFft<F>,
    k: usize,
    n: usize,
}

impl<F: BinaryFieldExtras + HardwareField> ReedSolomon<F> {
    /// Builds the encoder for `k = 2^log_k` message and `n = 2^log_n`
    /// codeword symbols. The only allocation is the two twiddle schedules.
    ///
    /// # Errors
    /// `BadRate` unless `1 <= log_k < log_n`; `FieldTooSmall`
    /// if `log_n > min(F::BITS, usize::BITS - 1)`;
    /// `TwiddleAlloc` if a twiddle table cannot be allocated.
    pub fn new(log_k: u32, log_n: u32) -> Result<Self, RsError> {
        if log_k < 1 || log_k >= log_n {
            return Err(RsError::BadRate { log_k, log_n });
        }

        let max_log_n = F::BITS.min(usize::BITS as usize - 1) as u32;

        if log_n > max_log_n {
            return Err(RsError::FieldTooSmall { log_n, max_log_n });
        }

        Ok(Self {
            fft_k: AdditiveFft::new(log_k)?,
            fft_n: AdditiveFft::new(log_n)?,
            k: 1usize << log_k,
            n: 1usize << log_n,
        })
    }

    /// Returns k, the message length per row.
    pub fn message_len(&self) -> usize {
        self.k
    }

    /// Returns n, the codeword length per row.
    pub fn codeword_len(&self) -> usize {
        self.n
    }

    /// Encodes one row: `out[..k] == msg` on return,
    /// `out[k..]` the n - k parity symbols.
    ///
    /// # Errors
    /// `BadLength` unless `msg.len() == k` and `out.len() == n`.
    pub fn encode_scalar(&self, msg: &[Flat<F>], out: &mut [Flat<F>]) -> Result<(), RsError> {
        self.check(msg.len(), out.len())?;

        out[..self.k].copy_from_slice(msg);
        out[self.k..].fill(Flat::from_raw(F::ZERO));

        self.fft_k.inverse_scalar(&mut out[..self.k])?;
        self.fft_n.forward_scalar(out)?;

        Ok(())
    }

    /// Encodes `F::WIDTH` rows in lockstep, one per lane;
    /// lengths count packed elements.
    ///
    /// # Errors
    /// `BadLength` unless `msg.len() == k` and `out.len() == n`.
    pub fn encode(&self, msg: &[PackedFlat<F>], out: &mut [PackedFlat<F>]) -> Result<(), RsError> {
        self.check(msg.len(), out.len())?;

        out[..self.k].copy_from_slice(msg);
        out[self.k..].fill(PackedFlat::default());

        self.fft_k.inverse(&mut out[..self.k])?;
        self.fft_n.forward(out)?;

        Ok(())
    }

    fn check(&self, msg_len: usize, out_len: usize) -> Result<(), RsError> {
        if msg_len != self.k {
            return Err(RsError::BadLength {
                expected: self.k,
                got: msg_len,
            });
        }

        if out_len != self.n {
            return Err(RsError::BadLength {
                expected: self.n,
                got: out_len,
            });
        }

        Ok(())
    }
}
