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

//! Additive FFT over GF(2^N) (Cantor basis).

mod additive;
mod reed_solomon;

pub use additive::{AdditiveFft, FftError};
pub use reed_solomon::{ReedSolomon, RsError};

use crate::{BinaryFieldExtras, Bit, Block16, TowerField, constants};

/// The GF(2)-basis {β_0, …, β_15} of GF(2^16) with
/// β_0 = 1 and β_{i-1} = β_i^2 + β_i (Cantor 1989).
/// Baked at build time; this is a typed view over it.
pub struct CantorBasis;

impl CantorBasis {
    pub const DIM: usize = 16;

    pub fn beta_tower(i: usize) -> Block16 {
        Block16(constants::CANTOR_BASIS_TOWER_16[i])
    }

    /// Verifies the baked basis against live field arithmetic:
    /// independence, β_0 = 1, σ(β_i) = β_{i-1},
    /// s_i(β_i) = 1, and the trace pattern.
    pub fn self_check() -> bool {
        if Self::beta_tower(0) != Block16::ONE {
            return false;
        }

        let mut piv = [0u16; 16];
        let mut rank = 0;

        for i in 0..Self::DIM {
            let b = Self::beta_tower(i);

            if vanish_eval(i, b) != Block16::ONE {
                return false;
            }

            if (b.trace() == Bit::ONE) != (i == Self::DIM - 1) {
                return false;
            }

            if i >= 1 && b.square() + b != Self::beta_tower(i - 1) {
                return false;
            }

            let mut x = b.0;
            while x != 0 {
                let p = x.trailing_zeros() as usize;

                if piv[p] == 0 {
                    piv[p] = x;
                    rank += 1;
                    break;
                }

                x ^= piv[p];
            }
        }

        rank == Self::DIM
    }
}

/// s_i(x): the GF(2)-linear vanishing polynomial of
/// W_i = span(β_0..β_{i-1}). Equals the i-fold
/// composition of σ(t) = t^2 + t; deg s_i = 2^i.
pub fn vanish_eval<F: BinaryFieldExtras>(i: usize, x: F) -> F {
    let mut t = x;
    for _ in 0..i {
        t = t.square() + t;
    }

    t
}
