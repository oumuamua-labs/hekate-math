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

//! `BinaryFieldExtras` (square, Frobenius, trace, Artin–Schreier
//! solver) and the macro that implements it for Block16 to Block128.

use crate::{Bit, TowerField};

/// Square, Frobenius, absolute trace and the Artin–Schreier solver of
/// a binary field; the solver builds the Cantor basis of the additive FFT.
pub trait BinaryFieldExtras: TowerField {
    /// Returns `self^2`; squaring is additive in characteristic 2.
    fn square(&self) -> Self {
        *self * *self
    }

    /// Returns `self^(2^k)`, `k` reduced mod `BITS` since
    /// `x^(2^BITS) = x`; costs `k % BITS` squarings.
    fn frobenius(&self, k: u32) -> Self {
        let reps = (k % Self::BITS as u32) as usize;

        let mut acc = *self;
        for _ in 0..reps {
            acc = acc.square();
        }

        acc
    }

    /// Returns the absolute trace Σ_{i<BITS} self^(2^i), always
    /// 0 or 1; the tower fields compute it as a masked parity.
    fn trace(&self) -> Bit {
        let mut acc = Self::ZERO;
        let mut p = *self;

        for _ in 0..Self::BITS {
            acc += p;
            p = p.square();
        }

        Bit::new((acc == Self::ONE) as u8)
    }

    /// Returns a root of x^2 + x = c, or `None` iff Tr(c) = 1; the other
    /// root is `result + ONE`. The fixed choice defines the Cantor basis.
    /// The value path is constant time; only `Some`/`None` reveals Tr(c).
    fn solve_quadratic(c: Self) -> Option<Self>;
}

macro_rules! impl_binary_field_extras {
    ($block:ty, $map_ct:ident, $trace_mask:ident, $solve_basis:ident) => {
        impl BinaryFieldExtras for $block {
            #[inline(always)]
            fn square(&self) -> Self {
                // char 2:
                // (lo + hi·X)^2 = lo^2 + hi^2·X^2,
                // no cross term.
                let (lo, hi) = self.split();
                let hi2 = hi.square();

                Self::new(lo.square() + hi2.mul_tau(), hi2)
            }

            #[inline(always)]
            fn trace(&self) -> Bit {
                Bit::new(((self.0 & constants::$trace_mask).count_ones() & 1) as u8)
            }

            #[inline(always)]
            fn solve_quadratic(c: Self) -> Option<Self> {
                if c.trace() != Bit::ZERO {
                    return None;
                }

                Some(Self($map_ct(c.0, &constants::$solve_basis)))
            }
        }
    };
}

pub(crate) use impl_binary_field_extras;
