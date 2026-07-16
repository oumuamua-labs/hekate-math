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

//! Binary-field algebraic extras.

use crate::{Bit, TowerField};

/// Binary-field operations beyond core `TowerField`:
/// Frobenius, absolute trace, and the Artin-Schreier
/// solver underpinning the Cantor/FFT substrate.
pub trait BinaryFieldExtras: TowerField {
    fn square(&self) -> Self {
        *self * *self
    }

    /// `x^(2^k)`. `k` is taken mod the field degree
    /// (`x^(2^BITS) = x`), so any `k` is valid.
    fn frobenius(&self, k: u32) -> Self {
        let reps = (k % Self::BITS as u32) as usize;

        let mut acc = *self;
        for _ in 0..reps {
            acc = acc.square();
        }

        acc
    }

    /// Absolute trace `Tr_{F/GF(2)}(x) = Σ x^(2^i)`,
    /// always 0 or 1.
    fn trace(&self) -> Bit {
        let mut acc = Self::ZERO;
        let mut p = *self;

        for _ in 0..Self::BITS {
            acc += p;
            p = p.square();
        }

        Bit::new((acc == Self::ONE) as u8)
    }

    /// A root of `x^2 + x = c`, or `None` iff
    /// `Tr(c) != 0` (then it has no solution).
    /// When solvable, the roots are the result and
    /// `result + ONE`. The value path is constant-time;
    /// only the `Some`/`None` choice reveals `Tr(c)`.
    fn solve_quadratic(c: Self) -> Option<Self>;
}
