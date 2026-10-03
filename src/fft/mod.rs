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

//! Additive FFT over the Cantor basis of a binary tower field
//! (Gao–Mateer 2010), evaluation at chosen domain points, and a
//! systematic Reed–Solomon encoder.
//!
//! Polynomials are given by their coefficients in the novel basis
//! of Lin–Chung–Han 2014: X_t = Π s_j over the set bits j of t,
//! with s_j = [`vanish_eval`]`(j, ·)`. Domain index i is the point
//! Σ β_j over the set bits j of i ([`CantorBasis::point`]).
//! Coefficients, points and evaluations are in the flat basis.

mod additive;
mod cantor;
mod reed_solomon;

pub use additive::{AdditiveFft, FftError};
pub use cantor::{CantorBasis, CantorError};
pub use reed_solomon::{ReedSolomon, RsError};

use crate::BinaryFieldExtras;

/// Evaluates at `x` the GF(2)-linear vanishing polynomial
/// s_i of W_i = span(β_0..β_{i-1}). Equals the i-fold
/// composition of σ(t) = t^2 + t; deg s_i = 2^i.
pub fn vanish_eval<F: BinaryFieldExtras>(i: usize, x: F) -> F {
    let mut t = x;
    for _ in 0..i {
        t = t.square() + t;
    }

    t
}
