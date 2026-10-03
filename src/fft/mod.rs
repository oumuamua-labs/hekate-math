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
mod cantor;
mod reed_solomon;

pub use additive::{AdditiveFft, FftError};
pub use cantor::{CantorBasis, CantorError};
pub use reed_solomon::{ReedSolomon, RsError};

use crate::BinaryFieldExtras;

/// s_i(x): the GF(2)-linear vanishing polynomial
/// of W_i = span(β_0..β_{i-1}). Equals the i-fold
/// composition of σ(t) = t^2 + t; deg s_i = 2^i.
pub fn vanish_eval<F: BinaryFieldExtras>(i: usize, x: F) -> F {
    let mut t = x;
    for _ in 0..i {
        t = t.square() + t;
    }

    t
}
