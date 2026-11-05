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

//! Twin and semantics of the additive FFT (src/fft/additive.rs).
//! The level-loop transforms refine the recursive fwd_spec/inv_spec
//! through a strided-gather invariant; the round-trip theorem uses
//! only the xor group; it holds for any twiddle and any multiply.

use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
#[path = "../flat/bridge.rs"]
pub mod bridge;

pub mod cantor;
pub mod lde;
pub mod spec;
pub mod twiddles;
pub mod twin;

verus! {

global size_of usize == 8;

fn main() {}

}
