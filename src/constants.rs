// SPDX-License-Identifier: Apache-2.0
// This file is part of the hekate-math project.
// Copyright (C) 2026 Andrei Kochergin <zeek@tuta.com>
// Copyright (C) 2026 Oumuamua Labs. All rights reserved.
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

#[allow(dead_code)]
#[allow(clippy::all)]
mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated_constants.rs"));
}

pub use generated::*;

// ========================================
// LIFTING CONSTANT WRAPPERS
// ========================================

#[cfg(not(feature = "table-math"))]
#[repr(align(64))]
pub struct CtLiftBasisU128<const N: usize>(pub [u128; N]);

#[cfg(not(feature = "table-math"))]
pub static LIFT_BASIS_8: CtLiftBasisU128<8> = CtLiftBasisU128(LIFT_BASIS_8_TO_128);

#[cfg(not(feature = "table-math"))]
pub static LIFT_BASIS_16: CtLiftBasisU128<16> = CtLiftBasisU128(LIFT_BASIS_16_TO_128);

#[cfg(not(feature = "table-math"))]
pub static LIFT_BASIS_32: CtLiftBasisU128<32> = CtLiftBasisU128(LIFT_BASIS_32_TO_128);

#[cfg(not(feature = "table-math"))]
pub static LIFT_BASIS_64: CtLiftBasisU128<64> = CtLiftBasisU128(LIFT_BASIS_64_TO_128);
