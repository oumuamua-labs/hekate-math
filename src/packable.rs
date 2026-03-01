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

use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

/// A trait linking a Field element
/// to its SIMD packed representation.
pub trait PackableField: Sized + Copy + Clone + Default {
    /// The packed vector type (e.g., PackedBlock128).
    type Packed: Add<Output = Self::Packed>
        + Sub<Output = Self::Packed>
        + Mul<Output = Self::Packed>
        + Mul<Self, Output = Self::Packed>
        + AddAssign
        + SubAssign
        + MulAssign
        + Copy
        + Clone
        + Default;

    /// How many elements fit in one packed vector.
    const WIDTH: usize;

    /// Pack a slice of scalars into a vector.
    /// Panics if slice len < WIDTH.
    fn pack(chunk: &[Self]) -> Self::Packed;

    /// Unpack vector back to scalars.
    fn unpack(packed: Self::Packed, output: &mut [Self]);
}
