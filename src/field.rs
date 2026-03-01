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

use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use zeroize::Zeroize;

pub trait TowerField:
    Copy
    + Default
    + Clone
    + PartialEq
    + Eq
    + core::fmt::Debug
    + Send
    + Sync
    + From<u8>
    + From<u32>
    + From<u64>
    + From<u128>
    + Add<Output = Self>
    + Sub<Output = Self>
    + Mul<Output = Self>
    + AddAssign
    + SubAssign
    + MulAssign
    + CanonicalSerialize
    + CanonicalDeserialize
    + Zeroize
{
    const BITS: usize;
    const ZERO: Self;
    const ONE: Self;

    /// The constant `TAU` needed to extend
    /// this field to the next level.
    /// If we are in F, then the next field
    /// F' is constructed as F[X] / (X^2 + X + EXTENSION_TAU).
    const EXTENSION_TAU: Self;

    /// Returns the multiplicative inverse
    /// of the element. By cryptographic
    /// convention, the inverse of 0 is
    /// defined as 0 to ensure constant-time
    /// execution without branching.
    fn invert(&self) -> Self;

    /// Constructs a field element from
    /// uniform bytes (e.g. hash output).
    /// Used for PRNG / Blinding.
    ///
    /// The input is strictly 32 bytes
    /// (standard hash size). Implementations
    /// should use as many bytes as needed
    /// from the prefix and ignore the rest.
    fn from_uniform_bytes(bytes: &[u8; 32]) -> Self;
}

/// Defines how field elements are converted to bytes.
/// Standard: Little-Endian.
pub trait CanonicalSerialize {
    /// Returns the size in bytes.
    fn serialized_size(&self) -> usize;

    /// Serializes the element into a buffer.
    /// Returns error if buffer is too small.
    #[allow(clippy::result_unit_err)]
    fn serialize(&self, writer: &mut [u8]) -> Result<(), ()>;

    /// Convenience method:
    /// returns a Vec<u8>.
    fn to_bytes(&self) -> Vec<u8> {
        let size = self.serialized_size();
        let mut buf = vec![0u8; size];
        self.serialize(&mut buf).expect("Size calculation matches");

        buf
    }
}

/// Defines how bytes are converted back to field elements.
/// Standard: Little-Endian.
pub trait CanonicalDeserialize: Sized {
    /// Deserializes from a buffer.
    /// Returns Err if buffer is too short.
    #[allow(clippy::result_unit_err)]
    fn deserialize(bytes: &[u8]) -> Result<Self, ()>;
}
