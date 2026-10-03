// SPDX-License-Identifier: Apache-2.0
// This file is part of the hekate-math project.
// Copyright (C) 2026 Andrei Kochergin <andrei@oumuamua.dev>
// Copyright (C) 2026 Oumuamua Labs <info@oumuamua.dev>. All rights reserved.
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

//! `TowerField`, the tower-basis trait every block type
//! implements, and the fixed little-endian byte encoding.

use alloc::vec;
use alloc::vec::Vec;
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use zeroize::Zeroize;

/// GF(2^BITS) in the tower basis: `Bit` and `Block8`
/// through `Block256`. Addition and subtraction are XOR.
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
    /// Degree over GF(2): 2^BITS elements.
    const BITS: usize;

    /// The additive identity.
    const ZERO: Self;

    /// The multiplicative identity.
    const ONE: Self;

    /// τ of the next level, F\[X\] / (X^2 + X + τ), for Block8 up.
    /// Tr(τ) = 1 makes X^2 + X + τ irreducible.
    const EXTENSION_TAU: Self;

    /// Returns `self^-1`, or 0 for 0. No branch on the value in the default build.
    fn invert(&self) -> Self;

    /// Builds the element from the first `BITS` bits
    /// of `bytes`, little-endian; ignores the rest.
    fn from_uniform_bytes(bytes: &[u8; 32]) -> Self;
}

/// Fixed-size little-endian encoding of the tower bits:
/// `BITS / 8` bytes, one byte for `Bit`.
pub trait CanonicalSerialize {
    /// Returns the encoded length in bytes.
    fn serialized_size(&self) -> usize;

    /// Writes the encoding to the start of `writer`;
    /// later bytes are left as they are.
    ///
    /// # Errors
    /// `Err(())` if `writer` is shorter than `serialized_size()`.
    #[allow(clippy::result_unit_err)]
    fn serialize(&self, writer: &mut [u8]) -> Result<(), ()>;

    /// Encodes `self` into a new `Vec<u8>` of `serialized_size()` bytes.
    fn to_bytes(&self) -> Vec<u8> {
        let size = self.serialized_size();
        let mut buf = vec![0u8; size];
        self.serialize(&mut buf).expect("Size calculation matches");

        buf
    }
}

/// The inverse of [`CanonicalSerialize`].
pub trait CanonicalDeserialize: Sized {
    /// Reads an element from the start of `bytes`; ignores the rest.
    ///
    /// # Errors
    /// `Err(())` if `bytes` is shorter than the encoding,
    /// or, for `Bit`, if the byte is above 1.
    #[allow(clippy::result_unit_err)]
    fn deserialize(bytes: &[u8]) -> Result<Self, ()>;
}
