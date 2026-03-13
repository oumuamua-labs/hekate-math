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

use crate::{
    Block8, CanonicalDeserialize, CanonicalSerialize, Flat, FlatPromote, HardwareField,
    PackableField, PackedFlat, TowerField,
};
use core::ops::{Add, AddAssign, BitAnd, BitXor, Mul, MulAssign, Sub, SubAssign};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// ==================================
// BIT (GF(2))
// ==================================

#[derive(Debug, Default, Copy, Clone, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[repr(transparent)]
pub struct Bit(pub u8);

impl Bit {
    pub const fn new(val: u8) -> Self {
        Self(val & 1) // Self(val.bitand(1))
    }
}

impl TowerField for Bit {
    const BITS: usize = 1;
    const ZERO: Self = Bit(0);
    const ONE: Self = Bit(1);

    // x^2 + x + 1 = 0 -> Irreducible over GF(2)
    const EXTENSION_TAU: Self = Bit(1);

    fn invert(&self) -> Self {
        // In GF(2), the inverse of 1 is 1.
        // By cryptographic convention, the
        // inverse of 0 is defined as 0.
        // Thus, inversion in GF(2) is
        // just the identity function.
        *self
    }

    fn from_uniform_bytes(bytes: &[u8; 32]) -> Self {
        // Take LSB of first byte
        Self(bytes[0] & 1)
    }
}

/// Add (XOR)
/// 0+0=0, 0+1=1, 1+0=1, 1+1=0
impl Add for Bit {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.bitxor(rhs.0))
    }
}

/// Sub is the same as add
impl Sub for Bit {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

/// Mul (AND)
/// 0*0=0, 0*1=0, 1*1=1
impl Mul for Bit {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        Self(self.0.bitand(rhs.0))
    }
}

impl AddAssign for Bit {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs
    }
}

impl SubAssign for Bit {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs
    }
}

impl MulAssign for Bit {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl CanonicalSerialize for Bit {
    #[inline]
    fn serialized_size(&self) -> usize {
        1
    }

    #[inline]
    fn serialize(&self, writer: &mut [u8]) -> Result<(), ()> {
        if writer.is_empty() {
            return Err(());
        }

        writer[0] = self.0;

        Ok(())
    }
}

impl CanonicalDeserialize for Bit {
    fn deserialize(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.is_empty() {
            return Err(());
        }

        if bytes[0] > 1 {
            return Err(());
        }

        Ok(Self(bytes[0]))
    }
}

impl From<u8> for Bit {
    #[inline]
    fn from(val: u8) -> Self {
        Self(val & 1)
    }
}

impl From<u32> for Bit {
    #[inline]
    fn from(val: u32) -> Self {
        Self((val & 1) as u8)
    }
}

impl From<u64> for Bit {
    #[inline]
    fn from(val: u64) -> Self {
        Self((val & 1) as u8)
    }
}

impl From<u128> for Bit {
    #[inline]
    fn from(val: u128) -> Self {
        Self((val & 1) as u8)
    }
}

// ===================================
// PACKED BIT (Width = 64)
// ===================================

// 64 bytes = 512 bits = 4 SIMD registers (128-bit each)
pub const PACKED_WIDTH_BIT: usize = 64;

#[repr(C, align(64))]
pub struct PackedBit(pub [Bit; PACKED_WIDTH_BIT]);

impl Clone for PackedBit {
    #[inline(always)]
    fn clone(&self) -> Self {
        *self
    }
}

impl Copy for PackedBit {}

impl Default for PackedBit {
    #[inline(always)]
    fn default() -> Self {
        Self::zero()
    }
}

impl PartialEq for PackedBit {
    fn eq(&self, other: &Self) -> bool {
        // Bit(u8) is transparent, direct slice
        // comparison works and is fast.
        self.0[..] == other.0[..]
    }
}

impl Eq for PackedBit {}

impl core::fmt::Debug for PackedBit {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PackedBit([size={}])", PACKED_WIDTH_BIT)
    }
}

impl PackedBit {
    #[inline(always)]
    pub fn zero() -> Self {
        Self([Bit::ZERO; PACKED_WIDTH_BIT])
    }
}

impl PackableField for Bit {
    type Packed = PackedBit;

    const WIDTH: usize = PACKED_WIDTH_BIT;

    #[inline(always)]
    fn pack(chunk: &[Self]) -> Self::Packed {
        assert!(
            chunk.len() >= PACKED_WIDTH_BIT,
            "PackableField::pack: input slice too short",
        );

        let mut arr = [Self::ZERO; PACKED_WIDTH_BIT];
        arr.copy_from_slice(&chunk[..PACKED_WIDTH_BIT]);

        PackedBit(arr)
    }

    #[inline(always)]
    fn unpack(packed: Self::Packed, output: &mut [Self]) {
        assert!(
            output.len() >= PACKED_WIDTH_BIT,
            "PackableField::unpack: output slice too short",
        );

        output[..PACKED_WIDTH_BIT].copy_from_slice(&packed.0);
    }
}

impl Add for PackedBit {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            neon::add_packed_bit(self, rhs)
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let mut res = [Bit::ZERO; PACKED_WIDTH_BIT];
            for ((out, l), r) in res.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
                *out = *l + *r;
            }

            Self(res)
        }
    }
}

impl AddAssign for PackedBit {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        for (l, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *l += *r;
        }
    }
}

impl Sub for PackedBit {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

impl SubAssign for PackedBit {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.add_assign(rhs)
    }
}

impl Mul for PackedBit {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            neon::mul_packed_bit(self, rhs)
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let mut res = [Bit::ZERO; PACKED_WIDTH_BIT];
            for ((out, l), r) in res.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
                *out = *l * *r;
            }

            Self(res)
        }
    }
}

impl MulAssign for PackedBit {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Mul<Bit> for PackedBit {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Bit) -> Self {
        let mut res = [Bit::ZERO; PACKED_WIDTH_BIT];
        for (out, v) in res.iter_mut().zip(self.0.iter()) {
            *out = *v * rhs;
        }

        Self(res)
    }
}

// ===================================
// Hardware Field
// ===================================

impl HardwareField for Bit {
    #[inline(always)]
    fn to_hardware(self) -> Flat<Self> {
        Flat::from_raw(self)
    }

    #[inline(always)]
    fn from_hardware(value: Flat<Self>) -> Self {
        value.into_raw()
    }

    #[inline(always)]
    fn add_hardware(lhs: Flat<Self>, rhs: Flat<Self>) -> Flat<Self> {
        let lhs = lhs.into_raw();
        let rhs = rhs.into_raw();

        // Hardware addition for bits is XOR
        Flat::from_raw(Self(lhs.0 ^ rhs.0))
    }

    #[inline(always)]
    fn add_hardware_packed(lhs: PackedFlat<Self>, rhs: PackedFlat<Self>) -> PackedFlat<Self> {
        PackedFlat::from_raw(lhs.into_raw() + rhs.into_raw())
    }

    #[inline(always)]
    fn mul_hardware(lhs: Flat<Self>, rhs: Flat<Self>) -> Flat<Self> {
        let lhs = lhs.into_raw();
        let rhs = rhs.into_raw();

        // Hardware multiplication for bits is AND
        Flat::from_raw(Self(lhs.0 & rhs.0))
    }

    #[inline(always)]
    fn mul_hardware_packed(lhs: PackedFlat<Self>, rhs: PackedFlat<Self>) -> PackedFlat<Self> {
        PackedFlat::from_raw(lhs.into_raw() * rhs.into_raw())
    }

    #[inline(always)]
    fn mul_hardware_scalar_packed(lhs: PackedFlat<Self>, rhs: Flat<Self>) -> PackedFlat<Self> {
        let broadcasted = PackedBit([rhs.into_raw(); PACKED_WIDTH_BIT]);
        Self::mul_hardware_packed(lhs, PackedFlat::from_raw(broadcasted))
    }

    #[inline(always)]
    fn tower_bit_from_hardware(value: Flat<Self>, bit_idx: usize) -> u8 {
        assert_eq!(bit_idx, 0, "bit index out of bounds for Bit");

        // In GF(2), Tower and Flat
        // bases are identical.
        value.into_raw().0
    }
}

impl FlatPromote<Block8> for Bit {
    #[inline(always)]
    fn promote_flat(val: Flat<Block8>) -> Flat<Self> {
        // Take LSB
        Flat::from_raw(Bit(val.into_raw().0 & 1))
    }
}

// ===========================================
// SIMD INSTRUCTIONS
// ===========================================

#[cfg(target_arch = "aarch64")]
mod neon {
    use super::*;
    use core::arch::aarch64::*;
    use core::mem::transmute;

    /// XOR for 64 bits (represented as bytes).
    /// Uses 4 NEON registers.
    #[inline(always)]
    pub fn add_packed_bit(lhs: PackedBit, rhs: PackedBit) -> PackedBit {
        unsafe {
            // Cast [Bit; 64] -> [uint8x16_t; 4]
            let l: [uint8x16_t; 4] = transmute::<[Bit; PACKED_WIDTH_BIT], [uint8x16_t; 4]>(lhs.0);
            let r: [uint8x16_t; 4] = transmute::<[Bit; PACKED_WIDTH_BIT], [uint8x16_t; 4]>(rhs.0);

            let res = [
                veorq_u8(l[0], r[0]),
                veorq_u8(l[1], r[1]),
                veorq_u8(l[2], r[2]),
                veorq_u8(l[3], r[3]),
            ];

            PackedBit(transmute::<[uint8x16_t; 4], [Bit; PACKED_WIDTH_BIT]>(res))
        }
    }

    /// AND for 64 bits (represented as bytes).
    /// Uses 4 NEON registers.
    #[inline(always)]
    pub fn mul_packed_bit(lhs: PackedBit, rhs: PackedBit) -> PackedBit {
        unsafe {
            let l: [uint8x16_t; 4] = transmute::<[Bit; PACKED_WIDTH_BIT], [uint8x16_t; 4]>(lhs.0);
            let r: [uint8x16_t; 4] = transmute::<[Bit; PACKED_WIDTH_BIT], [uint8x16_t; 4]>(rhs.0);

            let res = [
                vandq_u8(l[0], r[0]),
                vandq_u8(l[1], r[1]),
                vandq_u8(l[2], r[2]),
                vandq_u8(l[3], r[3]),
            ];

            PackedBit(transmute::<[uint8x16_t; 4], [Bit; PACKED_WIDTH_BIT]>(res))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngExt, rng};

    // ==================================
    // BASIC
    // ==================================

    #[test]
    fn add_truth() {
        let zero = Bit::ZERO;
        let one = Bit::ONE;

        assert_eq!(zero + zero, zero);
        assert_eq!(zero + one, one);
        assert_eq!(one + zero, one);
        assert_eq!(one + one, zero);
    }

    #[test]
    fn mul_truth() {
        let zero = Bit::ZERO;
        let one = Bit::ONE;

        assert_eq!(zero * zero, zero);
        assert_eq!(zero * one, zero);
        assert_eq!(one * one, one);
    }

    #[test]
    fn security_zeroize() {
        // Setup sensitive bit (1)
        let mut secret_bit = Bit::ONE;
        assert_eq!(secret_bit.0, 1);

        // Nuke it
        secret_bit.zeroize();

        // Verify
        assert_eq!(secret_bit, Bit::ZERO);
        assert_eq!(secret_bit.0, 0, "Bit memory leak detected");
    }

    #[test]
    fn invert_truth() {
        // In GF(2):
        // invert(1) = 1
        // invert(0) = 0 (by convention)

        let one = Bit::ONE;
        let zero = Bit::ZERO;

        assert_eq!(one.invert(), Bit::ONE, "Inversion of 1 must be 1");
        assert_eq!(zero.invert(), Bit::ZERO, "Inversion of 0 must be 0");
    }

    // ==================================
    // HARDWARE
    // ==================================

    #[test]
    fn isomorphism_roundtrip() {
        let mut rng = rng();
        for _ in 0..100 {
            // Generate random bit (0 or 1)
            let val = Bit::new(rng.random::<u8>());

            // Roundtrip: Tower -> Hardware -> Tower must be identity.
            // For Bit, this is trivial (identity),
            // but we verify the trait contract.
            assert_eq!(
                val.to_hardware().to_tower(),
                val,
                "Bit isomorphism roundtrip failed"
            );
        }
    }

    #[test]
    fn flat_mul_homomorphism() {
        let mut rng = rng();
        for _ in 0..100 {
            let a = Bit::new(rng.random::<u8>());
            let b = Bit::new(rng.random::<u8>());

            let expected_flat = (a * b).to_hardware();
            let actual_flat = a.to_hardware() * b.to_hardware();

            // Check if multiplication in Flat basis matches Tower
            assert_eq!(
                actual_flat, expected_flat,
                "Bit flat multiplication mismatch"
            );
        }
    }

    #[test]
    fn packed_consistency() {
        let mut rng = rng();
        for _ in 0..100 {
            // PACKED_WIDTH_BIT = 64
            let mut a_vals = [Bit::ZERO; 64];
            let mut b_vals = [Bit::ZERO; 64];

            for i in 0..64 {
                a_vals[i] = Bit::new(rng.random::<u8>());
                b_vals[i] = Bit::new(rng.random::<u8>());
            }

            let a_flat_vals = a_vals.map(|x| x.to_hardware());
            let b_flat_vals = b_vals.map(|x| x.to_hardware());
            let a_packed = Flat::<Bit>::pack(&a_flat_vals);
            let b_packed = Flat::<Bit>::pack(&b_flat_vals);

            // 1. Test SIMD Add (XOR)
            let add_res = Bit::add_hardware_packed(a_packed, b_packed);

            let mut add_out = [Bit::ZERO.to_hardware(); 64];
            Flat::<Bit>::unpack(add_res, &mut add_out);

            for i in 0..64 {
                assert_eq!(
                    add_out[i],
                    (a_vals[i] + b_vals[i]).to_hardware(),
                    "Bit packed add mismatch at index {}",
                    i
                );
            }

            // 2. Test SIMD Mul (AND)
            let mul_res = Bit::mul_hardware_packed(a_packed, b_packed);

            let mut mul_out = [Bit::ZERO.to_hardware(); 64];
            Flat::<Bit>::unpack(mul_res, &mut mul_out);

            for i in 0..64 {
                assert_eq!(
                    mul_out[i],
                    (a_vals[i] * b_vals[i]).to_hardware(),
                    "Bit packed mul mismatch at index {}",
                    i
                );
            }
        }
    }

    // ==================================
    // PACKED
    // ==================================

    #[test]
    fn pack_unpack_roundtrip() {
        let mut rng = rng();
        // Width is 64
        let mut data = [Bit::ZERO; PACKED_WIDTH_BIT];

        for v in data.iter_mut() {
            *v = Bit::new(rng.random());
        }

        let packed = Bit::pack(&data);
        let mut unpacked = [Bit::ZERO; PACKED_WIDTH_BIT];
        Bit::unpack(packed, &mut unpacked);

        assert_eq!(data, unpacked, "Bit pack/unpack roundtrip failed");
    }

    #[test]
    fn packed_add_consistency() {
        let mut rng = rng();
        let mut a_vals = [Bit::ZERO; PACKED_WIDTH_BIT];
        let mut b_vals = [Bit::ZERO; PACKED_WIDTH_BIT];

        for i in 0..PACKED_WIDTH_BIT {
            a_vals[i] = Bit::new(rng.random());
            b_vals[i] = Bit::new(rng.random());
        }

        let a_packed = Bit::pack(&a_vals);
        let b_packed = Bit::pack(&b_vals);

        // Uses the SIMD add impl (which uses aarch64::add_packed_bit)
        let res_packed = a_packed + b_packed;

        let mut res_unpacked = [Bit::ZERO; PACKED_WIDTH_BIT];
        Bit::unpack(res_packed, &mut res_unpacked);

        for i in 0..PACKED_WIDTH_BIT {
            assert_eq!(
                res_unpacked[i],
                a_vals[i] + b_vals[i], // Regular Bit add (XOR)
                "Bit packed add mismatch"
            );
        }
    }

    #[test]
    fn packed_mul_consistency() {
        let mut rng = rng();

        for _ in 0..100 {
            let mut a_arr = [Bit::ZERO; PACKED_WIDTH_BIT];
            let mut b_arr = [Bit::ZERO; PACKED_WIDTH_BIT];

            for i in 0..PACKED_WIDTH_BIT {
                a_arr[i] = Bit::new(rng.random());
                b_arr[i] = Bit::new(rng.random());
            }

            let a_packed = PackedBit(a_arr); // Using constructor directly or pack
            let b_packed = PackedBit(b_arr);

            // Uses the SIMD mul impl (which uses aarch64::mul_packed_bit)
            let c_packed = a_packed * b_packed;

            let mut c_expected = [Bit::ZERO; PACKED_WIDTH_BIT];
            for i in 0..PACKED_WIDTH_BIT {
                c_expected[i] = a_arr[i] * b_arr[i]; // Regular Bit mul (AND)
            }

            assert_eq!(c_packed.0, c_expected, "Bit packed mul mismatch");
        }
    }
}
