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

//! BLOCK 64 (GF(2^64))
use crate::constants::FLAT_TO_TOWER_BIT_MASKS_64;
use crate::towers::bit::Bit;
use crate::towers::block8::Block8;
use crate::towers::block16::Block16;
use crate::towers::block32::Block32;
use crate::{
    CanonicalDeserialize, CanonicalSerialize, Flat, FlatPromote, HardwareField, PackableField,
    PackedFlat, TowerField, constants,
};
use core::ops::{Add, AddAssign, BitXor, BitXorAssign, Mul, MulAssign, Sub, SubAssign};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[cfg(not(feature = "table-math"))]
#[repr(align(64))]
struct CtConvertBasisU64<const N: usize>([u64; N]);

#[cfg(not(feature = "table-math"))]
static TOWER_TO_FLAT_BASIS_64: CtConvertBasisU64<64> =
    CtConvertBasisU64(constants::RAW_TOWER_TO_FLAT_64);

#[cfg(not(feature = "table-math"))]
static FLAT_TO_TOWER_BASIS_64: CtConvertBasisU64<64> =
    CtConvertBasisU64(constants::RAW_FLAT_TO_TOWER_64);

#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[repr(transparent)]
pub struct Block64(pub u64);

impl Block64 {
    // 0x2000_0000 << 32 = 0x2000_0000_0000_0000
    pub const TAU: Self = Block64(0x2000_0000_0000_0000);

    pub fn new(lo: Block32, hi: Block32) -> Self {
        Self((hi.0 as u64) << 32 | (lo.0 as u64))
    }

    #[inline(always)]
    pub fn split(self) -> (Block32, Block32) {
        (Block32(self.0 as u32), Block32((self.0 >> 32) as u32))
    }
}

impl TowerField for Block64 {
    const BITS: usize = 64;
    const ZERO: Self = Block64(0);
    const ONE: Self = Block64(1);

    const EXTENSION_TAU: Self = Self::TAU;

    fn invert(&self) -> Self {
        let (l, h) = self.split();
        let h2 = h * h;
        let l2 = l * l;
        let hl = h * l;
        let norm = (h2 * Block32::TAU) + hl + l2;

        let norm_inv = norm.invert();
        let res_hi = h * norm_inv;
        let res_lo = (h + l) * norm_inv;

        Self::new(res_lo, res_hi)
    }

    fn from_uniform_bytes(bytes: &[u8; 32]) -> Self {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[0..8]);

        Self(u64::from_le_bytes(buf))
    }
}

impl Add for Block64 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0.bitxor(rhs.0))
    }
}

impl Sub for Block64 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

impl Mul for Block64 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let (a0, a1) = self.split();
        let (b0, b1) = rhs.split();

        let v0 = a0 * b0;
        let v1 = a1 * b1;
        let v_sum = (a0 + a1) * (b0 + b1);

        let c_hi = v0 + v_sum;
        let c_lo = v0 + (v1 * Block32::TAU);

        Self::new(c_lo, c_hi)
    }
}

impl AddAssign for Block64 {
    fn add_assign(&mut self, rhs: Self) {
        self.0.bitxor_assign(rhs.0);
    }
}

impl SubAssign for Block64 {
    fn sub_assign(&mut self, rhs: Self) {
        self.0.bitxor_assign(rhs.0);
    }
}

impl MulAssign for Block64 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl CanonicalSerialize for Block64 {
    fn serialized_size(&self) -> usize {
        8
    }

    fn serialize(&self, writer: &mut [u8]) -> Result<(), ()> {
        if writer.len() < 8 {
            return Err(());
        }

        writer.copy_from_slice(&self.0.to_le_bytes());

        Ok(())
    }
}

impl CanonicalDeserialize for Block64 {
    fn deserialize(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() < 8 {
            return Err(());
        }

        let mut buf = [0u8; 8];
        buf.copy_from_slice(&bytes[0..8]);

        Ok(Self(u64::from_le_bytes(buf)))
    }
}

impl From<u8> for Block64 {
    #[inline(always)]
    fn from(val: u8) -> Self {
        Self(val as u64)
    }
}

impl From<u32> for Block64 {
    #[inline(always)]
    fn from(val: u32) -> Self {
        Self::from(val as u64)
    }
}

impl From<u64> for Block64 {
    #[inline(always)]
    fn from(val: u64) -> Self {
        Self(val)
    }
}

impl From<u128> for Block64 {
    #[inline(always)]
    fn from(val: u128) -> Self {
        Self(val as u64)
    }
}

// ========================================
// FIELD LIFTING
// ========================================

impl From<Bit> for Block64 {
    #[inline(always)]
    fn from(val: Bit) -> Self {
        Self(val.0 as u64)
    }
}

impl From<Block8> for Block64 {
    #[inline(always)]
    fn from(val: Block8) -> Self {
        Self(val.0 as u64)
    }
}

impl From<Block16> for Block64 {
    #[inline(always)]
    fn from(val: Block16) -> Self {
        Self(val.0 as u64)
    }
}

impl From<Block32> for Block64 {
    #[inline(always)]
    fn from(val: Block32) -> Self {
        Self(val.0 as u64)
    }
}

// ===================================
// PACKED BLOCK 64 (Width = 2)
// ===================================

pub const PACKED_WIDTH_64: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(C, align(16))] // 128-bit alignment
pub struct PackedBlock64(pub [Block64; PACKED_WIDTH_64]);

impl PackedBlock64 {
    #[inline(always)]
    pub fn zero() -> Self {
        Self([Block64::ZERO; PACKED_WIDTH_64])
    }
}

impl PackableField for Block64 {
    type Packed = PackedBlock64;

    const WIDTH: usize = PACKED_WIDTH_64;

    #[inline(always)]
    fn pack(chunk: &[Self]) -> Self::Packed {
        assert!(
            chunk.len() >= PACKED_WIDTH_64,
            "PackableField::pack: input slice too short",
        );

        let mut arr = [Self::ZERO; PACKED_WIDTH_64];
        arr.copy_from_slice(&chunk[..PACKED_WIDTH_64]);

        PackedBlock64(arr)
    }

    #[inline(always)]
    fn unpack(packed: Self::Packed, output: &mut [Self]) {
        assert!(
            output.len() >= PACKED_WIDTH_64,
            "PackableField::unpack: output slice too short",
        );

        output[..PACKED_WIDTH_64].copy_from_slice(&packed.0);
    }
}

impl Add for PackedBlock64 {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        let mut res = [Block64::ZERO; PACKED_WIDTH_64];
        for ((out, l), r) in res.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            *out = *l + *r;
        }

        Self(res)
    }
}

impl AddAssign for PackedBlock64 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        for (l, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *l += *r;
        }
    }
}

impl Sub for PackedBlock64 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

impl SubAssign for PackedBlock64 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.add_assign(rhs);
    }
}

impl Mul for PackedBlock64 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            let a0 = mul_iso_64(self.0[0], rhs.0[0]);
            let a1 = mul_iso_64(self.0[1], rhs.0[1]);

            Self([a0, a1])
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let mut res = [Block64::ZERO; PACKED_WIDTH_64];
            for ((out, l), r) in res.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
                *out = *l * *r;
            }

            Self(res)
        }
    }
}

impl MulAssign for PackedBlock64 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        for (l, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *l *= *r;
        }
    }
}

impl Mul<Block64> for PackedBlock64 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Block64) -> Self {
        let mut res = [Block64::ZERO; PACKED_WIDTH_64];
        for (out, v) in res.iter_mut().zip(self.0.iter()) {
            *out = *v * rhs;
        }

        Self(res)
    }
}

// ===================================
// Hardware Field
// ===================================

impl HardwareField for Block64 {
    #[inline(always)]
    fn to_hardware(self) -> Flat<Self> {
        #[cfg(feature = "table-math")]
        {
            Flat::from_raw(apply_matrix_64(self, &constants::TOWER_TO_FLAT_64))
        }

        #[cfg(not(feature = "table-math"))]
        {
            Flat::from_raw(Block64(map_ct_64(self.0, &TOWER_TO_FLAT_BASIS_64.0)))
        }
    }

    #[inline(always)]
    fn from_hardware(value: Flat<Self>) -> Self {
        let value = value.into_raw();

        #[cfg(feature = "table-math")]
        {
            apply_matrix_64(value, &constants::FLAT_TO_TOWER_64)
        }

        #[cfg(not(feature = "table-math"))]
        {
            Block64(map_ct_64(value.0, &FLAT_TO_TOWER_BASIS_64.0))
        }
    }

    #[inline(always)]
    fn add_hardware(lhs: Flat<Self>, rhs: Flat<Self>) -> Flat<Self> {
        Flat::from_raw(lhs.into_raw() + rhs.into_raw())
    }

    #[inline(always)]
    fn add_hardware_packed(lhs: PackedFlat<Self>, rhs: PackedFlat<Self>) -> PackedFlat<Self> {
        let lhs = lhs.into_raw();
        let rhs = rhs.into_raw();

        #[cfg(target_arch = "aarch64")]
        {
            PackedFlat::from_raw(neon::add_packed_64(lhs, rhs))
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            PackedFlat::from_raw(lhs + rhs)
        }
    }

    #[inline(always)]
    fn mul_hardware(lhs: Flat<Self>, rhs: Flat<Self>) -> Flat<Self> {
        let lhs = lhs.into_raw();
        let rhs = rhs.into_raw();

        #[cfg(target_arch = "aarch64")]
        {
            Flat::from_raw(neon::mul_flat_64(lhs, rhs))
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let a_tower = Self::from_hardware(Flat::from_raw(lhs));
            let b_tower = Self::from_hardware(Flat::from_raw(rhs));

            (a_tower * b_tower).to_hardware()
        }
    }

    #[inline(always)]
    fn mul_hardware_packed(lhs: PackedFlat<Self>, rhs: PackedFlat<Self>) -> PackedFlat<Self> {
        let lhs = lhs.into_raw();
        let rhs = rhs.into_raw();

        #[cfg(target_arch = "aarch64")]
        {
            PackedFlat::from_raw(neon::mul_flat_packed_64(lhs, rhs))
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let mut l = [Self::ZERO; <Self as PackableField>::WIDTH];
            let mut r = [Self::ZERO; <Self as PackableField>::WIDTH];
            let mut res = [Self::ZERO; <Self as PackableField>::WIDTH];

            Self::unpack(lhs, &mut l);
            Self::unpack(rhs, &mut r);

            for i in 0..<Self as PackableField>::WIDTH {
                res[i] = Self::mul_hardware(Flat::from_raw(l[i]), Flat::from_raw(r[i])).into_raw();
            }

            PackedFlat::from_raw(Self::pack(&res))
        }
    }

    #[inline(always)]
    fn tower_bit_from_hardware(value: Flat<Self>, bit_idx: usize) -> u8 {
        let mask = FLAT_TO_TOWER_BIT_MASKS_64[bit_idx];

        // Parity of (x & mask) without popcount
        // Folds 64 bits down to 4,
        // then uses a lookup table.
        let mut v = value.into_raw().0 & mask;
        v ^= v >> 32;
        v ^= v >> 16;
        v ^= v >> 8;
        v ^= v >> 4;

        let idx = (v & 0xF) as u8;

        // Nibble parity lookup encoded
        // in a 16-bit constant (0x6996).
        ((0x6996u16 >> idx) & 1) as u8
    }
}

impl FlatPromote<Block8> for Block64 {
    #[inline(always)]
    fn promote_flat(val: Flat<Block8>) -> Flat<Self> {
        let val = val.into_raw();

        #[cfg(not(feature = "table-math"))]
        {
            let mut acc = 0u64;
            for i in 0..8 {
                let bit = (val.0 >> i) & 1;
                let mask = 0u64.wrapping_sub(bit as u64);
                acc ^= constants::LIFT_BASIS_8_TO_64[i] & mask;
            }

            Flat::from_raw(Block64(acc))
        }

        #[cfg(feature = "table-math")]
        {
            Flat::from_raw(Block64(constants::LIFT_TABLE_8_TO_64[val.0 as usize]))
        }
    }
}

// ===========================================
// UTILS
// ===========================================

#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn mul_iso_64(a: Block64, b: Block64) -> Block64 {
    let a_flat = a.to_hardware();
    let b_flat = b.to_hardware();

    let c_flat = Flat::from_raw(neon::mul_flat_64(a_flat.into_raw(), b_flat.into_raw()));

    c_flat.to_tower()
}

#[cfg(feature = "table-math")]
#[inline(always)]
pub fn apply_matrix_64(val: Block64, table: &[u64; 2048]) -> Block64 {
    let mut res = 0u64;
    let v = val.0;

    // 8 lookups (8-bit window)
    for i in 0..8 {
        let byte = (v >> (i * 8)) & 0xFF;
        let idx = (i * 256) + (byte as usize);
        res ^= unsafe { *table.get_unchecked(idx) };
    }

    Block64(res)
}

#[cfg(not(feature = "table-math"))]
#[inline(always)]
fn map_ct_64(x: u64, basis: &[u64; 64]) -> u64 {
    let mut acc = 0u64;
    let mut i = 0usize;

    while i < 64 {
        let bit = (x >> i) & 1;
        let mask = 0u64.wrapping_sub(bit);
        acc ^= basis[i] & mask;
        i += 1;
    }

    acc
}

// ===========================================
// SIMD INSTRUCTIONS
// ===========================================

#[cfg(target_arch = "aarch64")]
mod neon {
    use super::*;
    use core::arch::aarch64::*;
    use core::mem::transmute;

    #[inline(always)]
    pub fn add_packed_64(lhs: PackedBlock64, rhs: PackedBlock64) -> PackedBlock64 {
        unsafe {
            let l: uint8x16_t = transmute::<[Block64; PACKED_WIDTH_64], uint8x16_t>(lhs.0);
            let r: uint8x16_t = transmute::<[Block64; PACKED_WIDTH_64], uint8x16_t>(rhs.0);
            let res = veorq_u8(l, r);
            let out: [Block64; PACKED_WIDTH_64] =
                transmute::<uint8x16_t, [Block64; PACKED_WIDTH_64]>(res);

            PackedBlock64(out)
        }
    }

    #[inline(always)]
    pub fn mul_flat_packed_64(lhs: PackedBlock64, rhs: PackedBlock64) -> PackedBlock64 {
        unsafe {
            let a: uint64x2_t = transmute(lhs.0);
            let b: uint64x2_t = transmute(rhs.0);

            let a_lo = vget_low_u64(a);
            let b_lo = vget_low_u64(b);

            let p0: uint64x2_t =
                transmute(vmull_p64(vget_lane_u64(a_lo, 0), vget_lane_u64(b_lo, 0)));

            let a_hi = vget_high_u64(a);
            let b_hi = vget_high_u64(b);
            let p1: uint64x2_t =
                transmute(vmull_p64(vget_lane_u64(a_hi, 0), vget_lane_u64(b_hi, 0)));

            let r0 = reduce_64(p0);
            let r1 = reduce_64(p1);

            PackedBlock64([r0, r1])
        }
    }

    #[inline(always)]
    fn reduce_64(prod: uint64x2_t) -> Block64 {
        unsafe {
            let l = vgetq_lane_u64(prod, 0);
            let h = vgetq_lane_u64(prod, 1);

            let r_val = constants::POLY_64;

            let h_red: uint64x2_t = transmute(vmull_p64(h, r_val));

            let folded = vgetq_lane_u64(h_red, 0);
            let carry = vgetq_lane_u64(h_red, 1);

            let mut res = l ^ folded;

            let carry_red: uint64x2_t = transmute(vmull_p64(carry, r_val));
            res ^= vgetq_lane_u64(carry_red, 0);

            Block64(res)
        }
    }

    #[inline(always)]
    pub fn mul_flat_64(a: Block64, b: Block64) -> Block64 {
        unsafe {
            // Multiply 64x64 -> 128
            let prod = vmull_p64(a.0, b.0);
            let prod_u64: uint64x2_t = transmute(prod);

            let l = vgetq_lane_u64(prod_u64, 0);
            let h = vgetq_lane_u64(prod_u64, 1);

            // Reduce mod P(x) = x^64 + R(x).
            let r_val = constants::POLY_64; // u64

            // H * R
            let h_red = vmull_p64(h, r_val);
            let h_red_u64: uint64x2_t = transmute(h_red);

            let folded = vgetq_lane_u64(h_red_u64, 0);
            let carry = vgetq_lane_u64(h_red_u64, 1);

            let mut res = l ^ folded;

            // Reduce carry (if exists)
            let carry_red = vmull_p64(carry, r_val);
            let carry_res_vec: uint64x2_t = transmute(carry_red);
            let carry_val = vgetq_lane_u64(carry_res_vec, 0);

            res ^= carry_val;

            Block64(res)
        }
    }
}

// ==================================
// BLOCK 64 TESTS
// ==================================

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use rand::{RngExt, rng};

    // ==================================
    // BASIC
    // ==================================

    #[test]
    fn tower_constants() {
        // Check that tau is propagated correctly
        // For Block64, tau must be (0, 1) from Block32.
        let tau64 = Block64::EXTENSION_TAU;
        let (lo64, hi64) = tau64.split();
        assert_eq!(lo64, Block32::ZERO);
        assert_eq!(hi64, Block32::TAU);
    }

    #[test]
    fn add_truth() {
        let zero = Block64::ZERO;
        let one = Block64::ONE;

        assert_eq!(zero + zero, zero);
        assert_eq!(zero + one, one);
        assert_eq!(one + zero, one);
        assert_eq!(one + one, zero);
    }

    #[test]
    fn mul_truth() {
        let zero = Block64::ZERO;
        let one = Block64::ONE;

        assert_eq!(zero * zero, zero);
        assert_eq!(zero * one, zero);
        assert_eq!(one * one, one);
    }

    #[test]
    fn add() {
        // 5 ^ 3 = 6
        // 101 ^ 011 = 110
        assert_eq!(Block64(5) + Block64(3), Block64(6));
    }

    #[test]
    fn mul_simple() {
        // Check for prime numbers (without overflow)
        // x^1 * x^1 = x^2 (2 * 2 = 4)
        assert_eq!(Block64(2) * Block64(2), Block64(4));
    }

    #[test]
    fn mul_overflow() {
        // Reduction verification (AES test vectors)
        // Example from the AES specification:
        // 0x57 * 0x83 = 0xC1
        assert_eq!(Block64(0x57) * Block64(0x83), Block64(0xC1));
    }

    #[test]
    fn karatsuba_correctness() {
        // Let's check using Block64 as an example
        // Let A = X (hi=1, lo=0)
        // Let B = X (hi=1, lo=0)
        // A * B = X^2
        // According to the rule:
        // X^2 = X + tau
        // Where tau for Block32 = 0x2000_0000.
        // So the result should be:
        // hi=1 (X), lo=0x20 (tau)

        // Construct X manually
        let x = Block64::new(Block32::ZERO, Block32::ONE);
        let squared = x * x;

        // Verify result via splitting
        let (res_lo, res_hi) = squared.split();

        assert_eq!(res_hi, Block32::ONE, "X^2 should contain X component");
        assert_eq!(
            res_lo,
            Block32(0x2000_0000),
            "X^2 should contain tau component (0x2000_0000)"
        );
    }

    #[test]
    fn security_zeroize() {
        let mut secret_val = Block64::from(0xDEAD_BEEF_CAFE_BABE_u64);
        assert_ne!(secret_val, Block64::ZERO);

        secret_val.zeroize();

        assert_eq!(secret_val, Block64::ZERO);
        assert_eq!(secret_val.0, 0, "Block64 memory leak detected");
    }

    #[test]
    fn invert_zero() {
        // Zero check
        assert_eq!(
            Block64::ZERO.invert(),
            Block64::ZERO,
            "invert(0) must return 0"
        );
    }

    #[test]
    fn inversion_random() {
        let mut rng = rng();
        for _ in 0..1000 {
            let val = Block64(rng.random());
            if val != Block64::ZERO {
                let inv = val.invert();
                assert_eq!(
                    val * inv,
                    Block64::ONE,
                    "Inversion identity failed: a * a^-1 != 1"
                );
            }
        }
    }

    #[test]
    fn tower_embedding() {
        let mut rng = rng();
        for _ in 0..100 {
            let a = Block32(rng.random());
            let b = Block32(rng.random());

            // 1. Structure check
            let a_lifted: Block64 = a.into();
            let (lo, hi) = a_lifted.split();

            assert_eq!(lo, a, "Embedding structure failed: low part mismatch");
            assert_eq!(
                hi,
                Block32::ZERO,
                "Embedding structure failed: high part must be zero"
            );

            // 2. Addition Homomorphism
            let sum_sub = a + b;
            let sum_lifted: Block64 = sum_sub.into();
            let sum_in_super = Block64::from(a) + Block64::from(b);

            assert_eq!(sum_lifted, sum_in_super, "Homomorphism failed: add");

            // 3. Multiplication Homomorphism
            let prod_sub = a * b;
            let prod_lifted: Block64 = prod_sub.into();
            let prod_in_super = Block64::from(a) * Block64::from(b);

            assert_eq!(prod_lifted, prod_in_super, "Homomorphism failed: mul");
        }
    }

    // ==================================
    // HARDWARE
    // ==================================

    #[test]
    fn isomorphism_roundtrip() {
        let mut rng = rng();
        for _ in 0..1000 {
            let val = Block64(rng.random::<u64>());
            assert_eq!(val.to_hardware().to_tower(), val);
        }
    }

    #[test]
    fn flat_mul_homomorphism() {
        let mut rng = rng();
        for _ in 0..1000 {
            let a = Block64(rng.random());
            let b = Block64(rng.random());

            let expected_flat = (a * b).to_hardware();
            let actual_flat = a.to_hardware() * b.to_hardware();

            assert_eq!(
                actual_flat, expected_flat,
                "Block64 flat multiplication mismatch: (a*b)^H != a^H * b^H"
            );
        }
    }

    #[test]
    fn packed_consistency() {
        let mut rng = rng();
        for _ in 0..100 {
            let a_vals = [Block64(rng.random()), Block64(rng.random())];
            let b_vals = [Block64(rng.random()), Block64(rng.random())];

            let a_flat_vals = a_vals.map(|x| x.to_hardware());
            let b_flat_vals = b_vals.map(|x| x.to_hardware());
            let a_packed = Flat::<Block64>::pack(&a_flat_vals);
            let b_packed = Flat::<Block64>::pack(&b_flat_vals);

            // 1. Test SIMD Add (XOR)
            let add_res = Block64::add_hardware_packed(a_packed, b_packed);

            let mut add_out = [Block64::ZERO.to_hardware(); 2];
            Flat::<Block64>::unpack(add_res, &mut add_out);

            assert_eq!(add_out[0], (a_vals[0] + b_vals[0]).to_hardware());
            assert_eq!(add_out[1], (a_vals[1] + b_vals[1]).to_hardware());

            // 2. Test SIMD Mul (Isomorphic/Flat basis)
            let mul_res = Block64::mul_hardware_packed(a_packed, b_packed);

            let mut mul_out = [Block64::ZERO.to_hardware(); 2];
            Flat::<Block64>::unpack(mul_res, &mut mul_out);

            assert_eq!(
                mul_out[0],
                (a_vals[0] * b_vals[0]).to_hardware(),
                "Block64 SIMD mul mismatch at index 0"
            );
            assert_eq!(
                mul_out[1],
                (a_vals[1] * b_vals[1]).to_hardware(),
                "Block64 SIMD mul mismatch at index 1"
            );
        }
    }

    // ==================================
    // PACKED
    // ==================================

    #[test]
    fn pack_unpack_roundtrip() {
        let mut rng = rng();
        let data = [Block64(rng.random()), Block64(rng.random())];

        let packed = Block64::pack(&data);
        let mut unpacked = [Block64::ZERO; 2];

        Block64::unpack(packed, &mut unpacked);
        assert_eq!(data, unpacked);
    }

    #[test]
    fn packed_add_consistency() {
        let mut rng = rng();
        let a_vals = [Block64(rng.random()), Block64(rng.random())];
        let b_vals = [Block64(rng.random()), Block64(rng.random())];

        let res_packed = Block64::pack(&a_vals) + Block64::pack(&b_vals);
        let mut res_unpacked = [Block64::ZERO; 2];
        Block64::unpack(res_packed, &mut res_unpacked);

        assert_eq!(res_unpacked[0], a_vals[0] + b_vals[0]);
        assert_eq!(res_unpacked[1], a_vals[1] + b_vals[1]);
    }

    #[test]
    fn packed_mul_consistency() {
        let mut rng = rng();

        for _ in 0..1000 {
            let mut a_arr = [Block64::ZERO; PACKED_WIDTH_64];
            let mut b_arr = [Block64::ZERO; PACKED_WIDTH_64];

            for i in 0..PACKED_WIDTH_64 {
                let val_a: u64 = rng.random();
                let val_b: u64 = rng.random();
                a_arr[i] = Block64(val_a);
                b_arr[i] = Block64(val_b);
            }

            let a_packed = PackedBlock64(a_arr);
            let b_packed = PackedBlock64(b_arr);

            // Perform SIMD multiplication
            let c_packed = a_packed * b_packed;

            // Verify against Scalar
            let mut c_expected = [Block64::ZERO; PACKED_WIDTH_64];
            for i in 0..PACKED_WIDTH_64 {
                c_expected[i] = a_arr[i] * b_arr[i];
            }

            assert_eq!(c_packed.0, c_expected, "SIMD Block64 mismatch!");
        }
    }

    proptest! {
        #[test]
        fn parity_masks_match_from_hardware(x_flat in any::<u64>()) {
            let tower = Block64::from_hardware(Flat::from_raw(Block64(x_flat))).0;

            for (k, &mask) in FLAT_TO_TOWER_BIT_MASKS_64.iter().enumerate() {
                // Ensure the static masks
                // themselves are correct.
                let parity = ((x_flat & mask).count_ones() & 1) as u8;
                let bit = ((tower >> k) & 1) as u8;
                prop_assert_eq!(parity, bit, "Block64 static mask mismatch at k={}", k);

                // Ensure XOR-tree implementation matches.
                let via_api = Flat::from_raw(Block64(x_flat)).tower_bit(k);
                prop_assert_eq!(
                    via_api, bit,
                    "Block64 tower_bit_from_hardware mismatch at x_flat={:#018x}, bit_idx={}",
                    x_flat, k
                );
            }
        }
    }
}
