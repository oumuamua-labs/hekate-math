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

//! BLOCK 32 (GF(2^32))
use crate::towers::bit::Bit;
use crate::towers::block8::Block8;
use crate::towers::block16::Block16;
use crate::{
    CanonicalDeserialize, CanonicalSerialize, Flat, FlatPromote, HardwareField, PackableField,
    PackedFlat, TowerField, constants,
};
use core::ops::{Add, AddAssign, BitXor, BitXorAssign, Mul, MulAssign, Sub, SubAssign};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[cfg(not(feature = "table-math"))]
#[repr(align(64))]
struct CtConvertBasisU32<const N: usize>([u32; N]);

#[cfg(not(feature = "table-math"))]
static TOWER_TO_FLAT_BASIS_32: CtConvertBasisU32<32> =
    CtConvertBasisU32(constants::RAW_TOWER_TO_FLAT_32);

#[cfg(not(feature = "table-math"))]
static FLAT_TO_TOWER_BASIS_32: CtConvertBasisU32<32> =
    CtConvertBasisU32(constants::RAW_FLAT_TO_TOWER_32);

#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[repr(transparent)]
pub struct Block32(pub u32);

impl Block32 {
    // 0x2000 << 16 = 0x2000_0000
    pub const TAU: Self = Block32(0x2000_0000);

    pub fn new(lo: Block16, hi: Block16) -> Self {
        Self((hi.0 as u32) << 16 | (lo.0 as u32))
    }

    #[inline(always)]
    pub fn split(self) -> (Block16, Block16) {
        (Block16(self.0 as u16), Block16((self.0 >> 16) as u16))
    }
}

impl TowerField for Block32 {
    const BITS: usize = 32;
    const ZERO: Self = Block32(0);
    const ONE: Self = Block32(1);

    const EXTENSION_TAU: Self = Self::TAU;

    fn invert(&self) -> Self {
        let (l, h) = self.split();
        let h2 = h * h;
        let l2 = l * l;
        let hl = h * l;

        // Tau here is Block16::TAU
        let norm = (h2 * Block16::TAU) + hl + l2;

        let norm_inv = norm.invert();
        let res_hi = h * norm_inv;
        let res_lo = (h + l) * norm_inv;

        Self::new(res_lo, res_hi)
    }

    fn from_uniform_bytes(bytes: &[u8; 32]) -> Self {
        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);

        Self(u32::from_le_bytes(buf))
    }
}

impl Add for Block32 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0.bitxor(rhs.0))
    }
}

impl Sub for Block32 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

impl Mul for Block32 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let (a0, a1) = self.split();
        let (b0, b1) = rhs.split();

        let v0 = a0 * b0;
        let v1 = a1 * b1;
        let v_sum = (a0 + a1) * (b0 + b1);

        let c_hi = v0 + v_sum;
        let c_lo = v0 + (v1 * Block16::TAU);

        Self::new(c_lo, c_hi)
    }
}

impl AddAssign for Block32 {
    fn add_assign(&mut self, rhs: Self) {
        self.0.bitxor_assign(rhs.0);
    }
}

impl SubAssign for Block32 {
    fn sub_assign(&mut self, rhs: Self) {
        self.0.bitxor_assign(rhs.0);
    }
}

impl MulAssign for Block32 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl CanonicalSerialize for Block32 {
    fn serialized_size(&self) -> usize {
        4
    }

    fn serialize(&self, writer: &mut [u8]) -> Result<(), ()> {
        if writer.len() < 4 {
            return Err(());
        }

        writer.copy_from_slice(&self.0.to_le_bytes());

        Ok(())
    }
}

impl CanonicalDeserialize for Block32 {
    fn deserialize(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() < 4 {
            return Err(());
        }

        let mut buf = [0u8; 4];
        buf.copy_from_slice(&bytes[0..4]);

        Ok(Self(u32::from_le_bytes(buf)))
    }
}

impl From<u8> for Block32 {
    fn from(val: u8) -> Self {
        Self(val as u32)
    }
}

impl From<u16> for Block32 {
    #[inline]
    fn from(val: u16) -> Self {
        Self::from(val as u32)
    }
}

impl From<u32> for Block32 {
    #[inline]
    fn from(val: u32) -> Self {
        Self(val)
    }
}

impl From<u64> for Block32 {
    #[inline]
    fn from(val: u64) -> Self {
        Self(val as u32)
    }
}

impl From<u128> for Block32 {
    #[inline]
    fn from(val: u128) -> Self {
        Self(val as u32)
    }
}

// ========================================
// FIELD LIFTING
// ========================================

impl From<Bit> for Block32 {
    #[inline(always)]
    fn from(val: Bit) -> Self {
        Self(val.0 as u32)
    }
}

impl From<Block8> for Block32 {
    #[inline(always)]
    fn from(val: Block8) -> Self {
        Self(val.0 as u32)
    }
}

impl From<Block16> for Block32 {
    #[inline(always)]
    fn from(val: Block16) -> Self {
        Self(val.0 as u32)
    }
}

// ========================================
// PACKED BLOCK 32 (Width = 4)
// ========================================

pub const PACKED_WIDTH_32: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(C, align(16))]
pub struct PackedBlock32(pub [Block32; PACKED_WIDTH_32]);

impl PackedBlock32 {
    #[inline(always)]
    pub fn zero() -> Self {
        Self([Block32::ZERO; PACKED_WIDTH_32])
    }
}

impl PackableField for Block32 {
    type Packed = PackedBlock32;

    const WIDTH: usize = PACKED_WIDTH_32;

    #[inline(always)]
    fn pack(chunk: &[Self]) -> Self::Packed {
        assert!(
            chunk.len() >= PACKED_WIDTH_32,
            "PackableField::pack: input slice too short",
        );

        let mut arr = [Self::ZERO; PACKED_WIDTH_32];
        arr.copy_from_slice(&chunk[..PACKED_WIDTH_32]);

        PackedBlock32(arr)
    }

    #[inline(always)]
    fn unpack(packed: Self::Packed, output: &mut [Self]) {
        assert!(
            output.len() >= PACKED_WIDTH_32,
            "PackableField::unpack: output slice too short",
        );

        output[..PACKED_WIDTH_32].copy_from_slice(&packed.0);
    }
}

impl Add for PackedBlock32 {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        let mut res = [Block32::ZERO; PACKED_WIDTH_32];
        for ((out, l), r) in res.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            *out = *l + *r;
        }

        Self(res)
    }
}

impl AddAssign for PackedBlock32 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        for (l, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *l += *r;
        }
    }
}

impl Sub for PackedBlock32 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

impl SubAssign for PackedBlock32 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.add_assign(rhs);
    }
}

impl Mul for PackedBlock32 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            let a0 = mul_iso_32(self.0[0], rhs.0[0]);
            let a1 = mul_iso_32(self.0[1], rhs.0[1]);
            let a2 = mul_iso_32(self.0[2], rhs.0[2]);
            let a3 = mul_iso_32(self.0[3], rhs.0[3]);

            Self([a0, a1, a2, a3])
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let mut res = [Block32::ZERO; PACKED_WIDTH_32];
            for ((out, l), r) in res.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
                *out = *l * *r;
            }

            Self(res)
        }
    }
}

impl MulAssign for PackedBlock32 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        for (l, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *l *= *r;
        }
    }
}

impl Mul<Block32> for PackedBlock32 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Block32) -> Self {
        let mut res = [Block32::ZERO; PACKED_WIDTH_32];
        for (out, v) in res.iter_mut().zip(self.0.iter()) {
            *out = *v * rhs;
        }

        Self(res)
    }
}

// ===================================
// Block32 Hardware Field
// ===================================

impl HardwareField for Block32 {
    #[inline(always)]
    fn to_hardware(self) -> Flat<Self> {
        #[cfg(feature = "table-math")]
        {
            Flat::from_raw(apply_matrix_32(self, &constants::TOWER_TO_FLAT_32))
        }

        #[cfg(not(feature = "table-math"))]
        {
            Flat::from_raw(Block32(map_ct_32(self.0, &TOWER_TO_FLAT_BASIS_32.0)))
        }
    }

    #[inline(always)]
    fn from_hardware(value: Flat<Self>) -> Self {
        let value = value.into_raw();
        #[cfg(feature = "table-math")]
        {
            apply_matrix_32(value, &constants::FLAT_TO_TOWER_32)
        }

        #[cfg(not(feature = "table-math"))]
        {
            Block32(map_ct_32(value.0, &FLAT_TO_TOWER_BASIS_32.0))
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
            PackedFlat::from_raw(neon::add_packed_32(lhs, rhs))
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
            Flat::from_raw(neon::mul_flat_32(lhs, rhs))
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
            PackedFlat::from_raw(neon::mul_flat_packed_32(lhs, rhs))
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
    fn mul_hardware_scalar_packed(lhs: PackedFlat<Self>, rhs: Flat<Self>) -> PackedFlat<Self> {
        let broadcasted = PackedBlock32([rhs.into_raw(); PACKED_WIDTH_32]);
        Self::mul_hardware_packed(lhs, PackedFlat::from_raw(broadcasted))
    }

    #[inline(always)]
    fn tower_bit_from_hardware(value: Flat<Self>, bit_idx: usize) -> u8 {
        let mask = constants::FLAT_TO_TOWER_BIT_MASKS_32[bit_idx];

        // Parity of (x & mask) without popcount.
        // Folds 32 bits down to 1
        // using a binary XOR tree.
        let mut v = value.into_raw().0 & mask;
        v ^= v >> 16;
        v ^= v >> 8;
        v ^= v >> 4;
        v ^= v >> 2;
        v ^= v >> 1;

        (v & 1) as u8
    }
}

impl FlatPromote<Block8> for Block32 {
    #[inline(always)]
    fn promote_flat(val: Flat<Block8>) -> Flat<Self> {
        let val = val.into_raw();
        #[cfg(not(feature = "table-math"))]
        {
            let mut acc = 0u32;
            for i in 0..8 {
                let bit = (val.0 >> i) & 1;
                let mask = 0u32.wrapping_sub(bit as u32);
                acc ^= constants::LIFT_BASIS_8_TO_32[i] & mask;
            }

            Flat::from_raw(Block32(acc))
        }

        #[cfg(feature = "table-math")]
        {
            Flat::from_raw(Block32(constants::LIFT_TABLE_8_TO_32[val.0 as usize]))
        }
    }
}

// ===========================================
// UTILS
// ===========================================

#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn mul_iso_32(a: Block32, b: Block32) -> Block32 {
    let a_flat = a.to_hardware();
    let b_flat = b.to_hardware();
    let c_flat = Flat::from_raw(neon::mul_flat_32(a_flat.into_raw(), b_flat.into_raw()));

    c_flat.to_tower()
}

#[cfg(feature = "table-math")]
#[inline(always)]
pub fn apply_matrix_32(val: Block32, table: &[u32; 1024]) -> Block32 {
    let mut res = 0u32;
    let v = val.0;

    // 4 lookups
    for i in 0..4 {
        let byte = (v >> (i * 8)) & 0xFF;
        let idx = (i * 256) + (byte as usize);
        res ^= unsafe { *table.get_unchecked(idx) };
    }

    Block32(res)
}

#[cfg(not(feature = "table-math"))]
#[inline(always)]
fn map_ct_32(x: u32, basis: &[u32; 32]) -> u32 {
    let mut acc = 0u32;
    let mut i = 0usize;

    while i < 32 {
        let bit = (x >> i) & 1;
        let mask = 0u32.wrapping_sub(bit);
        acc ^= basis[i] & mask;
        i += 1;
    }

    acc
}

// ===========================================
// 32-BIT SIMD INSTRUCTIONS
// ===========================================

#[cfg(target_arch = "aarch64")]
mod neon {
    use super::*;
    use core::arch::aarch64::*;
    use core::mem::transmute;

    #[inline(always)]
    pub fn add_packed_32(lhs: PackedBlock32, rhs: PackedBlock32) -> PackedBlock32 {
        unsafe {
            let l: uint8x16_t = transmute::<[Block32; PACKED_WIDTH_32], uint8x16_t>(lhs.0);
            let r: uint8x16_t = transmute::<[Block32; PACKED_WIDTH_32], uint8x16_t>(rhs.0);
            let res = veorq_u8(l, r);
            let out: [Block32; PACKED_WIDTH_32] =
                transmute::<uint8x16_t, [Block32; PACKED_WIDTH_32]>(res);

            PackedBlock32(out)
        }
    }

    #[inline(always)]
    pub fn mul_flat_packed_32(lhs: PackedBlock32, rhs: PackedBlock32) -> PackedBlock32 {
        let r0 = mul_flat_32(lhs.0[0], rhs.0[0]);
        let r1 = mul_flat_32(lhs.0[1], rhs.0[1]);
        let r2 = mul_flat_32(lhs.0[2], rhs.0[2]);
        let r3 = mul_flat_32(lhs.0[3], rhs.0[3]);

        PackedBlock32([r0, r1, r2, r3])
    }

    #[inline(always)]
    pub fn mul_flat_32(a: Block32, b: Block32) -> Block32 {
        unsafe {
            // 1. Multiply 32x32 -> 64
            // Cast u32 to u64 for vmull
            let prod = vmull_p64(a.0 as u64, b.0 as u64);

            // The result is 128-bit type, but only care
            // about low 64 bits because 32*32 fits in 64 bits.
            let prod_u64: uint64x2_t = transmute(prod);
            let prod_val = vgetq_lane_u64(prod_u64, 0);

            let l = (prod_val & 0xFFFFFFFF) as u32;
            let h = (prod_val >> 32) as u32;

            // 2. Reduce mod P(x) = x^32 + R(x)
            let r_val = constants::POLY_32 as u64;

            // H * R
            let h_red = vmull_p64(h as u64, r_val);
            let h_red_vec: uint64x2_t = transmute(h_red);
            let h_red_val = vgetq_lane_u64(h_red_vec, 0);

            let folded = (h_red_val & 0xFFFFFFFF) as u32;
            let carry = (h_red_val >> 32) as u32;

            let mut res = l ^ folded;

            // 3. Reduce carry
            let carry_red = vmull_p64(carry as u64, r_val);
            let carry_res_vec: uint64x2_t = transmute(carry_red);
            let carry_val = vgetq_lane_u64(carry_res_vec, 0);

            res ^= carry_val as u32;

            Block32(res)
        }
    }
}

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
        // For Block32, tau must be (0, 1) from Block16.
        let tau32 = Block32::EXTENSION_TAU;
        let (lo32, hi32) = tau32.split();
        assert_eq!(lo32, Block16::ZERO);
        assert_eq!(hi32, Block16::TAU);
    }

    #[test]
    fn add_truth() {
        let zero = Block32::ZERO;
        let one = Block32::ONE;

        assert_eq!(zero + zero, zero);
        assert_eq!(zero + one, one);
        assert_eq!(one + zero, one);
        assert_eq!(one + one, zero);
    }

    #[test]
    fn mul_truth() {
        let zero = Block32::ZERO;
        let one = Block32::ONE;

        assert_eq!(zero * zero, zero);
        assert_eq!(zero * one, zero);
        assert_eq!(one * one, one);
    }

    #[test]
    fn add() {
        // 5 ^ 3 = 6
        // 101 ^ 011 = 110
        assert_eq!(Block32(5) + Block32(3), Block32(6));
    }

    #[test]
    fn mul_simple() {
        // Check for prime numbers (without overflow)
        // x^1 * x^1 = x^2 (2 * 2 = 4)
        assert_eq!(Block32(2) * Block32(2), Block32(4));
    }

    #[test]
    fn mul_overflow() {
        // Reduction verification (AES test vectors)
        // Example from the AES specification:
        // 0x57 * 0x83 = 0xC1
        assert_eq!(Block32(0x57) * Block32(0x83), Block32(0xC1));
    }

    #[test]
    fn karatsuba_correctness() {
        // Let A = X (hi=1, lo=0)
        // Let B = X (hi=1, lo=0)
        // A * B = X^2
        // According to the rule:
        // X^2 = X + tau
        // Where tau for Block16 = 0x2000.
        // So the result should be:
        // hi=1 (X), lo=0x20 (tau)

        // Construct X manually
        let x = Block32::new(Block16::ZERO, Block16::ONE);
        let squared = x * x;

        // Verify result via splitting
        let (res_lo, res_hi) = squared.split();

        assert_eq!(res_hi, Block16::ONE, "X^2 should contain X component");
        assert_eq!(
            res_lo,
            Block16(0x2000),
            "X^2 should contain tau component (0x2000)"
        );
    }

    #[test]
    fn security_zeroize() {
        let mut secret_val = Block32::from(0xDEAD_BEEF_u32);
        assert_ne!(secret_val, Block32::ZERO);

        secret_val.zeroize();

        assert_eq!(secret_val, Block32::ZERO);
        assert_eq!(secret_val.0, 0, "Block32 memory leak detected");
    }

    #[test]
    fn invert_zero() {
        // Verify that inverting zero adheres
        // to the API contract (returns 0).
        assert_eq!(
            Block32::ZERO.invert(),
            Block32::ZERO,
            "invert(0) must return 0"
        );
    }

    #[test]
    fn inversion_random() {
        let mut rng = rng();
        for _ in 0..1000 {
            let val = Block32(rng.random());

            if val != Block32::ZERO {
                let inv = val.invert();
                let res = val * inv;

                assert_eq!(
                    res,
                    Block32::ONE,
                    "Inversion identity failed: a * a^-1 != 1"
                );
            }
        }
    }

    #[test]
    fn tower_embedding() {
        let mut rng = rng();
        for _ in 0..100 {
            let a_u16: u16 = rng.random();
            let b_u16: u16 = rng.random();
            let a = Block16(a_u16);
            let b = Block16(b_u16);

            // 1. Structure check
            let a_lifted: Block32 = a.into();
            let (lo, hi) = a_lifted.split();

            assert_eq!(lo, a, "Embedding structure failed: low part mismatch");
            assert_eq!(
                hi,
                Block16::ZERO,
                "Embedding structure failed: high part must be zero"
            );

            // 2. Addition Homomorphism
            let sum_sub = a + b;
            let sum_lifted: Block32 = sum_sub.into();
            let sum_manual = Block32::from(a) + Block32::from(b);

            assert_eq!(sum_lifted, sum_manual, "Homomorphism failed: add");

            // 3. Multiplication Homomorphism
            let prod_sub = a * b;
            let prod_lifted: Block32 = prod_sub.into();
            let prod_manual = Block32::from(a) * Block32::from(b);

            assert_eq!(prod_lifted, prod_manual, "Homomorphism failed: mul");
        }
    }

    // ==================================
    // HARDWARE
    // ==================================

    #[test]
    fn isomorphism_roundtrip() {
        let mut rng = rng();
        for _ in 0..1000 {
            let val = Block32(rng.random::<u32>());
            assert_eq!(
                val.to_hardware().to_tower(),
                val,
                "Block32 isomorphism roundtrip failed"
            );
        }
    }

    #[test]
    fn flat_mul_homomorphism() {
        let mut rng = rng();
        for _ in 0..1000 {
            let a = Block32(rng.random::<u32>());
            let b = Block32(rng.random::<u32>());
            assert_eq!(a.to_hardware() * b.to_hardware(), (a * b).to_hardware());
        }
    }

    #[test]
    fn packed_consistency() {
        let mut rng = rng();
        let mut a_vals = [Block32::ZERO; 4];
        let mut b_vals = [Block32::ZERO; 4];

        for i in 0..4 {
            a_vals[i] = Block32(rng.random::<u32>());
            b_vals[i] = Block32(rng.random::<u32>());
        }

        // Add consistency
        let a_flat_vals = a_vals.map(|x| x.to_hardware());
        let b_flat_vals = b_vals.map(|x| x.to_hardware());
        let add_res = Block32::add_hardware_packed(
            Flat::<Block32>::pack(&a_flat_vals),
            Flat::<Block32>::pack(&b_flat_vals),
        );

        let mut add_out = [Block32::ZERO.to_hardware(); 4];
        Flat::<Block32>::unpack(add_res, &mut add_out);

        for i in 0..4 {
            assert_eq!(add_out[i], (a_vals[i] + b_vals[i]).to_hardware());
        }

        // Mul consistency (Flat basis)
        let mul_res = Block32::mul_hardware_packed(
            Flat::<Block32>::pack(&a_flat_vals),
            Flat::<Block32>::pack(&b_flat_vals),
        );

        let mut mul_out = [Block32::ZERO.to_hardware(); 4];
        Flat::<Block32>::unpack(mul_res, &mut mul_out);

        for i in 0..4 {
            assert_eq!(mul_out[i], (a_vals[i] * b_vals[i]).to_hardware());
        }
    }

    // ==================================
    // PACKED
    // ==================================

    #[test]
    fn pack_unpack_roundtrip() {
        let mut rng = rng();
        let mut data = [Block32::ZERO; PACKED_WIDTH_32];

        for v in data.iter_mut() {
            *v = Block32(rng.random());
        }

        let packed = Block32::pack(&data);
        let mut unpacked = [Block32::ZERO; PACKED_WIDTH_32];
        Block32::unpack(packed, &mut unpacked);

        assert_eq!(data, unpacked);
    }

    #[test]
    fn packed_add_consistency() {
        let mut rng = rng();
        let a_vals = [
            Block32(rng.random()),
            Block32(rng.random()),
            Block32(rng.random()),
            Block32(rng.random()),
        ];
        let b_vals = [
            Block32(rng.random()),
            Block32(rng.random()),
            Block32(rng.random()),
            Block32(rng.random()),
        ];

        let res_packed = Block32::pack(&a_vals) + Block32::pack(&b_vals);
        let mut res_unpacked = [Block32::ZERO; PACKED_WIDTH_32];
        Block32::unpack(res_packed, &mut res_unpacked);

        for i in 0..PACKED_WIDTH_32 {
            assert_eq!(res_unpacked[i], a_vals[i] + b_vals[i]);
        }
    }

    #[test]
    fn packed_mul_consistency() {
        let mut rng = rng();

        for _ in 0..1000 {
            let mut a_arr = [Block32::ZERO; PACKED_WIDTH_32];
            let mut b_arr = [Block32::ZERO; PACKED_WIDTH_32];

            for i in 0..PACKED_WIDTH_32 {
                let val_a: u32 = rng.random();
                let val_b: u32 = rng.random();
                a_arr[i] = Block32(val_a);
                b_arr[i] = Block32(val_b);
            }

            let a_packed = PackedBlock32(a_arr);
            let b_packed = PackedBlock32(b_arr);

            // Perform SIMD multiplication
            let c_packed = a_packed * b_packed;

            // Verify against Scalar
            let mut c_expected = [Block32::ZERO; PACKED_WIDTH_32];
            for i in 0..PACKED_WIDTH_32 {
                c_expected[i] = a_arr[i] * b_arr[i];
            }

            assert_eq!(c_packed.0, c_expected, "SIMD Block32 mismatch!");
        }
    }

    proptest! {
        #[test]
        fn parity_masks_match_from_hardware(x_flat in any::<u32>()) {
            let tower = Block32::from_hardware(Flat::from_raw(Block32(x_flat))).0;

            for k in 0..32 {
                let bit = ((tower >> k) & 1) as u8;
                let via_api = Flat::from_raw(Block32(x_flat)).tower_bit(k);

                prop_assert_eq!(
                    via_api, bit,
                    "Block32 tower_bit_from_hardware mismatch at x_flat={:#010x}, bit_idx={}",
                    x_flat, k
                );
            }
        }
    }
}
