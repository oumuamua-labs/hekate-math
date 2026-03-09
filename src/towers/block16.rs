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

//! BLOCK 16 (GF(2^16))
use crate::towers::bit::Bit;
use crate::towers::block8::Block8;
use crate::{
    CanonicalDeserialize, CanonicalSerialize, Flat, FlatPromote, HardwareField, PackableField,
    PackedFlat, TowerField, constants,
};
use core::ops::{Add, AddAssign, BitXor, BitXorAssign, Mul, MulAssign, Sub, SubAssign};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[cfg(not(feature = "table-math"))]
#[repr(align(64))]
struct CtConvertBasisU16<const N: usize>([u16; N]);

#[cfg(not(feature = "table-math"))]
static TOWER_TO_FLAT_BASIS_16: CtConvertBasisU16<16> =
    CtConvertBasisU16(constants::RAW_TOWER_TO_FLAT_16);

#[cfg(not(feature = "table-math"))]
static FLAT_TO_TOWER_BASIS_16: CtConvertBasisU16<16> =
    CtConvertBasisU16(constants::RAW_FLAT_TO_TOWER_16);

#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[repr(transparent)]
pub struct Block16(pub u16);

impl Block16 {
    pub const TAU: Self = Block16(0x2000);

    pub fn new(lo: Block8, hi: Block8) -> Self {
        Self((hi.0 as u16) << 8 | (lo.0 as u16))
    }

    #[inline(always)]
    pub fn split(self) -> (Block8, Block8) {
        (Block8(self.0 as u8), Block8((self.0 >> 8) as u8))
    }
}

impl TowerField for Block16 {
    const BITS: usize = 16;
    const ZERO: Self = Block16(0);
    const ONE: Self = Block16(1);

    const EXTENSION_TAU: Self = Self::TAU;

    fn invert(&self) -> Self {
        let (l, h) = self.split();

        // Norm = h^2 * tau + h*l + l^2
        let h2 = h * h;
        let l2 = l * l;
        let hl = h * l;
        let norm = (h2 * Block8::EXTENSION_TAU) + hl + l2;

        let norm_inv = norm.invert();

        // Res = (h*norm_inv) X + (h+l)*norm_inv
        let res_hi = h * norm_inv;
        let res_lo = (h + l) * norm_inv;

        Self::new(res_lo, res_hi)
    }

    fn from_uniform_bytes(bytes: &[u8; 32]) -> Self {
        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[0..2]);

        Self(u16::from_le_bytes(buf))
    }
}

impl Add for Block16 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0.bitxor(rhs.0))
    }
}

impl Sub for Block16 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        Self(self.0.bitxor(rhs.0))
    }
}

impl Mul for Block16 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let (a0, a1) = self.split();
        let (b0, b1) = rhs.split();

        // Karatsuba
        let v0 = a0 * b0;
        let v1 = a1 * b1;
        let v_sum = (a0 + a1) * (b0 + b1);

        // Reconstruction with reduction X^2 = X + tau
        // Hi
        let c_hi = v0 + v_sum;

        // Lo
        let c_lo = v0 + (v1 * Block8::EXTENSION_TAU);

        Self::new(c_lo, c_hi)
    }
}

impl AddAssign for Block16 {
    fn add_assign(&mut self, rhs: Self) {
        self.0.bitxor_assign(rhs.0);
    }
}

impl SubAssign for Block16 {
    fn sub_assign(&mut self, rhs: Self) {
        self.0.bitxor_assign(rhs.0);
    }
}

impl MulAssign for Block16 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl CanonicalSerialize for Block16 {
    fn serialized_size(&self) -> usize {
        2
    }

    fn serialize(&self, writer: &mut [u8]) -> Result<(), ()> {
        if writer.len() < 2 {
            return Err(());
        }

        writer.copy_from_slice(&self.0.to_le_bytes());

        Ok(())
    }
}

impl CanonicalDeserialize for Block16 {
    fn deserialize(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() < 2 {
            return Err(());
        }

        let mut buf = [0u8; 2];
        buf.copy_from_slice(&bytes[0..2]);

        Ok(Self(u16::from_le_bytes(buf)))
    }
}

impl From<u8> for Block16 {
    fn from(val: u8) -> Self {
        Self(val as u16)
    }
}

impl From<u16> for Block16 {
    #[inline]
    fn from(val: u16) -> Self {
        Self(val)
    }
}

impl From<u32> for Block16 {
    #[inline]
    fn from(val: u32) -> Self {
        Self(val as u16)
    }
}

impl From<u64> for Block16 {
    #[inline]
    fn from(val: u64) -> Self {
        Self(val as u16)
    }
}

impl From<u128> for Block16 {
    #[inline]
    fn from(val: u128) -> Self {
        Self(val as u16)
    }
}

// ========================================
// FIELD LIFTING
// ========================================

impl From<Bit> for Block16 {
    #[inline(always)]
    fn from(val: Bit) -> Self {
        Self(val.0 as u16)
    }
}

impl From<Block8> for Block16 {
    #[inline(always)]
    fn from(val: Block8) -> Self {
        Self(val.0 as u16)
    }
}

// ===================================
// PACKED BLOCK 16 (Width = 8)
// ===================================

// 128 bits / 16 = 8 elements
pub const PACKED_WIDTH_16: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(C, align(16))]
pub struct PackedBlock16(pub [Block16; PACKED_WIDTH_16]);

impl PackedBlock16 {
    #[inline(always)]
    pub fn zero() -> Self {
        Self([Block16::ZERO; PACKED_WIDTH_16])
    }
}

impl PackableField for Block16 {
    type Packed = PackedBlock16;

    const WIDTH: usize = PACKED_WIDTH_16;

    #[inline(always)]
    fn pack(chunk: &[Self]) -> Self::Packed {
        assert!(
            chunk.len() >= PACKED_WIDTH_16,
            "PackableField::pack: input slice too short",
        );

        let mut arr = [Self::ZERO; PACKED_WIDTH_16];
        arr.copy_from_slice(&chunk[..PACKED_WIDTH_16]);

        PackedBlock16(arr)
    }

    #[inline(always)]
    fn unpack(packed: Self::Packed, output: &mut [Self]) {
        assert!(
            output.len() >= PACKED_WIDTH_16,
            "PackableField::unpack: output slice too short",
        );

        output[..PACKED_WIDTH_16].copy_from_slice(&packed.0);
    }
}

impl Add for PackedBlock16 {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        let mut res = [Block16::ZERO; PACKED_WIDTH_16];
        for ((out, l), r) in res.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            *out = *l + *r;
        }

        Self(res)
    }
}

impl AddAssign for PackedBlock16 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        for (l, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *l += *r;
        }
    }
}

impl Sub for PackedBlock16 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

impl SubAssign for PackedBlock16 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.add_assign(rhs);
    }
}

impl Mul for PackedBlock16 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            let mut res = [Block16::ZERO; PACKED_WIDTH_16];
            for ((out, l), r) in res.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
                *out = mul_iso_16(*l, *r);
            }

            Self(res)
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let mut res = [Block16::ZERO; PACKED_WIDTH_16];
            for ((out, l), r) in res.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
                *out = *l * *r;
            }

            Self(res)
        }
    }
}

impl MulAssign for PackedBlock16 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Mul<Block16> for PackedBlock16 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Block16) -> Self {
        let mut res = [Block16::ZERO; PACKED_WIDTH_16];
        for (out, v) in res.iter_mut().zip(self.0.iter()) {
            *out = *v * rhs;
        }

        Self(res)
    }
}

// ===================================
// Hardware Field
// ===================================

impl HardwareField for Block16 {
    #[inline(always)]
    fn to_hardware(self) -> Flat<Self> {
        #[cfg(feature = "table-math")]
        {
            Flat::from_raw(apply_matrix_16(self, &constants::TOWER_TO_FLAT_16))
        }

        #[cfg(not(feature = "table-math"))]
        {
            Flat::from_raw(Block16(map_ct_16(self.0, &TOWER_TO_FLAT_BASIS_16.0)))
        }
    }

    #[inline(always)]
    fn from_hardware(value: Flat<Self>) -> Self {
        let value = value.into_raw();

        #[cfg(feature = "table-math")]
        {
            apply_matrix_16(value, &constants::FLAT_TO_TOWER_16)
        }

        #[cfg(not(feature = "table-math"))]
        {
            Block16(map_ct_16(value.0, &FLAT_TO_TOWER_BASIS_16.0))
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
            PackedFlat::from_raw(neon::add_packed_16(lhs, rhs))
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
            Flat::from_raw(neon::mul_flat_16(lhs, rhs))
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
            PackedFlat::from_raw(neon::mul_flat_packed_16(lhs, rhs))
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
        let mask = constants::FLAT_TO_TOWER_BIT_MASKS_16[bit_idx];

        // Parity of (x & mask) without
        // popcount. Folds 16 bits down
        // to 1 using a binary XOR tree.
        let mut v = value.into_raw().0 & mask;
        v ^= v >> 8;
        v ^= v >> 4;
        v ^= v >> 2;
        v ^= v >> 1;

        (v & 1) as u8
    }
}

impl FlatPromote<Block8> for Block16 {
    #[inline(always)]
    fn promote_flat(val: Flat<Block8>) -> Flat<Self> {
        let val = val.into_raw();

        #[cfg(not(feature = "table-math"))]
        {
            let mut acc = 0u16;
            for i in 0..8 {
                let bit = (val.0 >> i) & 1;
                let mask = 0u16.wrapping_sub(bit as u16);
                acc ^= constants::LIFT_BASIS_8_TO_16[i] & mask;
            }

            Flat::from_raw(Block16(acc))
        }

        #[cfg(feature = "table-math")]
        {
            Flat::from_raw(Block16(constants::LIFT_TABLE_8_TO_16[val.0 as usize]))
        }
    }
}

// ===========================================
// UTILS
// ===========================================

#[cfg(target_arch = "aarch64")]
#[inline(always)]
pub fn mul_iso_16(a: Block16, b: Block16) -> Block16 {
    let a_f = a.to_hardware();
    let b_f = b.to_hardware();
    let c_f = Flat::from_raw(neon::mul_flat_16(a_f.into_raw(), b_f.into_raw()));

    c_f.to_tower()
}

#[cfg(feature = "table-math")]
#[inline(always)]
pub fn apply_matrix_16(val: Block16, table: &[u16; 512]) -> Block16 {
    let v = val.0;
    let mut res = 0u16;

    // 2 lookups (8-bit window)
    for i in 0..2 {
        let idx = (i * 256) + ((v >> (i * 8)) & 0xFF) as usize;
        res ^= unsafe { *table.get_unchecked(idx) };
    }

    Block16(res)
}

#[cfg(not(feature = "table-math"))]
#[inline(always)]
fn map_ct_16(x: u16, basis: &[u16; 16]) -> u16 {
    let mut acc = 0u16;
    let mut i = 0usize;

    while i < 16 {
        let bit = (x >> i) & 1;
        let mask = 0u16.wrapping_sub(bit);
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
    pub fn add_packed_16(lhs: PackedBlock16, rhs: PackedBlock16) -> PackedBlock16 {
        unsafe {
            let res = veorq_u8(
                transmute::<[Block16; 8], uint8x16_t>(lhs.0),
                transmute::<[Block16; 8], uint8x16_t>(rhs.0),
            );
            transmute(res)
        }
    }

    #[inline(always)]
    pub fn mul_flat_16(a: Block16, b: Block16) -> Block16 {
        unsafe {
            // Note: Using 64-bit PMULL for 16-bit blocks
            // is optimal on Apple Silicon. The pipeline
            // parallelism of scalar `vmull_p64` outperforms
            // complex SIMD Karatsuba.
            let prod = vmull_p64(a.0 as u64, b.0 as u64);
            let prod_val = vgetq_lane_u64(transmute::<u128, uint64x2_t>(prod), 0);

            let l = (prod_val & 0xFFFF) as u16;
            let h = (prod_val >> 16) as u16; // The rest fits in u16 for 16x16

            // P(x) = x^16 + R
            let r_val = constants::POLY_16 as u64;

            // h * R
            let h_red = vmull_p64(h as u64, r_val);
            let h_red_val = vgetq_lane_u64(transmute::<u128, uint64x2_t>(h_red), 0);

            // Result of h*R fits in 32 bits max (16+16).
            // It's x^16 * H = H * R.
            // res = L ^ (H*R)
            // Since H*R > 16 bits, we have carry.

            let folded = (h_red_val & 0xFFFF) as u16;
            let carry = (h_red_val >> 16) as u16;

            let mut res = l ^ folded;

            // Unconditional reduction
            // ensures constant-time.
            let c_red = vmull_p64(carry as u64, r_val);
            let c_val = vgetq_lane_u64(transmute::<u128, uint64x2_t>(c_red), 0);

            res ^= c_val as u16;

            Block16(res)
        }
    }

    /// Vectorized multiplication
    /// for Block16 (8 elements at once).
    /// Uses Vector Karatsuba +
    /// Shift-XOR Reduction for 0x2B.
    #[inline(always)]
    pub fn mul_flat_packed_16(lhs: PackedBlock16, rhs: PackedBlock16) -> PackedBlock16 {
        let r0 = mul_flat_16(lhs.0[0], rhs.0[0]);
        let r1 = mul_flat_16(lhs.0[1], rhs.0[1]);
        let r2 = mul_flat_16(lhs.0[2], rhs.0[2]);
        let r3 = mul_flat_16(lhs.0[3], rhs.0[3]);
        let r4 = mul_flat_16(lhs.0[4], rhs.0[4]);
        let r5 = mul_flat_16(lhs.0[5], rhs.0[5]);
        let r6 = mul_flat_16(lhs.0[6], rhs.0[6]);
        let r7 = mul_flat_16(lhs.0[7], rhs.0[7]);

        PackedBlock16([r0, r1, r2, r3, r4, r5, r6, r7])
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
    fn tower_constants() {
        // Check that tau is propagated correctly
        // For Block16, tau must be (0, 1) from Block8.
        let tau16 = Block16::EXTENSION_TAU;
        let (lo16, hi16) = tau16.split();
        assert_eq!(lo16, Block8::ZERO);
        assert_eq!(hi16, Block8(0x20));
    }

    #[test]
    fn add_truth() {
        let zero = Block16::ZERO;
        let one = Block16::ONE;

        assert_eq!(zero + zero, zero);
        assert_eq!(zero + one, one);
        assert_eq!(one + zero, one);
        assert_eq!(one + one, zero);
    }

    #[test]
    fn mul_truth() {
        let zero = Block16::ZERO;
        let one = Block16::ONE;

        assert_eq!(zero * zero, zero);
        assert_eq!(zero * one, zero);
        assert_eq!(one * one, one);
    }

    #[test]
    fn add() {
        // 5 ^ 3 = 6
        // 101 ^ 011 = 110
        assert_eq!(Block16(5) + Block16(3), Block16(6));
    }

    #[test]
    fn mul_simple() {
        // Check for prime numbers (without overflow)
        // x^1 * x^1 = x^2 (2 * 2 = 4)
        assert_eq!(Block16(2) * Block16(2), Block16(4));
    }

    #[test]
    fn mul_overflow() {
        // Reduction verification (AES test vectors)
        // Example from the AES specification:
        // 0x57 * 0x83 = 0xC1
        assert_eq!(Block16(0x57) * Block16(0x83), Block16(0xC1));
    }

    #[test]
    fn karatsuba_correctness() {
        // Let A = X (hi=1, lo=0)
        // Let B = X (hi=1, lo=0)
        // A * B = X^2
        // According to the rule:
        // X^2 = X + tau
        // Where tau for Block8 = 0x20.
        // So the result should be:
        // hi=1 (X), lo=0x20 (tau)

        // Construct X manually
        let x = Block16::new(Block8::ZERO, Block8::ONE);
        let squared = x * x;

        // Verify result via splitting
        let (res_lo, res_hi) = squared.split();

        assert_eq!(res_hi, Block8::ONE, "X^2 should contain X component");
        assert_eq!(
            res_lo,
            Block8(0x20),
            "X^2 should contain tau component (0x20)"
        );
    }

    #[test]
    fn security_zeroize() {
        let mut secret_val = Block16::from(0xDEAD_u16);
        assert_ne!(secret_val, Block16::ZERO);

        secret_val.zeroize();

        assert_eq!(secret_val, Block16::ZERO);
        assert_eq!(secret_val.0, 0, "Block16 memory leak detected");
    }

    #[test]
    fn invert_zero() {
        // Critical safety check:
        // Inverting zero must return 0 by convention.
        assert_eq!(
            Block16::ZERO.invert(),
            Block16::ZERO,
            "invert(0) must return 0"
        );
    }

    #[test]
    fn inversion_random() {
        let mut rng = rng();

        // Test a significant number of random elements
        for _ in 0..1000 {
            let val_u16: u16 = rng.random();
            let val = Block16(val_u16);

            if val != Block16::ZERO {
                let inv = val.invert();
                let res = val * inv;

                assert_eq!(
                    res,
                    Block16::ONE,
                    "Inversion identity failed: a * a^-1 != 1"
                );
            }
        }
    }

    #[test]
    fn tower_embedding() {
        let mut rng = rng();
        for _ in 0..100 {
            let a = Block8(rng.random());
            let b = Block8(rng.random());

            // 1. Structure check:
            // Lifting puts value in low part,
            // zero in high part Subfield element
            // 'a' inside extension must look like (a, 0)
            let a_lifted: Block16 = a.into();
            let (lo, hi) = a_lifted.split();

            assert_eq!(lo, a, "Embedding structure failed: low part mismatch");
            assert_eq!(
                hi,
                Block8::ZERO,
                "Embedding structure failed: high part must be zero"
            );

            // 2. Addition Homomorphism:
            // lift(a + b) == lift(a) + lift(b)
            let sum_sub = a + b;
            let sum_lifted: Block16 = sum_sub.into();
            let sum_manual = Block16::from(a) + Block16::from(b);

            assert_eq!(sum_lifted, sum_manual, "Homomorphism failed: add");

            // 3. Multiplication Homomorphism:
            // lift(a * b) == lift(a) * lift(b)
            // Operations in the subfield must
            // match operations in the superfield.
            let prod_sub = a * b;
            let prod_lifted: Block16 = prod_sub.into();
            let prod_manual = Block16::from(a) * Block16::from(b);

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
            let val = Block16(rng.random::<u16>());
            assert_eq!(
                val.to_hardware().to_tower(),
                val,
                "Block16 isomorphism roundtrip failed"
            );
        }
    }

    #[test]
    fn flat_mul_homomorphism() {
        let mut rng = rng();
        for _ in 0..1000 {
            let a = Block16(rng.random::<u16>());
            let b = Block16(rng.random::<u16>());

            let expected_flat = (a * b).to_hardware();
            let actual_flat = a.to_hardware() * b.to_hardware();

            assert_eq!(
                actual_flat, expected_flat,
                "Block16 flat multiplication mismatch"
            );
        }
    }

    #[test]
    fn packed_consistency() {
        let mut rng = rng();
        for _ in 0..100 {
            let mut a_vals = [Block16::ZERO; 8];
            let mut b_vals = [Block16::ZERO; 8];

            for i in 0..8 {
                a_vals[i] = Block16(rng.random::<u16>());
                b_vals[i] = Block16(rng.random::<u16>());
            }

            let a_flat_vals = a_vals.map(|x| x.to_hardware());
            let b_flat_vals = b_vals.map(|x| x.to_hardware());
            let a_packed = Flat::<Block16>::pack(&a_flat_vals);
            let b_packed = Flat::<Block16>::pack(&b_flat_vals);

            // Test SIMD Add
            let add_res = Block16::add_hardware_packed(a_packed, b_packed);

            let mut add_out = [Block16::ZERO.to_hardware(); 8];
            Flat::<Block16>::unpack(add_res, &mut add_out);

            for i in 0..8 {
                assert_eq!(
                    add_out[i],
                    (a_vals[i] + b_vals[i]).to_hardware(),
                    "Block16 packed add mismatch"
                );
            }

            // Test SIMD Mul
            let mul_res = Block16::mul_hardware_packed(a_packed, b_packed);

            let mut mul_out = [Block16::ZERO.to_hardware(); 8];
            Flat::<Block16>::unpack(mul_res, &mut mul_out);

            for i in 0..8 {
                assert_eq!(
                    mul_out[i],
                    (a_vals[i] * b_vals[i]).to_hardware(),
                    "Block16 packed mul mismatch"
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
        let mut data = [Block16::ZERO; PACKED_WIDTH_16];

        for v in data.iter_mut() {
            *v = Block16(rng.random());
        }

        let packed = Block16::pack(&data);
        let mut unpacked = [Block16::ZERO; PACKED_WIDTH_16];
        Block16::unpack(packed, &mut unpacked);

        assert_eq!(data, unpacked, "Block16 pack/unpack roundtrip failed");
    }

    #[test]
    fn packed_add_consistency() {
        let mut rng = rng();
        let mut a_vals = [Block16::ZERO; PACKED_WIDTH_16];
        let mut b_vals = [Block16::ZERO; PACKED_WIDTH_16];

        for i in 0..PACKED_WIDTH_16 {
            a_vals[i] = Block16(rng.random());
            b_vals[i] = Block16(rng.random());
        }

        let res_packed = Block16::pack(&a_vals) + Block16::pack(&b_vals);
        let mut res_unpacked = [Block16::ZERO; PACKED_WIDTH_16];
        Block16::unpack(res_packed, &mut res_unpacked);

        for i in 0..PACKED_WIDTH_16 {
            assert_eq!(
                res_unpacked[i],
                a_vals[i] + b_vals[i],
                "Block16 packed add mismatch"
            );
        }
    }

    #[test]
    fn packed_mul_consistency() {
        let mut rng = rng();

        for _ in 0..1000 {
            let mut a_arr = [Block16::ZERO; PACKED_WIDTH_16];
            let mut b_arr = [Block16::ZERO; PACKED_WIDTH_16];

            for i in 0..PACKED_WIDTH_16 {
                let val_a_u16: u16 = rng.random();
                let val_b_u16: u16 = rng.random();

                a_arr[i] = Block16(val_a_u16);
                b_arr[i] = Block16(val_b_u16);
            }

            let a_packed = PackedBlock16(a_arr);
            let b_packed = PackedBlock16(b_arr);
            let c_packed = a_packed * b_packed;

            let mut c_expected = [Block16::ZERO; PACKED_WIDTH_16];
            for i in 0..PACKED_WIDTH_16 {
                c_expected[i] = a_arr[i] * b_arr[i];
            }

            assert_eq!(c_packed.0, c_expected, "SIMD Block16 mismatch!");
        }
    }

    #[test]
    fn parity_masks_match_from_hardware() {
        // Exhaustive for Block16:
        // 65536 values * 16 bits.
        for x_flat in 0u16..=u16::MAX {
            let tower = Block16::from_hardware(Flat::from_raw(Block16(x_flat))).0;

            for k in 0..16 {
                let bit = ((tower >> k) & 1) as u8;
                let via_api = Flat::from_raw(Block16(x_flat)).tower_bit(k);

                assert_eq!(
                    via_api, bit,
                    "Block16 tower_bit_from_hardware mismatch at x_flat={x_flat:#06x}, bit_idx={k}"
                );
            }
        }
    }
}
