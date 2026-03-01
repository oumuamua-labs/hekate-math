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

//! BLOCK 8 (GF(2^8))
use crate::constants::FLAT_TO_TOWER_BIT_MASKS_8;
use crate::towers::bit::Bit;
use crate::{CanonicalDeserialize, HardwarePromote, constants};
use crate::{CanonicalSerialize, HardwareField, PackableField, TowerField};
use core::ops::{Add, AddAssign, BitXor, Mul, MulAssign, Sub, SubAssign};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[cfg(not(feature = "table-math"))]
#[repr(align(64))]
struct CtConvertBasisU8<const N: usize>([u8; N]);

#[cfg(not(feature = "table-math"))]
static TOWER_TO_FLAT_BASIS_8: CtConvertBasisU8<8> =
    CtConvertBasisU8(constants::RAW_TOWER_TO_FLAT_8);

#[cfg(not(feature = "table-math"))]
static FLAT_TO_TOWER_BASIS_8: CtConvertBasisU8<8> =
    CtConvertBasisU8(constants::RAW_FLAT_TO_TOWER_8);

// ============================================================
// Precomputed Lookup Tables for GF(2^8) arithmetic.
// Polynomial: x^8 + x^4 + x^3 + x + 1 (0x11B) [AES Standard]
// Generator: 3 (x + 1)
// ============================================================

/// Exponentiation Table: g^i
/// Maps index i -> value inside the field.
/// Range: [0..255].
/// Note that EXP_TABLE[0] == 1 and EXP_TABLE[255] == 1.
#[cfg(feature = "table-math")]
const EXP_TABLE: [u8; 256] = generate_exp_table();

/// Logarithm Table: log_g(x)
/// Maps value x -> power i such that g^i = x.
/// Range: LOG_TABLE[1..=255] contain values 0..254.
/// LOG_TABLE[0] is 0 (undefined).
#[cfg(feature = "table-math")]
const LOG_TABLE: [u8; 256] = generate_log_table();

/// Field element GF(2^8).
#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[repr(transparent)]
pub struct Block8(pub u8);

impl Block8 {
    pub const fn new(val: u8) -> Self {
        Self(val)
    }
}

impl TowerField for Block8 {
    const BITS: usize = 8;
    const ZERO: Self = Block8(0);
    const ONE: Self = Block8(1);

    const EXTENSION_TAU: Self = Block8(0x20);

    fn invert(&self) -> Self {
        #[cfg(feature = "table-math")]
        {
            if self.0 == 0 {
                return Self::ZERO;
            }

            let i = LOG_TABLE[self.0 as usize] as usize;
            Block8(EXP_TABLE[255 - i])
        }

        #[cfg(not(feature = "table-math"))]
        {
            // Fermat's Little Theorem:
            // a^-1 = a^254 in GF(2^8)
            // Constant-time, no branching.
            let x = *self;
            let x2 = x * x;
            let x4 = x2 * x2;
            let x8 = x4 * x4;
            let x16 = x8 * x8;
            let x32 = x16 * x16;
            let x64 = x32 * x32;
            let x128 = x64 * x64;

            // 254 = 128 + 64 + 32 + 16 + 8 + 4 + 2
            x128 * x64 * x32 * x16 * x8 * x4 * x2
        }
    }

    fn from_uniform_bytes(bytes: &[u8; 32]) -> Self {
        Self(bytes[0])
    }
}

/// Add (XOR)
impl Add for Block8 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self::Output {
        Self(self.0.bitxor(rhs.0))
    }
}

impl Sub for Block8 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self::Output {
        self.add(rhs)
    }
}

/// Mul (Galois Field Multiplication)
impl Mul for Block8 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self::Output {
        #[cfg(feature = "table-math")]
        {
            // Handle zero explicitly (log(0) is undefined)
            if self.0 == 0 || rhs.0 == 0 {
                return Self::ZERO;
            }

            // Lookup Logarithms
            // Math:
            // a * b = g^(log(a) + log(b))
            let i = LOG_TABLE[self.0 as usize] as usize;
            let j = LOG_TABLE[rhs.0 as usize] as usize;

            // Add exponents modulo 255
            // Since max(i) = 254, max(i+j) = 508.
            // Check if sum >= 255 and subtract.
            let k = i + j;
            let idx = if k >= 255 { k - 255 } else { k };

            // Lookup Exponent result
            Self(EXP_TABLE[idx])
        }

        #[cfg(not(feature = "table-math"))]
        {
            #[cfg(target_arch = "aarch64")]
            {
                neon::mul_8(self, rhs)
            }

            #[cfg(not(target_arch = "aarch64"))]
            {
                let mut a = self.0;
                let mut b = rhs.0;
                let mut res = 0u8;

                // Constant-time shift-and-add
                // over GF(2^8) with poly 0x11B.
                for _ in 0..8 {
                    let bit = b & 1;
                    let mask = 0u8.wrapping_sub(bit);
                    res ^= a & mask;

                    let high_bit = a >> 7;
                    let overflow_mask = 0u8.wrapping_sub(high_bit);
                    a = (a << 1) ^ (0x1B & overflow_mask);

                    b >>= 1;
                }

                Self(res)
            }
        }
    }
}

impl AddAssign for Block8 {
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl SubAssign for Block8 {
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl MulAssign for Block8 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl CanonicalSerialize for Block8 {
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

impl CanonicalDeserialize for Block8 {
    fn deserialize(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.is_empty() {
            return Err(());
        }

        Ok(Self(bytes[0]))
    }
}

impl From<u8> for Block8 {
    #[inline]
    fn from(val: u8) -> Self {
        Self::new(val)
    }
}

impl From<u32> for Block8 {
    #[inline]
    fn from(val: u32) -> Self {
        Self(val as u8)
    }
}

impl From<u64> for Block8 {
    #[inline]
    fn from(val: u64) -> Self {
        Self(val as u8)
    }
}

impl From<u128> for Block8 {
    #[inline]
    fn from(val: u128) -> Self {
        Self(val as u8)
    }
}

// ========================================
// FIELD LIFTING
// ========================================

impl From<Bit> for Block8 {
    #[inline(always)]
    fn from(val: Bit) -> Self {
        Self(val.0)
    }
}

// ===================================
// PACKED BLOCK 8 (Width = 16)
// ===================================

// 128 bits / 8 = 16 elements
pub const PACKED_WIDTH_8: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(C, align(16))]
pub struct PackedBlock8(pub [Block8; PACKED_WIDTH_8]);

impl PackedBlock8 {
    #[inline(always)]
    pub fn zero() -> Self {
        Self([Block8::ZERO; PACKED_WIDTH_8])
    }
}

impl PackableField for Block8 {
    type Packed = PackedBlock8;

    const WIDTH: usize = PACKED_WIDTH_8;

    #[inline(always)]
    fn pack(chunk: &[Self]) -> Self::Packed {
        assert!(
            chunk.len() >= PACKED_WIDTH_8,
            "PackableField::pack: input slice too short",
        );

        let mut arr = [Self::ZERO; PACKED_WIDTH_8];
        arr.copy_from_slice(&chunk[..PACKED_WIDTH_8]);

        PackedBlock8(arr)
    }

    #[inline(always)]
    fn unpack(packed: Self::Packed, output: &mut [Self]) {
        assert!(
            output.len() >= PACKED_WIDTH_8,
            "PackableField::unpack: output slice too short",
        );

        output[..PACKED_WIDTH_8].copy_from_slice(&packed.0);
    }
}

impl Add for PackedBlock8 {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        let mut res = [Block8::ZERO; PACKED_WIDTH_8];
        for ((out, l), r) in res.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            *out = *l + *r;
        }

        Self(res)
    }
}

impl AddAssign for PackedBlock8 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        for (l, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *l += *r;
        }
    }
}

impl Sub for PackedBlock8 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

impl SubAssign for PackedBlock8 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.add_assign(rhs);
    }
}

impl Mul for PackedBlock8 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            let mut res = [Block8::ZERO; PACKED_WIDTH_8];
            for ((out, l), r) in res.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
                *out = mul_iso_8(*l, *r);
            }

            Self(res)
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let mut res = [Block8::ZERO; PACKED_WIDTH_8];
            for ((out, l), r) in res.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
                *out = *l * *r;
            }

            Self(res)
        }
    }
}

impl MulAssign for PackedBlock8 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl Mul<Block8> for PackedBlock8 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Block8) -> Self {
        let mut res = [Block8::ZERO; PACKED_WIDTH_8];
        for (out, v) in res.iter_mut().zip(self.0.iter()) {
            *out = *v * rhs;
        }

        Self(res)
    }
}

// ===================================
// Hardware Field
// ===================================

impl HardwareField for Block8 {
    #[inline(always)]
    fn to_hardware(self) -> Self {
        #[cfg(feature = "table-math")]
        {
            apply_matrix_8(self, &constants::TOWER_TO_FLAT_8)
        }

        #[cfg(not(feature = "table-math"))]
        {
            Block8(map_ct_8(self.0, &TOWER_TO_FLAT_BASIS_8.0))
        }
    }

    #[inline(always)]
    fn convert_hardware(self) -> Self {
        #[cfg(feature = "table-math")]
        {
            apply_matrix_8(self, &constants::FLAT_TO_TOWER_8)
        }

        #[cfg(not(feature = "table-math"))]
        {
            Block8(map_ct_8(self.0, &FLAT_TO_TOWER_BASIS_8.0))
        }
    }

    #[inline(always)]
    fn add_hardware(self, rhs: Self) -> Self {
        self + rhs
    }

    #[inline(always)]
    fn add_hardware_packed(lhs: Self::Packed, rhs: Self::Packed) -> Self::Packed {
        #[cfg(target_arch = "aarch64")]
        {
            neon::add_packed_8(lhs, rhs)
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            lhs + rhs
        }
    }

    #[inline(always)]
    fn mul_hardware(self, rhs: Self) -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            neon::mul_8(self, rhs)
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let a_tower = self.convert_hardware();
            let b_tower = rhs.convert_hardware();
            (a_tower * b_tower).to_hardware()
        }
    }

    #[inline(always)]
    fn mul_hardware_packed(lhs: Self::Packed, rhs: Self::Packed) -> Self::Packed {
        #[cfg(target_arch = "aarch64")]
        {
            neon::mul_flat_packed_8(lhs, rhs)
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let mut l = [Self::ZERO; <Self as PackableField>::WIDTH];
            let mut r = [Self::ZERO; <Self as PackableField>::WIDTH];
            let mut res = [Self::ZERO; <Self as PackableField>::WIDTH];

            Self::unpack(lhs, &mut l);
            Self::unpack(rhs, &mut r);

            for i in 0..<Self as PackableField>::WIDTH {
                res[i] = l[i].mul_hardware(r[i]);
            }

            Self::pack(&res)
        }
    }

    #[inline(always)]
    fn tower_bit_from_hardware(self, bit_idx: usize) -> u8 {
        assert!(bit_idx < 8, "bit index out of bounds for Block8");

        let mask = unsafe { *FLAT_TO_TOWER_BIT_MASKS_8.get_unchecked(bit_idx) };

        // Parity of (x & mask) without popcount
        let mut v = self.0 & mask;
        v ^= v >> 4;
        v ^= v >> 2;
        v ^= v >> 1;

        v & 1
    }
}

impl HardwarePromote<Block8> for Block8 {
    #[inline(always)]
    fn from_partial_hardware(val: Block8) -> Self {
        val
    }
}

// ===========================================
// UTILS
// ===========================================

#[cfg(target_arch = "aarch64")]
#[inline(always)]
fn mul_iso_8(a: Block8, b: Block8) -> Block8 {
    let a_f = a.to_hardware();
    let b_f = b.to_hardware();

    let c_f = neon::mul_8(a_f, b_f);

    c_f.convert_hardware()
}

#[cfg(feature = "table-math")]
#[inline(always)]
fn apply_matrix_8(val: Block8, table: &[u8; 256]) -> Block8 {
    let idx = val.0 as usize;
    Block8(unsafe { *table.get_unchecked(idx) })
}

#[cfg(not(feature = "table-math"))]
#[inline(always)]
fn map_ct_8(x: u8, basis: &[u8; 8]) -> u8 {
    let mut acc = 0u8;
    let mut i = 0usize;

    while i < 8 {
        let bit = (x >> i) & 1;
        let mask = 0u8.wrapping_sub(bit);
        acc ^= basis[i] & mask;
        i += 1;
    }

    acc
}

#[cfg(feature = "table-math")]
const fn generate_exp_table() -> [u8; 256] {
    let mut table = [0u8; 256];
    let mut val: u8 = 1;

    // Iterate i from 0 to 255 (inclusive).
    // This fills table[0]..table[255].
    // At i=0, table[0] = 1.
    // At i=255, val cycles back to 1, so table[255] = 1.
    // This allows safe access to table[255]
    // during inversion logic (255 - i).
    let mut i = 0;
    while i < 256 {
        table[i] = val;

        // Multiply val by GENERATOR (3) in GF(2^8)
        // val * 3 = val * (x + 1) = (val << 1) ^ val

        let high_bit = val & 0x80;
        let mut shifted = val << 1;

        // AES Polynomial 0x11B.
        // If high bit was set, XOR with
        // the lower 8 bits (0x1B).
        if high_bit != 0 {
            shifted ^= 0x1B;
        }

        val = shifted ^ val;
        i += 1;
    }

    table
}

#[cfg(feature = "table-math")]
const fn generate_log_table() -> [u8; 256] {
    let mut table = [0u8; 256];

    // For Log table, iterate 0..254.
    // Valid log values are in range [0, 254].
    // log(1) is 0. log(g^254) is 254.
    //
    // Note:
    // Don't map index 255 here, as log(1)
    // is strictly 0 for canonical form.

    let mut val: u8 = 1;
    let mut i = 0;

    while i < 255 {
        table[val as usize] = i as u8;

        let high_bit = val & 0x80;
        let mut shifted = val << 1;

        if high_bit != 0 {
            shifted ^= 0x1B;
        }

        val = shifted ^ val;

        i += 1;
    }

    // table[0] remains 0 (log(0) is undefined).

    table
}

// ===========================================
// 8-BIT SIMD INSTRUCTIONS
// ===========================================

#[cfg(target_arch = "aarch64")]
mod neon {
    use super::*;
    use core::arch::aarch64::*;
    use core::mem::transmute;

    #[inline(always)]
    pub fn add_packed_8(lhs: PackedBlock8, rhs: PackedBlock8) -> PackedBlock8 {
        unsafe {
            let res = veorq_u8(
                transmute::<[Block8; 16], uint8x16_t>(lhs.0),
                transmute::<[Block8; 16], uint8x16_t>(rhs.0),
            );
            transmute(res)
        }
    }

    #[inline(always)]
    pub fn mul_8(a: Block8, b: Block8) -> Block8 {
        unsafe {
            // Load 8-bit scalars
            // into NEON vectors.
            let a_poly = transmute::<uint8x8_t, poly8x8_t>(vdup_n_u8(a.0));
            let b_poly = transmute::<uint8x8_t, poly8x8_t>(vdup_n_u8(b.0));

            // Multiply:
            // 8-bit x 8-bit -> 16-bit
            let prod = vmull_p8(a_poly, b_poly);

            // Extract the 16-bit result
            let prod_u16 = vgetq_lane_u16(transmute::<poly16x8_t, uint16x8_t>(prod), 0);

            let l = (prod_u16 & 0xFF) as u8;
            let h = (prod_u16 >> 8) as u8;

            // P(x) = x^8 + 0x1B
            let r_val = constants::POLY_8; // u8

            // Fold high bits (h * 0x1B)
            let h_poly = transmute::<uint8x8_t, poly8x8_t>(vdup_n_u8(h));
            let r_poly = transmute::<uint8x8_t, poly8x8_t>(vdup_n_u8(r_val));
            let h_red = vmull_p8(h_poly, r_poly);

            let h_red_u16 = vgetq_lane_u16(transmute::<poly16x8_t, uint16x8_t>(h_red), 0);

            let folded = (h_red_u16 & 0xFF) as u8;
            let carry = (h_red_u16 >> 8) as u8;

            let mut res = l ^ folded;

            // Unconditional carry reduction:
            // If carry is 0, c_poly is 0,
            // c_red is 0, and XOR does nothing.
            let c_poly = transmute::<uint8x8_t, poly8x8_t>(vdup_n_u8(carry));
            let c_red = vmull_p8(c_poly, r_poly);
            let c_red_u16 = vgetq_lane_u16(transmute::<poly16x8_t, uint16x8_t>(c_red), 0);

            res ^= (c_red_u16 & 0xFF) as u8;

            Block8(res)
        }
    }

    /// Vectorized multiplication for Block8 (16 elements at once).
    /// Uses vmull_p8 for multiplication and vqtbl1q_u8 for reduction.
    #[inline(always)]
    pub fn mul_flat_packed_8(lhs: PackedBlock8, rhs: PackedBlock8) -> PackedBlock8 {
        unsafe {
            let a: uint8x16_t = transmute(lhs.0);
            let b: uint8x16_t = transmute(rhs.0);

            // Split into low/high 64-bit halves
            let a_lo = vget_low_u8(a);
            let a_hi = vget_high_u8(a);
            let b_lo = vget_low_u8(b);
            let b_hi = vget_high_u8(b);

            // Multiply 8x8 -> 16 bits
            // (poly16x8_t, which is 128-bit wide)
            let res_lo = vmull_p8(
                transmute::<uint8x8_t, poly8x8_t>(a_lo),
                transmute::<uint8x8_t, poly8x8_t>(b_lo),
            );
            let res_hi = vmull_p8(
                transmute::<uint8x8_t, poly8x8_t>(a_hi),
                transmute::<uint8x8_t, poly8x8_t>(b_hi),
            );

            // Reduction using Table Lookup
            // Load the tables once.
            let tbl_lo = vld1q_u8(
                [
                    0x00, 0x1b, 0x36, 0x2d, 0x6c, 0x77, 0x5a, 0x41, 0xd8, 0xc3, 0xee, 0xf5, 0xb4,
                    0xaf, 0x82, 0x99,
                ]
                .as_ptr(),
            );

            let tbl_hi = vld1q_u8(
                [
                    0x00, 0xab, 0x4d, 0xe6, 0x9a, 0x31, 0xd7, 0x7c, 0x2f, 0x84, 0x62, 0xc9, 0xb5,
                    0x1e, 0xf8, 0x53,
                ]
                .as_ptr(),
            );

            // Helper to reduce a 128-bit vector
            // of 16-bit polys down to a 64-bit
            // vector of 8-bit results.
            let reduce_tbl = |val_poly: poly16x8_t| -> uint8x8_t {
                let val: uint16x8_t = transmute(val_poly);

                // vmovn_u16 narrows 128-bit (u16x8) to 64-bit (u8x8)
                let data = vmovn_u16(val);
                let carry_u16 = vshrq_n_u16(val, 8);
                let carry = vmovn_u16(carry_u16);

                // Operations on 64-bit vectors
                let mask_lo = vdup_n_u8(0x0F);
                let h_lo = vand_u8(carry, mask_lo);
                let h_hi = vshr_n_u8(carry, 4);

                // Lookup:
                // Table is 128-bit (q),
                // Index is 64-bit.
                // Result is 64-bit.
                let r_lo = vqtbl1_u8(tbl_lo, h_lo);
                let r_hi = vqtbl1_u8(tbl_hi, h_hi);

                // XOR everything together
                veor_u8(data, veor_u8(r_lo, r_hi))
            };

            let final_lo = reduce_tbl(res_lo);
            let final_hi = reduce_tbl(res_hi);

            // Combine two 64-bit results
            // back into one 128-bit vector.
            let res = vcombine_u8(final_lo, final_hi);

            PackedBlock8(transmute::<uint8x16_t, [Block8; 16]>(res))
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
    fn tower_constants() {
        // Check that tau is propagated correctly
        // For Block8 we set 0x20
        assert_eq!(Block8::EXTENSION_TAU, Block8(0x20));
    }

    #[test]
    fn add_truth() {
        let zero = Block8::ZERO;
        let one = Block8::ONE;

        assert_eq!(zero + zero, zero);
        assert_eq!(zero + one, one);
        assert_eq!(one + zero, one);
        assert_eq!(one + one, zero);
    }

    #[test]
    fn mul_truth() {
        let zero = Block8::ZERO;
        let one = Block8::ONE;

        assert_eq!(zero * zero, zero);
        assert_eq!(zero * one, zero);
        assert_eq!(one * one, one);
    }

    #[test]
    fn add() {
        // 5 ^ 3 = 6
        // 101 ^ 011 = 110
        assert_eq!(Block8(5) + Block8(3), Block8(6));
    }

    #[test]
    fn mul_simple() {
        // Check for prime numbers (without overflow)
        // x^1 * x^1 = x^2 (2 * 2 = 4)
        assert_eq!(Block8(2) * Block8(2), Block8(4));
    }

    #[test]
    fn mul_overflow() {
        // Reduction verification (AES test vectors)
        // Example from the AES specification:
        // 0x57 * 0x83 = 0xC1
        assert_eq!(Block8(0x57) * Block8(0x83), Block8(0xC1));
    }

    #[test]
    fn security_zeroize() {
        let mut secret_val = Block8::from(0xFF_u32);
        assert_ne!(secret_val, Block8::ZERO);

        secret_val.zeroize();

        assert_eq!(secret_val, Block8::ZERO);
        assert_eq!(secret_val.0, 0, "Block8 memory leak detected");
    }

    #[test]
    fn inversion_exhaustive() {
        // Iterate over all possible field elements (0..255)
        for i in 0u8..=255 {
            let val = Block8(i);

            if val == Block8::ZERO {
                // Case 1:
                // Zero inversion safety check
                assert_eq!(val.invert(), Block8::ZERO, "invert(0) must return 0");
            } else {
                // Case 2:
                // Algebraic correctness a * a^-1 = 1
                let inv = val.invert();
                let product = val * inv;

                assert_eq!(
                    product,
                    Block8::ONE,
                    "Inversion identity failed: a * a^-1 != 1"
                );
            }
        }
    }

    // ==================================
    // HARDWARE
    // ==================================

    #[test]
    fn isomorphism_roundtrip() {
        let mut rng = rng();
        for _ in 0..1000 {
            let val = Block8::from(rng.random::<u8>());

            // Roundtrip:
            // Tower -> Flat -> Tower must be identity
            assert_eq!(
                val.to_hardware().convert_hardware(),
                val,
                "Block8 isomorphism roundtrip failed"
            );
        }
    }

    #[test]
    fn parity_masks_match_convert_hardware() {
        // Exhaustive for Block8:
        // 256 values * 8 bits.
        for x in 0u16..=255 {
            let x_flat = x as u8;
            let tower = Block8(x_flat).convert_hardware().0;

            for (k, &mask) in FLAT_TO_TOWER_BIT_MASKS_8.iter().enumerate() {
                let parity = ((x_flat & mask).count_ones() & 1) as u8;
                let bit = (tower >> k) & 1;
                assert_eq!(
                    parity, bit,
                    "Block8 mask mismatch at x={x_flat:#04x}, k={k}"
                );

                let via_api = Block8(x_flat).tower_bit_from_hardware(k);
                assert_eq!(via_api, bit, "Block8 tower_bit_from_hardware mismatch");
            }
        }
    }

    #[test]
    fn flat_mul_homomorphism() {
        let mut rng = rng();
        for _ in 0..1000 {
            let a = Block8::from(rng.random::<u8>());
            let b = Block8::from(rng.random::<u8>());

            let expected_flat = (a * b).to_hardware();
            let actual_flat = a.to_hardware().mul_hardware(b.to_hardware());

            // Check if multiplication in Flat basis matches Tower
            assert_eq!(
                actual_flat, expected_flat,
                "Block8 flat multiplication mismatch"
            );
        }
    }

    #[test]
    fn packed_consistency() {
        let mut rng = rng();
        for _ in 0..100 {
            let mut a_vals = [Block8::ZERO; 16];
            let mut b_vals = [Block8::ZERO; 16];

            for i in 0..16 {
                a_vals[i] = Block8::from(rng.random::<u8>());
                b_vals[i] = Block8::from(rng.random::<u8>());
            }

            let a_packed = Block8::pack(&a_vals);
            let b_packed = Block8::pack(&b_vals);

            // Test SIMD Add (XOR)
            let add_res = Block8::add_hardware_packed(a_packed, b_packed);

            let mut add_out = [Block8::ZERO; 16];
            Block8::unpack(add_res, &mut add_out);

            for i in 0..16 {
                assert_eq!(
                    add_out[i],
                    a_vals[i] + b_vals[i],
                    "Block8 packed add mismatch"
                );
            }

            // Test SIMD Mul (Flat basis)
            let a_flat_packed = Block8::pack(&a_vals.map(|x| x.to_hardware()));
            let b_flat_packed = Block8::pack(&b_vals.map(|x| x.to_hardware()));
            let mul_res = Block8::mul_hardware_packed(a_flat_packed, b_flat_packed);

            let mut mul_out = [Block8::ZERO; 16];
            Block8::unpack(mul_res, &mut mul_out);

            for i in 0..16 {
                assert_eq!(
                    mul_out[i],
                    (a_vals[i] * b_vals[i]).to_hardware(),
                    "Block8 packed mul mismatch"
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
        let mut data = [Block8::ZERO; PACKED_WIDTH_8];

        for v in data.iter_mut() {
            *v = Block8(rng.random());
        }

        let packed = Block8::pack(&data);
        let mut unpacked = [Block8::ZERO; PACKED_WIDTH_8];
        Block8::unpack(packed, &mut unpacked);

        assert_eq!(data, unpacked, "Block8 pack/unpack roundtrip failed");
    }

    #[test]
    fn packed_add_consistency() {
        let mut rng = rng();
        let mut a_vals = [Block8::ZERO; PACKED_WIDTH_8];
        let mut b_vals = [Block8::ZERO; PACKED_WIDTH_8];

        for i in 0..PACKED_WIDTH_8 {
            a_vals[i] = Block8(rng.random());
            b_vals[i] = Block8(rng.random());
        }

        let a_packed = Block8::pack(&a_vals);
        let b_packed = Block8::pack(&b_vals);
        let res_packed = a_packed + b_packed;

        let mut res_unpacked = [Block8::ZERO; PACKED_WIDTH_8];
        Block8::unpack(res_packed, &mut res_unpacked);

        for i in 0..PACKED_WIDTH_8 {
            assert_eq!(
                res_unpacked[i],
                a_vals[i] + b_vals[i],
                "Block8 packed add mismatch at index {}",
                i
            );
        }
    }

    #[test]
    fn packed_mul_consistency() {
        let mut rng = rng();

        for _ in 0..1000 {
            let mut a_arr = [Block8::ZERO; PACKED_WIDTH_8];
            let mut b_arr = [Block8::ZERO; PACKED_WIDTH_8];

            for i in 0..PACKED_WIDTH_8 {
                let val_a: u8 = rng.random();
                let val_b: u8 = rng.random();
                a_arr[i] = Block8(val_a);
                b_arr[i] = Block8(val_b);
            }

            let a_packed = PackedBlock8(a_arr);
            let b_packed = PackedBlock8(b_arr);
            let c_packed = a_packed * b_packed;

            let mut c_expected = [Block8::ZERO; PACKED_WIDTH_8];
            for i in 0..PACKED_WIDTH_8 {
                c_expected[i] = a_arr[i] * b_arr[i];
            }

            assert_eq!(c_packed.0, c_expected, "SIMD Block8 mismatch!");
        }
    }
}
