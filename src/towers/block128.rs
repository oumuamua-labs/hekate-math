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

//! BLOCK 128 (GF(2^128))
use crate::towers::bit::Bit;
use crate::towers::block8::Block8;
use crate::towers::block16::Block16;
use crate::towers::block32::Block32;
use crate::towers::block64::Block64;
use crate::{
    CanonicalDeserialize, CanonicalSerialize, Flat, FlatPromote, HardwareField, PackableField,
    PackedFlat, TowerField, constants,
};
use core::ops::{Add, AddAssign, BitXor, BitXorAssign, Mul, MulAssign, Sub, SubAssign};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

#[cfg(not(feature = "table-math"))]
#[repr(align(64))]
struct CtConvertBasisU128<const N: usize>([u128; N]);

#[cfg(not(feature = "table-math"))]
static TOWER_TO_FLAT_BASIS_128: CtConvertBasisU128<128> =
    CtConvertBasisU128(constants::RAW_TOWER_TO_FLAT_128);

#[cfg(not(feature = "table-math"))]
static FLAT_TO_TOWER_BASIS_128: CtConvertBasisU128<128> =
    CtConvertBasisU128(constants::RAW_FLAT_TO_TOWER_128);

#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[repr(transparent)]
pub struct Block128(pub u128);

impl Block128 {
    // 0x2000_0000_0000_0000 << 64
    const TAU: Self = Block128(0x2000_0000_0000_0000_0000_0000_0000_0000);

    pub fn new(lo: Block64, hi: Block64) -> Self {
        Self((hi.0 as u128) << 64 | (lo.0 as u128))
    }

    #[inline(always)]
    pub fn split(self) -> (Block64, Block64) {
        (Block64(self.0 as u64), Block64((self.0 >> 64) as u64))
    }
}

impl TowerField for Block128 {
    const BITS: usize = 128;
    const ZERO: Self = Block128(0);
    const ONE: Self = Block128(1);

    const EXTENSION_TAU: Self = Self::TAU;

    fn invert(&self) -> Self {
        let (l, h) = self.split();
        let h2 = h * h;
        let l2 = l * l;
        let hl = h * l;
        let norm = (h2 * Block64::TAU) + hl + l2;

        let norm_inv = norm.invert();
        let res_hi = h * norm_inv;
        let res_lo = (h + l) * norm_inv;

        Self::new(res_lo, res_hi)
    }

    fn from_uniform_bytes(bytes: &[u8; 32]) -> Self {
        let mut buf = [0u8; 16];
        buf.copy_from_slice(&bytes[0..16]);

        Self(u128::from_le_bytes(buf))
    }
}

impl Add for Block128 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self(self.0.bitxor(rhs.0))
    }
}

impl Sub for Block128 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

impl Mul for Block128 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let (a0, a1) = self.split();
        let (b0, b1) = rhs.split();

        let v0 = a0 * b0;
        let v1 = a1 * b1;
        let v_sum = (a0 + a1) * (b0 + b1);

        let c_hi = v0 + v_sum;
        let c_lo = v0 + (v1 * Block64::TAU);

        Self::new(c_lo, c_hi)
    }
}

impl AddAssign for Block128 {
    fn add_assign(&mut self, rhs: Self) {
        self.0.bitxor_assign(rhs.0);
    }
}

impl SubAssign for Block128 {
    fn sub_assign(&mut self, rhs: Self) {
        self.0.bitxor_assign(rhs.0);
    }
}

impl MulAssign for Block128 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl CanonicalSerialize for Block128 {
    fn serialized_size(&self) -> usize {
        16
    }

    fn serialize(&self, writer: &mut [u8]) -> Result<(), ()> {
        if writer.len() < 16 {
            return Err(());
        }

        writer.copy_from_slice(&self.0.to_le_bytes());

        Ok(())
    }
}

impl CanonicalDeserialize for Block128 {
    fn deserialize(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() < 16 {
            return Err(());
        }

        let mut buf = [0u8; 16];
        buf.copy_from_slice(&bytes[0..16]);

        Ok(Self(u128::from_le_bytes(buf)))
    }
}

impl From<u8> for Block128 {
    fn from(val: u8) -> Self {
        Self(val as u128)
    }
}

impl From<u32> for Block128 {
    #[inline]
    fn from(val: u32) -> Self {
        Self(val as u128)
    }
}

impl From<u64> for Block128 {
    #[inline]
    fn from(val: u64) -> Self {
        Self::from(val as u128)
    }
}

impl From<u128> for Block128 {
    #[inline]
    fn from(val: u128) -> Self {
        Self(val)
    }
}

// ========================================
// FIELD LIFTING
// ========================================

impl From<Bit> for Block128 {
    #[inline(always)]
    fn from(val: Bit) -> Self {
        Self(val.0 as u128)
    }
}

impl From<Block8> for Block128 {
    #[inline(always)]
    fn from(val: Block8) -> Self {
        Self(val.0 as u128)
    }
}

impl From<Block16> for Block128 {
    #[inline(always)]
    fn from(val: Block16) -> Self {
        Self(val.0 as u128)
    }
}

impl From<Block32> for Block128 {
    #[inline(always)]
    fn from(val: Block32) -> Self {
        Self(val.0 as u128)
    }
}

impl From<Block64> for Block128 {
    #[inline(always)]
    fn from(val: Block64) -> Self {
        Self(val.0 as u128)
    }
}

// ===================================
// PACKED BLOCK 128 (Width = 4)
// ===================================

pub const PACKED_WIDTH_128: usize = 4;

/// A SIMD register containing `PACKED_WIDTH`
/// of Block128 elements. Force 32-byte alignment
/// for AVX2 compatibility.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(C, align(32))]
pub struct PackedBlock128(pub [Block128; PACKED_WIDTH_128]);

impl PackedBlock128 {
    /// Create a zeroed vector.
    #[inline(always)]
    pub fn zero() -> Self {
        Self([Block128::ZERO; PACKED_WIDTH_128])
    }

    /// Fill vector with the same value (Broadcast).
    #[inline(always)]
    pub fn broadcast(val: Block128) -> Self {
        Self([val; PACKED_WIDTH_128])
    }
}

impl PackableField for Block128 {
    type Packed = PackedBlock128;

    const WIDTH: usize = PACKED_WIDTH_128;

    #[inline(always)]
    fn pack(chunk: &[Self]) -> Self::Packed {
        assert!(
            chunk.len() >= PACKED_WIDTH_128,
            "PackableField::pack: input slice too short",
        );

        let mut arr = [Self::ZERO; PACKED_WIDTH_128];
        arr.copy_from_slice(&chunk[..PACKED_WIDTH_128]);

        PackedBlock128(arr)
    }

    #[inline(always)]
    fn unpack(packed: Self::Packed, output: &mut [Self]) {
        assert!(
            output.len() >= PACKED_WIDTH_128,
            "PackableField::unpack: output slice too short",
        );

        output[..PACKED_WIDTH_128].copy_from_slice(&packed.0);
    }
}

// 1. ADDITION (XOR)
// This is perfectly parallel. Compiler will
// vectorize this automatically using `vpxor`.

impl Add for PackedBlock128 {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        let mut res = [Block128::ZERO; PACKED_WIDTH_128];
        for ((out, l), r) in res.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            *out = *l + *r;
        }

        Self(res)
    }
}

impl AddAssign for PackedBlock128 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        for (l, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *l += *r;
        }
    }
}

// 2. SUBTRACTION (Same as Add for Char 2)

impl Sub for PackedBlock128 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

impl SubAssign for PackedBlock128 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.add_assign(rhs);
    }
}

// 3. MULTIPLICATION (Hardware Accelerated)

impl Mul for PackedBlock128 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        #[cfg(target_arch = "aarch64")]
        {
            let mut res = [Block128::ZERO; PACKED_WIDTH_128];
            for ((out, l), r) in res.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
                let a_flat = l.to_hardware();
                let b_flat = r.to_hardware();
                let c_flat =
                    Flat::from_raw(neon::mul_flat_128(a_flat.into_raw(), b_flat.into_raw()));

                *out = c_flat.to_tower();
            }

            Self(res)
        }

        #[cfg(not(target_arch = "aarch64"))]
        {
            let mut res = [Block128::ZERO; PACKED_WIDTH_128];
            for ((out, l), r) in res.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
                *out = *l * *r;
            }

            Self(res)
        }
    }
}

impl MulAssign for PackedBlock128 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        for (l, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *l *= *r;
        }
    }
}

// 4. SCALAR MULTIPLICATION (Vector * Scalar)
// Used for broadcasting coefficients.

impl Mul<Block128> for PackedBlock128 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Block128) -> Self {
        let mut res = [Block128::ZERO; PACKED_WIDTH_128];
        for (out, v) in res.iter_mut().zip(self.0.iter()) {
            *out = *v * rhs;
        }

        Self(res)
    }
}

impl MulAssign<Block128> for PackedBlock128 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Block128) {
        for v in self.0.iter_mut() {
            *v *= rhs;
        }
    }
}

// ===================================
// Block128 Hardware Field
// ===================================

impl HardwareField for Block128 {
    #[inline(always)]
    fn to_hardware(self) -> Flat<Self> {
        #[cfg(feature = "table-math")]
        {
            Flat::from_raw(apply_matrix_128(self, &constants::TOWER_TO_FLAT_128))
        }

        #[cfg(not(feature = "table-math"))]
        {
            Flat::from_raw(Block128(map_ct_128_split(
                self.0,
                &TOWER_TO_FLAT_BASIS_128.0,
            )))
        }
    }

    #[inline(always)]
    fn from_hardware(value: Flat<Self>) -> Self {
        let value = value.into_raw();

        #[cfg(feature = "table-math")]
        {
            apply_matrix_128(value, &constants::FLAT_TO_TOWER_128)
        }

        #[cfg(not(feature = "table-math"))]
        {
            Block128(map_ct_128_split(value.0, &FLAT_TO_TOWER_BASIS_128.0))
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
            PackedFlat::from_raw(neon::add_packed_128(lhs, rhs))
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
            Flat::from_raw(neon::mul_flat_128(lhs, rhs))
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
            let mut res = [Block128::ZERO; PACKED_WIDTH_128];
            for ((out, l), r) in res.iter_mut().zip(lhs.0.iter()).zip(rhs.0.iter()) {
                *out = neon::mul_flat_128(*l, *r);
            }

            PackedFlat::from_raw(PackedBlock128(res))
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
        let broadcasted = PackedBlock128::broadcast(rhs.into_raw());
        Self::mul_hardware_packed(lhs, PackedFlat::from_raw(broadcasted))
    }

    #[inline(always)]
    fn tower_bit_from_hardware(value: Flat<Self>, bit_idx: usize) -> u8 {
        let mask = constants::FLAT_TO_TOWER_BIT_MASKS_128[bit_idx];

        // Parity of (x & mask) without popcount.
        // Folds 128 bits down to 1
        // using a binary XOR tree.
        let mut v = value.into_raw().0 & mask;
        v ^= v >> 64;
        v ^= v >> 32;
        v ^= v >> 16;
        v ^= v >> 8;
        v ^= v >> 4;
        v ^= v >> 2;
        v ^= v >> 1;

        (v & 1) as u8
    }
}

// ========================================
// FIELD LIFTING (FlatPromote)
// ========================================
//
// SECURITY:
// Default implementation is constant-time (CT):
// no secret-dependent memory access.

#[cfg(not(feature = "table-math"))]
impl FlatPromote<Block8> for Block128 {
    #[inline(always)]
    fn promote_flat(val: Flat<Block8>) -> Flat<Self> {
        let val = val.into_raw();
        Flat::from_raw(Block128(lift_ct::<8>(
            val.0 as u64,
            &constants::LIFT_BASIS_8.0,
        )))
    }
}

#[cfg(not(feature = "table-math"))]
impl FlatPromote<Block16> for Block128 {
    #[inline(always)]
    fn promote_flat(val: Flat<Block16>) -> Flat<Self> {
        Flat::from_raw(Block128(lift_ct::<16>(
            val.into_raw().0 as u64,
            &constants::LIFT_BASIS_16.0,
        )))
    }
}

#[cfg(not(feature = "table-math"))]
impl FlatPromote<Block32> for Block128 {
    #[inline(always)]
    fn promote_flat(val: Flat<Block32>) -> Flat<Self> {
        Flat::from_raw(Block128(lift_ct::<32>(
            val.into_raw().0 as u64,
            &constants::LIFT_BASIS_32.0,
        )))
    }
}

#[cfg(not(feature = "table-math"))]
impl FlatPromote<Block64> for Block128 {
    #[inline(always)]
    fn promote_flat(val: Flat<Block64>) -> Flat<Self> {
        Flat::from_raw(Block128(lift_ct::<64>(
            val.into_raw().0,
            &constants::LIFT_BASIS_64.0,
        )))
    }
}

// Insecure (secret-dependent table indexing) lifting path
#[cfg(feature = "table-math")]
impl FlatPromote<Block8> for Block128 {
    #[inline(always)]
    fn promote_flat(val: Flat<Block8>) -> Flat<Self> {
        let val = val.into_raw();
        let idx_flat = val.0 as usize;
        let tower_byte = unsafe { *constants::FLAT_TO_TOWER_8.get_unchecked(idx_flat) };
        let idx_tower = tower_byte as usize;

        Flat::from_raw(Block128(unsafe {
            *constants::TOWER_TO_FLAT_128.get_unchecked(idx_tower)
        }))
    }
}

#[cfg(feature = "table-math")]
impl FlatPromote<Block16> for Block128 {
    #[inline(always)]
    fn promote_flat(val: Flat<Block16>) -> Flat<Self> {
        let val = val.into_raw();
        let v_flat = val.0;

        let mut v_tower = 0u16;
        for i in 0..2 {
            let byte = ((v_flat >> (i * 8)) & 0xFF) as usize;
            let idx = (i * 256) + byte;
            v_tower ^= unsafe { *constants::FLAT_TO_TOWER_16.get_unchecked(idx) };
        }

        let mut res = 0u128;
        for i in 0..2 {
            let byte = ((v_tower >> (i * 8)) & 0xFF) as usize;
            let idx = (i * 256) + byte;
            res ^= unsafe { *constants::TOWER_TO_FLAT_128.get_unchecked(idx) };
        }

        Flat::from_raw(Block128(res))
    }
}

#[cfg(feature = "table-math")]
impl FlatPromote<Block32> for Block128 {
    #[inline(always)]
    fn promote_flat(val: Flat<Block32>) -> Flat<Self> {
        let val = val.into_raw();
        let v_flat = val.0;

        let mut v_tower = 0u32;
        for i in 0..4 {
            let byte = ((v_flat >> (i * 8)) & 0xFF) as usize;
            let idx = (i * 256) + byte;
            v_tower ^= unsafe { *constants::FLAT_TO_TOWER_32.get_unchecked(idx) };
        }

        let mut res = 0u128;
        for i in 0..4 {
            let byte = ((v_tower >> (i * 8)) & 0xFF) as usize;
            let idx = (i * 256) + byte;
            res ^= unsafe { *constants::TOWER_TO_FLAT_128.get_unchecked(idx) };
        }

        Flat::from_raw(Block128(res))
    }
}

#[cfg(feature = "table-math")]
impl FlatPromote<Block64> for Block128 {
    #[inline(always)]
    fn promote_flat(val: Flat<Block64>) -> Flat<Self> {
        let val = val.into_raw();
        let v_flat = val.0;

        let mut v_tower = 0u64;
        for i in 0..8 {
            let byte = ((v_flat >> (i * 8)) & 0xFF) as usize;
            let idx = (i * 256) + byte;
            v_tower ^= unsafe { *constants::FLAT_TO_TOWER_64.get_unchecked(idx) };
        }

        let mut res = 0u128;
        for i in 0..8 {
            let byte = ((v_tower >> (i * 8)) & 0xFF) as usize;
            let idx = (i * 256) + byte;
            res ^= unsafe { *constants::TOWER_TO_FLAT_128.get_unchecked(idx) };
        }

        Flat::from_raw(Block128(res))
    }
}

// ===========================================
// UTILS
// ===========================================

#[cfg(feature = "table-math")]
#[inline(always)]
pub fn apply_matrix_128(val: Block128, table: &[u128; 4096]) -> Block128 {
    let mut res = 0u128;
    let v = val.0;

    // [!] The Ghost isn't in the Shell @_@

    // 16 lookups (8-bit window)
    for i in 0..16 {
        let byte = (v >> (i * 8)) & 0xFF;
        let idx = (i * 256) + (byte as usize);
        res ^= unsafe { *table.get_unchecked(idx) };
    }

    Block128(res)
}

#[cfg(not(feature = "table-math"))]
#[inline(always)]
fn map_ct_128_split(x: u128, basis: &[u128; 128]) -> u128 {
    let mut acc_lo = 0u64;
    let mut acc_hi = 0u64;
    let mut i = 0usize;

    while i < 128 {
        let bit = ((x >> i) & 1) as u64;
        let mask = 0u64.wrapping_sub(bit);

        let b = basis[i];
        acc_lo ^= (b as u64) & mask;
        acc_hi ^= ((b >> 64) as u64) & mask;

        i += 1;
    }

    (acc_lo as u128) | ((acc_hi as u128) << 64)
}

#[cfg(not(feature = "table-math"))]
#[inline(always)]
fn lift_ct<const N: usize>(x: u64, basis: &'static [u128; N]) -> u128 {
    let mut acc = 0u128;

    let mut i = 0usize;
    while i < N {
        let bit = (x >> i) & 1;
        let mask = 0u128.wrapping_sub(bit as u128);
        acc ^= basis[i] & mask;
        i += 1;
    }

    acc
}

// ===========================================
// 128-BIT SIMD INSTRUCTIONS
// ===========================================

#[cfg(target_arch = "aarch64")]
mod neon {
    use super::*;
    use core::arch::aarch64::*;
    use core::mem::transmute;

    #[inline(always)]
    pub fn add_packed_128(lhs: PackedBlock128, rhs: PackedBlock128) -> PackedBlock128 {
        unsafe {
            // Block128 is packed into 4 elements
            // (512 bits), work with 4 registers.
            let l: [uint8x16_t; 4] = transmute(lhs.0);
            let r: [uint8x16_t; 4] = transmute(rhs.0);

            let res = [
                veorq_u8(l[0], r[0]),
                veorq_u8(l[1], r[1]),
                veorq_u8(l[2], r[2]),
                veorq_u8(l[3], r[3]),
            ];

            transmute(res)
        }
    }

    #[inline(always)]
    pub fn mul_flat_128(a: Block128, b: Block128) -> Block128 {
        unsafe {
            // Treat inputs as pairs of u64
            let a_vec: uint64x2_t = transmute(a.0);
            let b_vec: uint64x2_t = transmute(b.0);

            let a0 = vgetq_lane_u64(a_vec, 0);
            let a1 = vgetq_lane_u64(a_vec, 1);
            let b0 = vgetq_lane_u64(b_vec, 0);
            let b1 = vgetq_lane_u64(b_vec, 1);

            // Karatsuba Multiplication using PMULL (64x64 -> 128)
            // vmull_p64 takes poly64_t (which is u64)
            let d0 = vmull_p64(a0, b0);
            let d2 = vmull_p64(a1, b1);
            let d1 = vmull_p64(a0 ^ a1, b0 ^ b1);

            // Mid term = D1 ^ D0 ^ D2 (128-bit XOR)
            // Since d0, d1, d2 are poly128_t,
            // cast to uint128-like (uint8x16_t) to XOR
            let d0_v: uint8x16_t = transmute(d0);
            let d1_v: uint8x16_t = transmute(d1);
            let d2_v: uint8x16_t = transmute(d2);

            let mid_v = veorq_u8(d1_v, veorq_u8(d0_v, d2_v));

            // Convert results to u64 parts for reduction
            let d0_u64: uint64x2_t = transmute(d0);
            let mid_u64: uint64x2_t = transmute(mid_v);
            let d2_u64: uint64x2_t = transmute(d2);

            let c0 = vgetq_lane_u64(d0_u64, 0);
            let c1 = vgetq_lane_u64(d0_u64, 1) ^ vgetq_lane_u64(mid_u64, 0);
            let c2 = vgetq_lane_u64(d2_u64, 0) ^ vgetq_lane_u64(mid_u64, 1);
            let c3 = vgetq_lane_u64(d2_u64, 1);

            // Reduction P(x) = x^128 + R(x).
            // R(x) = 0x87 (fits in u64)
            let r_val = constants::POLY_128 as u64;

            // Fold H = [C2, C3]
            // Multiply C2 and C3 by R(x)
            let p0 = vmull_p64(c2, r_val);
            let p1 = vmull_p64(c3, r_val);

            let p0_u64: uint64x2_t = transmute(p0);
            let p1_u64: uint64x2_t = transmute(p1);

            let folded_0 = vgetq_lane_u64(p0_u64, 0);
            let folded_1 = vgetq_lane_u64(p0_u64, 1) ^ vgetq_lane_u64(p1_u64, 0);
            let carry = vgetq_lane_u64(p1_u64, 1);

            let final_0 = c0 ^ folded_0;
            let final_1 = c1 ^ folded_1;

            // Second reduction for carry
            let carry_mul = vmull_p64(carry, r_val);

            // Use transmute to convert the opaque
            // poly128_t to something we can read.
            let carry_res_vec: uint64x2_t = transmute(carry_mul);
            let carry_res = vgetq_lane_u64(carry_res_vec, 0);

            let res_lo = final_0 ^ carry_res;
            let res_hi = final_1;

            Block128((res_lo as u128) | ((res_hi as u128) << 64))
        }
    }
}

// ==================================
// BLOCK 128 TESTS
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
        // For Block128, tau must be (0, 1) from Block64.
        let tau128 = Block128::EXTENSION_TAU;
        let (lo128, hi128) = tau128.split();
        assert_eq!(lo128, Block64::ZERO);
        assert_eq!(hi128, Block64::TAU);
    }

    #[test]
    fn add_truth() {
        let zero = Block128::ZERO;
        let one = Block128::ONE;

        assert_eq!(zero + zero, zero);
        assert_eq!(zero + one, one);
        assert_eq!(one + zero, one);
        assert_eq!(one + one, zero);
    }

    #[test]
    fn mul_truth() {
        let zero = Block128::ZERO;
        let one = Block128::ONE;

        assert_eq!(zero * zero, zero);
        assert_eq!(zero * one, zero);
        assert_eq!(one * one, one);
    }

    #[test]
    fn add() {
        // 5 ^ 3 = 6
        // 101 ^ 011 = 110
        assert_eq!(Block128(5) + Block128(3), Block128(6));
    }

    #[test]
    fn mul_simple() {
        // Check for prime numbers (without overflow)
        // x^1 * x^1 = x^2 (2 * 2 = 4)
        assert_eq!(Block128(2) * Block128(2), Block128(4));
    }

    #[test]
    fn mul_overflow() {
        // Reduction verification (AES test vectors)
        // Example from the AES specification:
        // 0x57 * 0x83 = 0xC1
        assert_eq!(Block128(0x57) * Block128(0x83), Block128(0xC1));
    }

    #[test]
    fn karatsuba_correctness() {
        // Let's check using Block128 as an example
        // Let A = X (hi=1, lo=0)
        // Let B = X (hi=1, lo=0)
        // A * B = X^2
        // According to the rule:
        // X^2 = X + tau
        // Where tau for Block64 = 0x2000_0000_0000_0000.
        // So the result should be:
        // hi=1 (X), lo=0x20 (tau)

        // Construct X manually
        let x = Block128::new(Block64::ZERO, Block64::ONE);
        let squared = x * x;

        // Verify result via splitting
        let (res_lo, res_hi) = squared.split();

        assert_eq!(res_hi, Block64::ONE, "X^2 should contain X component");
        assert_eq!(
            res_lo,
            Block64(0x2000_0000_0000_0000),
            "X^2 should contain tau component (0x2000_0000_0000_0000)"
        );
    }

    #[test]
    fn security_zeroize() {
        // Setup sensitive data
        let mut secret_val = Block128::from(0xDEAD_BEEF_CAFE_BABE_u128);
        assert_ne!(secret_val, Block128::ZERO);

        // Nuke it
        secret_val.zeroize();

        // Verify absolute zero
        assert_eq!(secret_val, Block128::ZERO, "Memory was not wiped!");

        // Check internal bytes just to be sure
        assert_eq!(secret_val.0, 0u128, "Underlying memory leak detected");
    }

    #[test]
    fn invert_zero() {
        // Ensure strictly that 0 cannot be inverted.
        assert_eq!(
            Block128::ZERO.invert(),
            Block128::ZERO,
            "invert(0) must return 0"
        );
    }

    #[test]
    fn inversion_random() {
        let mut rng = rng();
        for _i in 0..1000 {
            let val = Block128(rng.random());

            if val != Block128::ZERO {
                let inv = val.invert();
                let identity = val * inv;

                assert_eq!(
                    identity,
                    Block128::ONE,
                    "Inversion identity failed: a * a^-1 != 1"
                );
            }
        }
    }

    #[test]
    fn tower_embedding() {
        let mut rng = rng();
        for _ in 0..100 {
            let a = Block64(rng.random());
            let b = Block64(rng.random());

            // 1. Structure check: Lifting Block64 -> Block128
            let a_lifted: Block128 = a.into();
            let (lo, hi) = a_lifted.split();

            assert_eq!(lo, a, "Embedding structure failed: low part mismatch");
            assert_eq!(
                hi,
                Block64::ZERO,
                "Embedding structure failed: high part must be zero"
            );

            // 2. Addition Homomorphism
            let sum_sub = a + b;
            let sum_lifted: Block128 = sum_sub.into();
            let sum_in_super = Block128::from(a) + Block128::from(b);

            assert_eq!(sum_lifted, sum_in_super, "Homomorphism failed: add");

            // 3. Multiplication Homomorphism
            // If I multiply two small numbers inside the big field,
            // the result must be the same as multiplying them in the small field
            // and then converting.
            let prod_sub = a * b;
            let prod_lifted: Block128 = prod_sub.into();
            let prod_in_super = Block128::from(a) * Block128::from(b);

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
            let val = Block128(rng.random::<u128>());
            assert_eq!(val.to_hardware().to_tower(), val);
        }
    }

    #[test]
    fn flat_mul_homomorphism() {
        let mut rng = rng();
        for _ in 0..1000 {
            let a = Block128(rng.random());
            let b = Block128(rng.random());

            let expected_flat = (a * b).to_hardware();
            let actual_flat = a.to_hardware() * b.to_hardware();

            assert_eq!(
                actual_flat, expected_flat,
                "Block128 flat multiplication mismatch: (a*b)^H != a^H * b^H"
            );
        }
    }

    #[test]
    fn packed_consistency() {
        let mut rng = rng();
        for _ in 0..100 {
            let mut a_vals = [Block128::ZERO; 4];
            let mut b_vals = [Block128::ZERO; 4];

            for i in 0..4 {
                a_vals[i] = Block128(rng.random::<u128>());
                b_vals[i] = Block128(rng.random::<u128>());
            }

            let a_flat_vals = a_vals.map(|x| x.to_hardware());
            let b_flat_vals = b_vals.map(|x| x.to_hardware());
            let a_packed = Flat::<Block128>::pack(&a_flat_vals);
            let b_packed = Flat::<Block128>::pack(&b_flat_vals);

            // 1. Test SIMD Add (Check 512-bit / 4-register XOR)
            let add_res = Block128::add_hardware_packed(a_packed, b_packed);

            let mut add_out = [Block128::ZERO.to_hardware(); 4];
            Flat::<Block128>::unpack(add_res, &mut add_out);

            for i in 0..4 {
                assert_eq!(
                    add_out[i],
                    (a_vals[i] + b_vals[i]).to_hardware(),
                    "Block128 SIMD add mismatch at index {}",
                    i
                );
            }

            // 2. Test SIMD Mul (Flat basis)
            let mul_res = Block128::mul_hardware_packed(a_packed, b_packed);

            let mut mul_out = [Block128::ZERO.to_hardware(); 4];
            Flat::<Block128>::unpack(mul_res, &mut mul_out);

            for i in 0..4 {
                let expected_flat = (a_vals[i] * b_vals[i]).to_hardware();
                assert_eq!(
                    mul_out[i], expected_flat,
                    "Block128 SIMD mul mismatch at index {}",
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
        let mut data = [Block128::ZERO; PACKED_WIDTH_128];
        for v in data.iter_mut() {
            *v = Block128(rng.random());
        }

        let packed = Block128::pack(&data);
        let mut unpacked = [Block128::ZERO; PACKED_WIDTH_128];
        Block128::unpack(packed, &mut unpacked);
        assert_eq!(data, unpacked);
    }

    #[test]
    fn packed_add_consistency() {
        let mut rng = rng();
        let mut a_vals = [Block128::ZERO; PACKED_WIDTH_128];
        let mut b_vals = [Block128::ZERO; PACKED_WIDTH_128];

        for i in 0..PACKED_WIDTH_128 {
            a_vals[i] = Block128(rng.random());
            b_vals[i] = Block128(rng.random());
        }

        let res_packed = Block128::pack(&a_vals) + Block128::pack(&b_vals);
        let mut res_unpacked = [Block128::ZERO; PACKED_WIDTH_128];
        Block128::unpack(res_packed, &mut res_unpacked);

        for i in 0..PACKED_WIDTH_128 {
            assert_eq!(res_unpacked[i], a_vals[i] + b_vals[i]);
        }
    }

    #[test]
    fn packed_mul_consistency() {
        let mut rng = rng();

        for _ in 0..1000 {
            // Check 1000 random cases.
            // Generate random inputs
            let mut a_arr = [Block128::ZERO; PACKED_WIDTH_128];
            let mut b_arr = [Block128::ZERO; PACKED_WIDTH_128];

            for i in 0..PACKED_WIDTH_128 {
                // Generate random u128
                let val_a: u128 = rng.random();
                let val_b: u128 = rng.random();
                a_arr[i] = Block128(val_a);
                b_arr[i] = Block128(val_b);
            }

            let a_packed = PackedBlock128(a_arr);
            let b_packed = PackedBlock128(b_arr);

            // Perform SIMD multiplication
            let c_packed = a_packed * b_packed;

            // Verify against Scalar multiplication
            let mut c_expected = [Block128::ZERO; PACKED_WIDTH_128];
            for i in 0..PACKED_WIDTH_128 {
                c_expected[i] = a_arr[i] * b_arr[i];
            }

            assert_eq!(c_packed.0, c_expected, "SIMD multiplication mismatch!");
        }
    }

    // ==================================
    // CT LIFTING BASIS
    // ==================================

    #[inline(always)]
    fn promote_block8_tables(val: Block8) -> Block128 {
        // Current (table) lifting: flat/hardware byte -> tower byte -> Block128 flat.
        let idx_flat = val.0 as usize;
        let tower_byte = unsafe { *constants::FLAT_TO_TOWER_8.get_unchecked(idx_flat) };
        let idx_tower = tower_byte as usize;

        Block128(unsafe { *constants::TOWER_TO_FLAT_128.get_unchecked(idx_tower) })
    }

    #[inline(always)]
    fn promote_block16_tables(val: Block16) -> Block128 {
        let v_flat = val.0;

        let mut v_tower = 0u16;
        for i in 0..2 {
            let byte = ((v_flat >> (i * 8)) & 0xFF) as usize;
            let idx = (i * 256) + byte;
            v_tower ^= unsafe { *constants::FLAT_TO_TOWER_16.get_unchecked(idx) };
        }

        let mut res = 0u128;
        for i in 0..2 {
            let byte = ((v_tower >> (i * 8)) & 0xFF) as usize;
            let idx = (i * 256) + byte;
            res ^= unsafe { *constants::TOWER_TO_FLAT_128.get_unchecked(idx) };
        }

        Block128(res)
    }

    #[inline(always)]
    fn promote_block32_tables(val: Block32) -> Block128 {
        let v_flat = val.0;

        let mut v_tower = 0u32;
        for i in 0..4 {
            let byte = ((v_flat >> (i * 8)) & 0xFF) as usize;
            let idx = (i * 256) + byte;
            v_tower ^= unsafe { *constants::FLAT_TO_TOWER_32.get_unchecked(idx) };
        }

        let mut res = 0u128;
        for i in 0..4 {
            let byte = ((v_tower >> (i * 8)) & 0xFF) as usize;
            let idx = (i * 256) + byte;
            res ^= unsafe { *constants::TOWER_TO_FLAT_128.get_unchecked(idx) };
        }

        Block128(res)
    }

    #[inline(always)]
    fn promote_block64_tables(val: Block64) -> Block128 {
        let v_flat = val.0;

        let mut v_tower = 0u64;
        for i in 0..8 {
            let byte = ((v_flat >> (i * 8)) & 0xFF) as usize;
            let idx = (i * 256) + byte;
            v_tower ^= unsafe { *constants::FLAT_TO_TOWER_64.get_unchecked(idx) };
        }

        let mut res = 0u128;
        for i in 0..8 {
            let byte = ((v_tower >> (i * 8)) & 0xFF) as usize;
            let idx = (i * 256) + byte;
            res ^= unsafe { *constants::TOWER_TO_FLAT_128.get_unchecked(idx) };
        }

        Block128(res)
    }

    #[test]
    fn lift_from_partial_hardware_matches_tables_block8_exhaustive() {
        for x in 0u16..=u8::MAX as u16 {
            let v = Block8(x as u8);
            let got = Block128::promote_flat(Flat::from_raw(v)).into_raw();
            let expected = promote_block8_tables(v);

            assert_eq!(got, expected);
        }
    }

    #[test]
    fn lift_from_partial_hardware_matches_tables_block16_exhaustive() {
        for x in 0..=u16::MAX {
            let v = Block16(x);
            let got = Block128::promote_flat(Flat::from_raw(v)).into_raw();
            let expected = promote_block16_tables(v);

            assert_eq!(got, expected);
        }
    }

    #[test]
    fn lift_from_partial_hardware_matches_tables_block32_random() {
        let mut rng = rng();
        for _ in 0..10_000 {
            let v = Block32(rng.random::<u32>());
            let got = Block128::promote_flat(Flat::from_raw(v)).into_raw();
            let expected = promote_block32_tables(v);

            assert_eq!(got, expected);
        }
    }

    #[test]
    fn lift_from_partial_hardware_matches_tables_block64_random() {
        let mut rng = rng();
        for _ in 0..10_000 {
            let v = Block64(rng.random::<u64>());
            let got = Block128::promote_flat(Flat::from_raw(v)).into_raw();
            let expected = promote_block64_tables(v);

            assert_eq!(got, expected);
        }
    }

    proptest! {
        #[test]
        fn parity_masks_match_from_hardware(x_flat in any::<u128>()) {
            let tower = Block128::from_hardware(Flat::from_raw(Block128(x_flat))).0;

            for k in 0..128 {
                let bit = ((tower >> k) & 1) as u8;
                let via_api = Flat::from_raw(Block128(x_flat)).tower_bit(k);

                prop_assert_eq!(
                    via_api, bit,
                    "Block128 tower_bit_from_hardware mismatch at x_flat={:#034x}, bit_idx={}",
                    x_flat, k
                );
            }
        }
    }
}
