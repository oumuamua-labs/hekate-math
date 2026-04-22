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

//! BLOCK 256 (GF(2^256))
use crate::{Bit, Block8, Block16, Block32, Block64, Block128};
use crate::{
    CanonicalDeserialize, CanonicalSerialize, Flat, FlatPromote, HardwareField, PackableField,
    PackedFlat, TowerField,
};
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

// Flat<Block256> = Flat<Block128>[y] / (y² + y + τ_flat).
// τ_flat = to_hardware(Block128::EXTENSION_TAU).
const TAU_FLAT: u128 = 0x66340c45203fe3685d08f8c248334a81;

#[derive(Copy, Clone, Default, Debug, Eq, PartialEq, Serialize, Deserialize, Zeroize)]
#[repr(C, align(32))]
pub struct Block256(pub [u128; 2]); // [lo, hi]

impl Block256 {
    const TAU: Self = Block256([0, 0x2000_0000_0000_0000_0000_0000_0000_0000]);

    pub fn new(lo: Block128, hi: Block128) -> Self {
        Self([lo.0, hi.0])
    }

    #[inline(always)]
    pub fn split(self) -> (Block128, Block128) {
        (Block128(self.0[0]), Block128(self.0[1]))
    }
}

impl TowerField for Block256 {
    const BITS: usize = 256;
    const ZERO: Self = Block256([0, 0]);
    const ONE: Self = Block256([1, 0]);

    const EXTENSION_TAU: Self = Self::TAU;

    fn invert(&self) -> Self {
        let (l, h) = self.split();
        let h2 = h * h;
        let l2 = l * l;
        let hl = h * l;
        let norm = (h2 * Block128::EXTENSION_TAU) + hl + l2;

        let norm_inv = norm.invert();
        let res_hi = h * norm_inv;
        let res_lo = (h + l) * norm_inv;

        Self::new(res_lo, res_hi)
    }

    fn from_uniform_bytes(bytes: &[u8; 32]) -> Self {
        let mut lo_buf = [0u8; 16];
        let mut hi_buf = [0u8; 16];

        lo_buf.copy_from_slice(&bytes[0..16]);
        hi_buf.copy_from_slice(&bytes[16..32]);

        Self([u128::from_le_bytes(lo_buf), u128::from_le_bytes(hi_buf)])
    }
}

impl Add for Block256 {
    type Output = Self;

    fn add(self, rhs: Self) -> Self {
        Self([self.0[0] ^ rhs.0[0], self.0[1] ^ rhs.0[1]])
    }
}

impl Sub for Block256 {
    type Output = Self;

    fn sub(self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

impl Mul for Block256 {
    type Output = Self;

    fn mul(self, rhs: Self) -> Self {
        let (a0, a1) = self.split();
        let (b0, b1) = rhs.split();

        let v0 = a0 * b0;
        let v1 = a1 * b1;
        let v_sum = (a0 + a1) * (b0 + b1);

        let c_hi = v0 + v_sum;
        let c_lo = v0 + (v1 * Block128::EXTENSION_TAU);

        Self::new(c_lo, c_hi)
    }
}

impl AddAssign for Block256 {
    fn add_assign(&mut self, rhs: Self) {
        self.0[0] ^= rhs.0[0];
        self.0[1] ^= rhs.0[1];
    }
}

impl SubAssign for Block256 {
    fn sub_assign(&mut self, rhs: Self) {
        self.0[0] ^= rhs.0[0];
        self.0[1] ^= rhs.0[1];
    }
}

impl MulAssign for Block256 {
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl CanonicalSerialize for Block256 {
    fn serialized_size(&self) -> usize {
        32
    }

    fn serialize(&self, writer: &mut [u8]) -> Result<(), ()> {
        if writer.len() < 32 {
            return Err(());
        }

        writer[0..16].copy_from_slice(&self.0[0].to_le_bytes());
        writer[16..32].copy_from_slice(&self.0[1].to_le_bytes());

        Ok(())
    }
}

impl CanonicalDeserialize for Block256 {
    fn deserialize(bytes: &[u8]) -> Result<Self, ()> {
        if bytes.len() < 32 {
            return Err(());
        }

        let mut lo_buf = [0u8; 16];
        let mut hi_buf = [0u8; 16];

        lo_buf.copy_from_slice(&bytes[0..16]);
        hi_buf.copy_from_slice(&bytes[16..32]);

        Ok(Self([
            u128::from_le_bytes(lo_buf),
            u128::from_le_bytes(hi_buf),
        ]))
    }
}

impl From<u8> for Block256 {
    fn from(val: u8) -> Self {
        Self([val as u128, 0])
    }
}

impl From<u32> for Block256 {
    #[inline]
    fn from(val: u32) -> Self {
        Self([val as u128, 0])
    }
}

impl From<u64> for Block256 {
    #[inline]
    fn from(val: u64) -> Self {
        Self([val as u128, 0])
    }
}

impl From<u128> for Block256 {
    #[inline]
    fn from(val: u128) -> Self {
        Self([val, 0])
    }
}

impl From<Bit> for Block256 {
    #[inline(always)]
    fn from(val: Bit) -> Self {
        Self([val.0 as u128, 0])
    }
}

impl From<Block8> for Block256 {
    #[inline(always)]
    fn from(val: Block8) -> Self {
        Self([val.0 as u128, 0])
    }
}

impl From<Block16> for Block256 {
    #[inline(always)]
    fn from(val: Block16) -> Self {
        Self([val.0 as u128, 0])
    }
}

impl From<Block32> for Block256 {
    #[inline(always)]
    fn from(val: Block32) -> Self {
        Self([val.0 as u128, 0])
    }
}

impl From<Block64> for Block256 {
    #[inline(always)]
    fn from(val: Block64) -> Self {
        Self([val.0 as u128, 0])
    }
}

impl From<Block128> for Block256 {
    #[inline(always)]
    fn from(val: Block128) -> Self {
        Self([val.0, 0])
    }
}

// ===================================
// PACKED BLOCK 256 (Width = 2)
// ===================================

pub const PACKED_WIDTH_256: usize = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
#[repr(C, align(64))]
pub struct PackedBlock256(pub [Block256; PACKED_WIDTH_256]);

impl PackedBlock256 {
    #[inline(always)]
    pub fn zero() -> Self {
        Self([Block256::ZERO; PACKED_WIDTH_256])
    }

    #[inline(always)]
    pub fn broadcast(val: Block256) -> Self {
        Self([val; PACKED_WIDTH_256])
    }
}

impl PackableField for Block256 {
    type Packed = PackedBlock256;

    const WIDTH: usize = PACKED_WIDTH_256;

    #[inline(always)]
    fn pack(chunk: &[Self]) -> Self::Packed {
        assert!(
            chunk.len() >= PACKED_WIDTH_256,
            "PackableField::pack: input slice too short",
        );

        let mut arr = [Self::ZERO; PACKED_WIDTH_256];
        arr.copy_from_slice(&chunk[..PACKED_WIDTH_256]);

        PackedBlock256(arr)
    }

    #[inline(always)]
    fn unpack(packed: Self::Packed, output: &mut [Self]) {
        assert!(
            output.len() >= PACKED_WIDTH_256,
            "PackableField::unpack: output slice too short",
        );

        output[..PACKED_WIDTH_256].copy_from_slice(&packed.0);
    }
}

impl Add for PackedBlock256 {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self {
        let mut res = [Block256::ZERO; PACKED_WIDTH_256];
        for ((out, l), r) in res.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            *out = *l + *r;
        }

        Self(res)
    }
}

impl AddAssign for PackedBlock256 {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        for (l, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *l += *r;
        }
    }
}

impl Sub for PackedBlock256 {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self {
        self.add(rhs)
    }
}

impl SubAssign for PackedBlock256 {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        self.add_assign(rhs);
    }
}

impl Mul for PackedBlock256 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self {
        let mut res = [Block256::ZERO; PACKED_WIDTH_256];
        for ((out, l), r) in res.iter_mut().zip(self.0.iter()).zip(rhs.0.iter()) {
            *out = *l * *r;
        }

        Self(res)
    }
}

impl MulAssign for PackedBlock256 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        for (l, r) in self.0.iter_mut().zip(rhs.0.iter()) {
            *l *= *r;
        }
    }
}

impl Mul<Block256> for PackedBlock256 {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Block256) -> Self {
        let mut res = [Block256::ZERO; PACKED_WIDTH_256];
        for (out, v) in res.iter_mut().zip(self.0.iter()) {
            *out = *v * rhs;
        }

        Self(res)
    }
}

impl MulAssign<Block256> for PackedBlock256 {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Block256) {
        for v in self.0.iter_mut() {
            *v *= rhs;
        }
    }
}

impl HardwareField for Block256 {
    #[inline(always)]
    fn to_hardware(self) -> Flat<Self> {
        let (lo, hi) = self.split();
        let flat_lo = lo.to_hardware().into_raw().0;
        let flat_hi = hi.to_hardware().into_raw().0;

        Flat::from_raw(Block256([flat_lo, flat_hi]))
    }

    #[inline(always)]
    fn from_hardware(value: Flat<Self>) -> Self {
        let raw = value.into_raw();
        let lo = Block128::from_hardware(Flat::from_raw(Block128(raw.0[0])));
        let hi = Block128::from_hardware(Flat::from_raw(Block128(raw.0[1])));

        Self::new(lo, hi)
    }

    #[inline(always)]
    fn add_hardware(lhs: Flat<Self>, rhs: Flat<Self>) -> Flat<Self> {
        let l = lhs.into_raw();
        let r = rhs.into_raw();

        Flat::from_raw(Block256([l.0[0] ^ r.0[0], l.0[1] ^ r.0[1]]))
    }

    #[inline(always)]
    fn add_hardware_packed(lhs: PackedFlat<Self>, rhs: PackedFlat<Self>) -> PackedFlat<Self> {
        PackedFlat::from_raw(lhs.into_raw() + rhs.into_raw())
    }

    #[inline(always)]
    fn mul_hardware(lhs: Flat<Self>, rhs: Flat<Self>) -> Flat<Self> {
        let a_lo = Flat::from_raw(Block128(lhs.into_raw().0[0]));
        let a_hi = Flat::from_raw(Block128(lhs.into_raw().0[1]));
        let b_lo = Flat::from_raw(Block128(rhs.into_raw().0[0]));
        let b_hi = Flat::from_raw(Block128(rhs.into_raw().0[1]));

        let tau = Flat::from_raw(Block128(TAU_FLAT));

        let v0 = Block128::mul_hardware(a_lo, b_lo);
        let v1 = Block128::mul_hardware(a_hi, b_hi);

        let a_sum = Block128::add_hardware(a_lo, a_hi);
        let b_sum = Block128::add_hardware(b_lo, b_hi);
        let v_sum = Block128::mul_hardware(a_sum, b_sum);

        let c_hi = Block128::add_hardware(v0, v_sum);

        let v1_tau = Block128::mul_hardware(v1, tau);
        let c_lo = Block128::add_hardware(v0, v1_tau);

        Flat::from_raw(Block256([c_lo.into_raw().0, c_hi.into_raw().0]))
    }

    #[inline(always)]
    fn mul_hardware_packed(lhs: PackedFlat<Self>, rhs: PackedFlat<Self>) -> PackedFlat<Self> {
        let lhs = lhs.into_raw().0;
        let rhs = rhs.into_raw().0;

        let mut res = [Block256::ZERO; PACKED_WIDTH_256];
        for i in 0..PACKED_WIDTH_256 {
            res[i] = Self::mul_hardware(Flat::from_raw(lhs[i]), Flat::from_raw(rhs[i])).into_raw();
        }

        PackedFlat::from_raw(PackedBlock256(res))
    }

    #[inline(always)]
    fn mul_hardware_scalar_packed(lhs: PackedFlat<Self>, rhs: Flat<Self>) -> PackedFlat<Self> {
        let broadcasted = PackedBlock256::broadcast(rhs.into_raw());
        Self::mul_hardware_packed(lhs, PackedFlat::from_raw(broadcasted))
    }

    #[inline(always)]
    fn tower_bit_from_hardware(value: Flat<Self>, bit_idx: usize) -> u8 {
        if bit_idx < 128 {
            Block128::tower_bit_from_hardware(
                Flat::from_raw(Block128(value.into_raw().0[0])),
                bit_idx,
            )
        } else {
            Block128::tower_bit_from_hardware(
                Flat::from_raw(Block128(value.into_raw().0[1])),
                bit_idx - 128,
            )
        }
    }
}

const PROMOTE_CHUNK: usize = 64;

impl FlatPromote<Block8> for Block256 {
    #[inline(always)]
    fn promote_flat(val: Flat<Block8>) -> Flat<Self> {
        let promoted = Block128::promote_flat(val);
        Flat::from_raw(Block256([promoted.into_raw().0, 0]))
    }

    fn promote_flat_batch(input: &[Flat<Block8>], output: &mut [Flat<Self>]) {
        promote_chunked(input, output);
    }
}

impl FlatPromote<Block16> for Block256 {
    #[inline(always)]
    fn promote_flat(val: Flat<Block16>) -> Flat<Self> {
        let promoted = Block128::promote_flat(val);
        Flat::from_raw(Block256([promoted.into_raw().0, 0]))
    }

    fn promote_flat_batch(input: &[Flat<Block16>], output: &mut [Flat<Self>]) {
        promote_chunked(input, output);
    }
}

impl FlatPromote<Block32> for Block256 {
    #[inline(always)]
    fn promote_flat(val: Flat<Block32>) -> Flat<Self> {
        let promoted = Block128::promote_flat(val);
        Flat::from_raw(Block256([promoted.into_raw().0, 0]))
    }

    fn promote_flat_batch(input: &[Flat<Block32>], output: &mut [Flat<Self>]) {
        promote_chunked(input, output);
    }
}

impl FlatPromote<Block64> for Block256 {
    #[inline(always)]
    fn promote_flat(val: Flat<Block64>) -> Flat<Self> {
        let promoted = Block128::promote_flat(val);
        Flat::from_raw(Block256([promoted.into_raw().0, 0]))
    }

    fn promote_flat_batch(input: &[Flat<Block64>], output: &mut [Flat<Self>]) {
        promote_chunked(input, output);
    }
}

impl FlatPromote<Block128> for Block256 {
    #[inline(always)]
    fn promote_flat(val: Flat<Block128>) -> Flat<Self> {
        Flat::from_raw(Block256([val.into_raw().0, 0]))
    }

    fn promote_flat_batch(input: &[Flat<Block128>], output: &mut [Flat<Self>]) {
        let n = input.len().min(output.len());
        for i in 0..n {
            output[i] = Flat::from_raw(Block256([input[i].into_raw().0, 0]));
        }
    }
}

#[inline(always)]
fn promote_chunked<FromF>(input: &[Flat<FromF>], output: &mut [Flat<Block256>])
where
    FromF: HardwareField,
    Block128: FlatPromote<FromF>,
{
    let n = input.len().min(output.len());

    let mut scratch = [Flat::from_raw(Block128::ZERO); PROMOTE_CHUNK];
    let mut i = 0;

    while i < n {
        let len = (n - i).min(PROMOTE_CHUNK);
        Block128::promote_flat_batch(&input[i..i + len], &mut scratch[..len]);

        for j in 0..len {
            output[i + j] = Flat::from_raw(Block256([scratch[j].into_raw().0, 0]));
        }

        i += len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{RngExt, rng};

    #[test]
    fn tau_flat_matches_derived() {
        let derived = Block128::EXTENSION_TAU.to_hardware().into_raw().0;
        assert_eq!(
            TAU_FLAT, derived,
            "TAU_FLAT drifted from Block128::EXTENSION_TAU.to_hardware()",
        );
    }

    // ==================================
    // BASIC
    // ==================================

    #[test]
    fn tower_constants() {
        // Check that tau is propagated correctly
        // For Block256, tau must be (0, EXTENSION_TAU) from Block128.
        let tau256 = Block256::EXTENSION_TAU;
        let (lo256, hi256) = tau256.split();
        assert_eq!(lo256, Block128::ZERO);
        assert_eq!(hi256, Block128::EXTENSION_TAU);
    }

    #[test]
    fn add_truth() {
        let zero = Block256::ZERO;
        let one = Block256::ONE;

        assert_eq!(zero + zero, zero);
        assert_eq!(zero + one, one);
        assert_eq!(one + zero, one);
        assert_eq!(one + one, zero);
    }

    #[test]
    fn mul_truth() {
        let zero = Block256::ZERO;
        let one = Block256::ONE;

        assert_eq!(zero * zero, zero);
        assert_eq!(zero * one, zero);
        assert_eq!(one * one, one);
    }

    #[test]
    fn add() {
        // 5 ^ 3 = 6
        // 101 ^ 011 = 110
        assert_eq!(Block256([5, 0]) + Block256([3, 0]), Block256([6, 0]));
    }

    #[test]
    fn mul_simple() {
        // x^1 * x^1 = x^2 (2 * 2 = 4) inside the Block8 subfield
        assert_eq!(
            Block256::from(2u32) * Block256::from(2u32),
            Block256::from(4u32)
        );
    }

    #[test]
    fn mul_overflow() {
        // AES reduction: 0x57 * 0x83 = 0xC1 inside the Block8 subfield
        assert_eq!(
            Block256::from(0x57u32) * Block256::from(0x83u32),
            Block256::from(0xC1u32)
        );
    }

    #[test]
    fn karatsuba_correctness() {
        // Y = (hi=ONE, lo=ZERO). Y^2 = Y + tau_256.
        // So the result must be:
        // hi = Block128::ONE (the Y component),
        // lo = Block128::EXTENSION_TAU (the tau component).
        let y = Block256::new(Block128::ZERO, Block128::ONE);
        let squared = y * y;

        let (res_lo, res_hi) = squared.split();

        assert_eq!(res_hi, Block128::ONE, "Y^2 should contain Y component");
        assert_eq!(
            res_lo,
            Block128::EXTENSION_TAU,
            "Y^2 should contain tau_256 component"
        );
    }

    #[test]
    fn security_zeroize() {
        let mut secret_val = Block256([0xDEAD_BEEF_CAFE_BABE_u128, 0xFEED_FACE_BAAD_F00D_u128]);
        assert_ne!(secret_val, Block256::ZERO);

        secret_val.zeroize();

        assert_eq!(secret_val, Block256::ZERO, "Memory was not wiped!");
        assert_eq!(
            secret_val.0,
            [0u128, 0u128],
            "Underlying memory leak detected"
        );
    }

    #[test]
    fn invert_zero() {
        assert_eq!(
            Block256::ZERO.invert(),
            Block256::ZERO,
            "invert(0) must return 0"
        );
    }

    #[test]
    fn inversion_random() {
        let mut rng = rng();
        for _ in 0..1000 {
            let val = Block256([rng.random(), rng.random()]);

            if val != Block256::ZERO {
                let inv = val.invert();
                let identity = val * inv;

                assert_eq!(
                    identity,
                    Block256::ONE,
                    "Inversion identity failed: a * a^-1 != 1"
                );
            }
        }
    }

    #[test]
    fn tower_embedding() {
        let mut rng = rng();
        for _ in 0..100 {
            let a = Block128(rng.random());
            let b = Block128(rng.random());

            // 1. Structure:
            // Block128 -> Block256
            let a_lifted: Block256 = a.into();
            let (lo, hi) = a_lifted.split();

            assert_eq!(lo, a, "Embedding structure failed: low part mismatch");
            assert_eq!(
                hi,
                Block128::ZERO,
                "Embedding structure failed: high part must be zero"
            );

            // 2. Addition Homomorphism
            let sum_sub = a + b;
            let sum_lifted: Block256 = sum_sub.into();
            let sum_in_super = Block256::from(a) + Block256::from(b);

            assert_eq!(sum_lifted, sum_in_super, "Homomorphism failed: add");

            // 3. Multiplication Homomorphism
            let prod_sub = a * b;
            let prod_lifted: Block256 = prod_sub.into();
            let prod_in_super = Block256::from(a) * Block256::from(b);

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
            let val = Block256([rng.random::<u128>(), rng.random::<u128>()]);
            assert_eq!(val.to_hardware().to_tower(), val);
        }
    }

    #[test]
    fn flat_mul_homomorphism() {
        let mut rng = rng();
        for _ in 0..1000 {
            let a = Block256([rng.random(), rng.random()]);
            let b = Block256([rng.random(), rng.random()]);

            let expected_flat = (a * b).to_hardware();
            let actual_flat = a.to_hardware() * b.to_hardware();

            assert_eq!(
                actual_flat, expected_flat,
                "Block256 flat multiplication mismatch: (a*b)^H != a^H * b^H"
            );
        }
    }

    #[test]
    fn packed_consistency() {
        let mut rng = rng();
        for _ in 0..100 {
            let mut a_vals = [Block256::ZERO; PACKED_WIDTH_256];
            let mut b_vals = [Block256::ZERO; PACKED_WIDTH_256];

            for i in 0..PACKED_WIDTH_256 {
                a_vals[i] = Block256([rng.random::<u128>(), rng.random::<u128>()]);
                b_vals[i] = Block256([rng.random::<u128>(), rng.random::<u128>()]);
            }

            let a_flat_vals = a_vals.map(|x| x.to_hardware());
            let b_flat_vals = b_vals.map(|x| x.to_hardware());
            let a_packed = Flat::<Block256>::pack(&a_flat_vals);
            let b_packed = Flat::<Block256>::pack(&b_flat_vals);

            let add_res = Block256::add_hardware_packed(a_packed, b_packed);

            let mut add_out = [Block256::ZERO.to_hardware(); PACKED_WIDTH_256];
            Flat::<Block256>::unpack(add_res, &mut add_out);

            for i in 0..PACKED_WIDTH_256 {
                assert_eq!(
                    add_out[i],
                    (a_vals[i] + b_vals[i]).to_hardware(),
                    "Block256 SIMD add mismatch at index {}",
                    i
                );
            }

            let mul_res = Block256::mul_hardware_packed(a_packed, b_packed);

            let mut mul_out = [Block256::ZERO.to_hardware(); PACKED_WIDTH_256];
            Flat::<Block256>::unpack(mul_res, &mut mul_out);

            for i in 0..PACKED_WIDTH_256 {
                let expected_flat = (a_vals[i] * b_vals[i]).to_hardware();
                assert_eq!(
                    mul_out[i], expected_flat,
                    "Block256 SIMD mul mismatch at index {}",
                    i
                );
            }
        }
    }

    #[test]
    fn tower_bit_from_hardware_matches_tower() {
        let mut rng = rng();
        for _ in 0..64 {
            let val = Block256([rng.random::<u128>(), rng.random::<u128>()]);
            let flat = val.to_hardware();

            for bit in 0..Block256::BITS {
                let expected = if bit < 128 {
                    ((val.0[0] >> bit) & 1) as u8
                } else {
                    ((val.0[1] >> (bit - 128)) & 1) as u8
                };

                assert_eq!(
                    Block256::tower_bit_from_hardware(flat, bit),
                    expected,
                    "tower_bit mismatch at bit {}",
                    bit
                );
            }
        }
    }

    // ==================================
    // PROMOTE
    // ==================================

    #[test]
    fn promote_flat_batch_matches_scalar_block8() {
        let mut rng = rng();
        let input: Vec<Flat<Block8>> = (0..200)
            .map(|_| Block8(rng.random::<u8>()).to_hardware())
            .collect();

        let mut batch_out = vec![Flat::from_raw(Block256::ZERO); input.len()];
        <Block256 as FlatPromote<Block8>>::promote_flat_batch(&input, &mut batch_out);

        for i in 0..input.len() {
            let scalar = <Block256 as FlatPromote<Block8>>::promote_flat(input[i]);
            assert_eq!(
                batch_out[i], scalar,
                "Block8 batch/scalar mismatch at {}",
                i
            );
        }
    }

    #[test]
    fn promote_flat_batch_matches_scalar_block16() {
        let mut rng = rng();
        let input: Vec<Flat<Block16>> = (0..200)
            .map(|_| Block16(rng.random::<u16>()).to_hardware())
            .collect();

        let mut batch_out = vec![Flat::from_raw(Block256::ZERO); input.len()];
        <Block256 as FlatPromote<Block16>>::promote_flat_batch(&input, &mut batch_out);

        for i in 0..input.len() {
            let scalar = <Block256 as FlatPromote<Block16>>::promote_flat(input[i]);
            assert_eq!(
                batch_out[i], scalar,
                "Block16 batch/scalar mismatch at {}",
                i
            );
        }
    }

    #[test]
    fn promote_flat_batch_matches_scalar_block32() {
        let mut rng = rng();
        let input: Vec<Flat<Block32>> = (0..200)
            .map(|_| Block32(rng.random::<u32>()).to_hardware())
            .collect();

        let mut batch_out = vec![Flat::from_raw(Block256::ZERO); input.len()];
        <Block256 as FlatPromote<Block32>>::promote_flat_batch(&input, &mut batch_out);

        for i in 0..input.len() {
            let scalar = <Block256 as FlatPromote<Block32>>::promote_flat(input[i]);
            assert_eq!(
                batch_out[i], scalar,
                "Block32 batch/scalar mismatch at {}",
                i
            );
        }
    }

    #[test]
    fn promote_flat_batch_matches_scalar_block64() {
        let mut rng = rng();
        let input: Vec<Flat<Block64>> = (0..200)
            .map(|_| Block64(rng.random::<u64>()).to_hardware())
            .collect();

        let mut batch_out = vec![Flat::from_raw(Block256::ZERO); input.len()];
        <Block256 as FlatPromote<Block64>>::promote_flat_batch(&input, &mut batch_out);

        for i in 0..input.len() {
            let scalar = <Block256 as FlatPromote<Block64>>::promote_flat(input[i]);
            assert_eq!(
                batch_out[i], scalar,
                "Block64 batch/scalar mismatch at {}",
                i
            );
        }
    }

    #[test]
    fn promote_flat_batch_matches_scalar_block128() {
        let mut rng = rng();
        let input: Vec<Flat<Block128>> = (0..200)
            .map(|_| Block128(rng.random::<u128>()).to_hardware())
            .collect();

        let mut batch_out = vec![Flat::from_raw(Block256::ZERO); input.len()];
        <Block256 as FlatPromote<Block128>>::promote_flat_batch(&input, &mut batch_out);

        for i in 0..input.len() {
            let scalar = <Block256 as FlatPromote<Block128>>::promote_flat(input[i]);
            assert_eq!(
                batch_out[i], scalar,
                "Block128 batch/scalar mismatch at {}",
                i
            );
        }
    }

    #[test]
    fn promote_flat_batch_partial_slice() {
        let mut rng = rng();
        let input: Vec<Flat<Block8>> = (0..10)
            .map(|_| Block8(rng.random::<u8>()).to_hardware())
            .collect();

        let mut out_short = vec![Flat::from_raw(Block256::ZERO); 5];
        <Block256 as FlatPromote<Block8>>::promote_flat_batch(&input, &mut out_short);

        for i in 0..5 {
            let scalar = <Block256 as FlatPromote<Block8>>::promote_flat(input[i]);
            assert_eq!(out_short[i], scalar);
        }

        let short_input = &input[..3];

        let mut out_long = vec![Flat::from_raw(Block256::ZERO); 10];
        <Block256 as FlatPromote<Block8>>::promote_flat_batch(short_input, &mut out_long);

        for i in 0..3 {
            let scalar = <Block256 as FlatPromote<Block8>>::promote_flat(short_input[i]);
            assert_eq!(out_long[i], scalar);
        }

        for val in out_long.iter().skip(3) {
            assert_eq!(*val, Flat::from_raw(Block256::ZERO));
        }
    }

    #[test]
    fn promote_flat_batch_across_chunk_boundary() {
        let mut rng = rng();
        // Exercise lengths straddling PROMOTE_CHUNK.
        for &n in &[
            PROMOTE_CHUNK - 1,
            PROMOTE_CHUNK,
            PROMOTE_CHUNK + 1,
            PROMOTE_CHUNK * 2 + 3,
        ] {
            let input: Vec<Flat<Block8>> = (0..n)
                .map(|_| Block8(rng.random::<u8>()).to_hardware())
                .collect();

            let mut batch_out = vec![Flat::from_raw(Block256::ZERO); n];
            <Block256 as FlatPromote<Block8>>::promote_flat_batch(&input, &mut batch_out);

            for i in 0..n {
                let scalar = <Block256 as FlatPromote<Block8>>::promote_flat(input[i]);
                assert_eq!(batch_out[i], scalar, "n={}, idx={}", n, i);
            }
        }
    }
}
