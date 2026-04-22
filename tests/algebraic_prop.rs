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

use hekate_math::{
    Bit, Block8, Block16, Block32, Block64, Block128, Block256, Flat, FlatPromote, HardwareField,
    TowerField,
};
use proptest::prelude::*;

// Strategy:
// Generate any valid Bit (0 or 1)
fn any_bit() -> impl Strategy<Value = Bit> {
    (0u8..=1).prop_map(Bit::new)
}

// Strategy:
// Generate any Block8 from a random u8
fn any_block8() -> impl Strategy<Value = Block8> {
    any::<u8>().prop_map(Block8)
}

// Strategy:
// Generate any Block16 from a random u16
fn any_block16() -> impl Strategy<Value = Block16> {
    any::<u16>().prop_map(Block16)
}

// Strategy:
// Generate any Block64 from a random u64
fn any_block64() -> impl Strategy<Value = Block64> {
    any::<u64>().prop_map(Block64)
}

// Strategy:
// Generate any Block32 from a random u32
fn any_block32() -> impl Strategy<Value = Block32> {
    any::<u32>().prop_map(Block32)
}

// Strategy: Generate any Block128 from a random u128
fn any_block128() -> impl Strategy<Value = Block128> {
    any::<u128>().prop_map(Block128)
}

fn any_block256() -> impl Strategy<Value = Block256> {
    (any::<u128>(), any::<u128>()).prop_map(|(lo, hi)| Block256([lo, hi]))
}

proptest! {
    // ==================================
    // Bit
    // ==================================

    // 1. Associativity
    #[test]
    fn prop_bit_add_associativity(a in any_bit(), b in any_bit(), c in any_bit()) {
        // (a + b) + c == a + (b + c)
        prop_assert_eq!((a + b) + c, a + (b + c));
    }

    #[test]
    fn prop_bit_mul_associativity(a in any_bit(), b in any_bit(), c in any_bit()) {
        // (a * b) * c == a * (b * c)
        prop_assert_eq!((a * b) * c, a * (b * c));
    }

    // 2. Distributivity
    #[test]
    fn prop_bit_distributivity(a in any_bit(), b in any_bit(), c in any_bit()) {
        // a * (b + c) == a * b + a * c
        prop_assert_eq!(a * (b + c), a * b + a * c);
    }

    // 3. Identity
    #[test]
    fn prop_bit_add_identity(a in any_bit()) {
        // a + 0 == a
        prop_assert_eq!(a + Bit::ZERO, a);
        prop_assert_eq!(Bit::ZERO + a, a);
    }

    #[test]
    fn prop_bit_mul_identity(a in any_bit()) {
        // a * 1 == a
        prop_assert_eq!(a * Bit::ONE, a);
        prop_assert_eq!(Bit::ONE * a, a);
    }

    // 4. Inverse Properties (Field axioms)
    #[test]
    fn prop_bit_additive_inverse(a in any_bit()) {
        // a + (-a) == 0.
        // In GF(2^n), -a = a, so a + a == 0.
        prop_assert_eq!(a + a, Bit::ZERO);
    }

    // 5. Annihilation
     #[test]
    fn prop_bit_mul_annihilation(a in any_bit()) {
        // a * 0 == 0
        prop_assert_eq!(a * Bit::ZERO, Bit::ZERO);
        prop_assert_eq!(Bit::ZERO * a, Bit::ZERO);
    }

    // ==================================
    // Block8
    // ==================================

    // 1. Associativity
    #[test]
    fn prop_block8_add_associativity(a in any_block8(), b in any_block8(), c in any_block8()) {
        // (a + b) + c == a + (b + c)
        prop_assert_eq!((a + b) + c, a + (b + c));
    }

    #[test]
    fn prop_block8_mul_associativity(a in any_block8(), b in any_block8(), c in any_block8()) {
        // (a * b) * c == a * (b * c)
        prop_assert_eq!((a * b) * c, a * (b * c));
    }

    // 2. Distributivity
    #[test]
    fn prop_block8_distributivity(a in any_block8(), b in any_block8(), c in any_block8()) {
        // a * (b + c) == a * b + a * c
        prop_assert_eq!(a * (b + c), a * b + a * c);
    }

    // 3. Identity
    #[test]
    fn prop_block8_add_identity(a in any_block8()) {
        // a + 0 == a
        prop_assert_eq!(a + Block8::ZERO, a);
        prop_assert_eq!(Block8::ZERO + a, a);
    }

    #[test]
    fn prop_block8_mul_identity(a in any_block8()) {
        // a * 1 == a
        prop_assert_eq!(a * Block8::ONE, a);
        prop_assert_eq!(Block8::ONE * a, a);
    }

    // 4. Additive Inverse (Characteristic 2)
    #[test]
    fn prop_block8_additive_inverse(a in any_block8()) {
        // a + a == 0
        prop_assert_eq!(a + a, Block8::ZERO);
    }

    // 5. Annihilation
    #[test]
    fn prop_block8_mul_annihilation(a in any_block8()) {
        // a * 0 == 0
        prop_assert_eq!(a * Block8::ZERO, Block8::ZERO);
        prop_assert_eq!(Block8::ZERO * a, Block8::ZERO);
    }

    // 6. Hardware Isomorphism Roundtrip
    #[test]
    fn prop_block8_hardware_iso_roundtrip(a in any_block8()) {
        // convert(to_hardware(a)) == a
        prop_assert_eq!(a.to_hardware().to_tower(), a);
    }

    // ==================================
    // Block16
    // ==================================

    // 1. Associativity
    #[test]
    fn prop_block16_add_associativity(a in any_block16(), b in any_block16(), c in any_block16()) {
        // (a + b) + c == a + (b + c)
        prop_assert_eq!((a + b) + c, a + (b + c));
    }

    #[test]
    fn prop_block16_mul_associativity(a in any_block16(), b in any_block16(), c in any_block16()) {
        // (a * b) * c == a * (b * c)
        prop_assert_eq!((a * b) * c, a * (b * c));
    }

    // 2. Distributivity
    #[test]
    fn prop_block16_distributivity(a in any_block16(), b in any_block16(), c in any_block16()) {
        // a * (b + c) == a * b + a * c
        prop_assert_eq!(a * (b + c), a * b + a * c);
    }

    // 3. Identity
    #[test]
    fn prop_block16_add_identity(a in any_block16()) {
        // a + 0 == a
        prop_assert_eq!(a + Block16::ZERO, a);
        prop_assert_eq!(Block16::ZERO + a, a);
    }

    #[test]
    fn prop_block16_mul_identity(a in any_block16()) {
        // a * 1 == a
        prop_assert_eq!(a * Block16::ONE, a);
        prop_assert_eq!(Block16::ONE * a, a);
    }

    // 4. Additive Inverse
    #[test]
    fn prop_block16_additive_inverse(a in any_block16()) {
        // a + a == 0
        prop_assert_eq!(a + a, Block16::ZERO);
    }

    // 5. Annihilation
    #[test]
    fn prop_block16_mul_annihilation(a in any_block16()) {
        // a * 0 == 0
        prop_assert_eq!(a * Block16::ZERO, Block16::ZERO);
        prop_assert_eq!(Block16::ZERO * a, Block16::ZERO);
    }

    // 6. Hardware Isomorphism Roundtrip
    #[test]
    fn prop_block16_hardware_iso_roundtrip(a in any_block16()) {
        // convert(to_hardware(a)) == a
        prop_assert_eq!(a.to_hardware().to_tower(), a);
    }

    // ==================================
    // Block32
    // ==================================

    // 1. Associativity
    #[test]
    fn prop_block32_add_associativity(a in any_block32(), b in any_block32(), c in any_block32()) {
        // (a + b) + c == a + (b + c)
        prop_assert_eq!((a + b) + c, a + (b + c));
    }

    #[test]
    fn prop_block32_mul_associativity(a in any_block32(), b in any_block32(), c in any_block32()) {
        // (a * b) * c == a * (b * c)
        prop_assert_eq!((a * b) * c, a * (b * c));
    }

    // 2. Distributivity
    #[test]
    fn prop_block32_distributivity(a in any_block32(), b in any_block32(), c in any_block32()) {
        // a * (b + c) == a * b + a * c
        prop_assert_eq!(a * (b + c), a * b + a * c);
    }

    // 3. Identity
    #[test]
    fn prop_block32_add_identity(a in any_block32()) {
        // a + 0 == a
        prop_assert_eq!(a + Block32::ZERO, a);
        prop_assert_eq!(Block32::ZERO + a, a);
    }

    #[test]
    fn prop_block32_mul_identity(a in any_block32()) {
        // a * 1 == a
        prop_assert_eq!(a * Block32::ONE, a);
        prop_assert_eq!(Block32::ONE * a, a);
    }

    // 4. Additive Inverse
    #[test]
    fn prop_block32_additive_inverse(a in any_block32()) {
        // a + a == 0
        prop_assert_eq!(a + a, Block32::ZERO);
    }

    // 5. Annihilation
    #[test]
    fn prop_block32_mul_annihilation(a in any_block32()) {
        // a * 0 == 0
        prop_assert_eq!(a * Block32::ZERO, Block32::ZERO);
        prop_assert_eq!(Block32::ZERO * a, Block32::ZERO);
    }

    // 6. Hardware Isomorphism Roundtrip
    #[test]
    fn prop_block32_hardware_iso_roundtrip(a in any_block32()) {
        // convert(to_hardware(a)) == a
        prop_assert_eq!(a.to_hardware().to_tower(), a);
    }

    // ==================================
    // Block64
    // ==================================

    // 1. Associativity
    #[test]
    fn prop_block64_add_associativity(a in any_block64(), b in any_block64(), c in any_block64()) {
        // (a + b) + c == a + (b + c)
        prop_assert_eq!((a + b) + c, a + (b + c));
    }

    #[test]
    fn prop_block64_mul_associativity(a in any_block64(), b in any_block64(), c in any_block64()) {
        // (a * b) * c == a * (b * c)
        prop_assert_eq!((a * b) * c, a * (b * c));
    }

    // 2. Distributivity
    #[test]
    fn prop_block64_distributivity(a in any_block64(), b in any_block64(), c in any_block64()) {
        // a * (b + c) == a * b + a * c
        prop_assert_eq!(a * (b + c), a * b + a * c);
    }

    // 3. Identity
    #[test]
    fn prop_block64_add_identity(a in any_block64()) {
        // a + 0 == a
        prop_assert_eq!(a + Block64::ZERO, a);
        prop_assert_eq!(Block64::ZERO + a, a);
    }

    #[test]
    fn prop_block64_mul_identity(a in any_block64()) {
        // a * 1 == a
        prop_assert_eq!(a * Block64::ONE, a);
        prop_assert_eq!(Block64::ONE * a, a);
    }

    // 4. Additive Inverse
    #[test]
    fn prop_block64_additive_inverse(a in any_block64()) {
        // a + a == 0
        prop_assert_eq!(a + a, Block64::ZERO);
    }

    // 5. Annihilation
    #[test]
    fn prop_block64_mul_annihilation(a in any_block64()) {
        // a * 0 == 0
        prop_assert_eq!(a * Block64::ZERO, Block64::ZERO);
        prop_assert_eq!(Block64::ZERO * a, Block64::ZERO);
    }

    // 6. Hardware Isomorphism Roundtrip
    #[test]
    fn prop_block64_hardware_iso_roundtrip(a in any_block64()) {
        // convert(to_hardware(a)) == a
        prop_assert_eq!(a.to_hardware().to_tower(), a);
    }

    // ==================================
    // Block128
    // ==================================

    // 1. Associativity
    #[test]
    fn prop_block128_add_associativity(a in any_block128(), b in any_block128(), c in any_block128()) {
        // (a + b) + c == a + (b + c)
        prop_assert_eq!((a + b) + c, a + (b + c));
    }

    #[test]
    fn prop_block128_mul_associativity(a in any_block128(), b in any_block128(), c in any_block128()) {
        // (a * b) * c == a * (b * c)
        prop_assert_eq!((a * b) * c, a * (b * c));
    }

    // 2. Distributivity
    #[test]
    fn prop_block128_distributivity(a in any_block128(), b in any_block128(), c in any_block128()) {
        // a * (b + c) == a * b + a * c
        prop_assert_eq!(a * (b + c), a * b + a * c);
    }

    // 3. Identity
    #[test]
    fn prop_block128_add_identity(a in any_block128()) {
        // a + 0 == a
        prop_assert_eq!(a + Block128::ZERO, a);
        prop_assert_eq!(Block128::ZERO + a, a);
    }

    #[test]
    fn prop_block128_mul_identity(a in any_block128()) {
        // a * 1 == a
        prop_assert_eq!(a * Block128::ONE, a);
        prop_assert_eq!(Block128::ONE * a, a);
    }

    // 4. Additive Inverse
    #[test]
    fn prop_block128_additive_inverse(a in any_block128()) {
        // a + a == 0
        prop_assert_eq!(a + a, Block128::ZERO);
    }

    // 5. Annihilation
    #[test]
    fn prop_block128_mul_annihilation(a in any_block128()) {
        // a * 0 == 0
        prop_assert_eq!(a * Block128::ZERO, Block128::ZERO);
        prop_assert_eq!(Block128::ZERO * a, Block128::ZERO);
    }

    // 6. Hardware Isomorphism Roundtrip
    #[test]
    fn prop_block128_hardware_iso_roundtrip(a in any_block128()) {
        // convert(to_hardware(a)) == a
        prop_assert_eq!(a.to_hardware().to_tower(), a);
    }

    // ==================================
    // Block256
    // ==================================

    #[test]
    fn prop_block256_add_associativity(a in any_block256(), b in any_block256(), c in any_block256()) {
        prop_assert_eq!((a + b) + c, a + (b + c));
    }

    #[test]
    fn prop_block256_mul_associativity(a in any_block256(), b in any_block256(), c in any_block256()) {
        prop_assert_eq!((a * b) * c, a * (b * c));
    }

    #[test]
    fn prop_block256_distributivity(a in any_block256(), b in any_block256(), c in any_block256()) {
        prop_assert_eq!(a * (b + c), a * b + a * c);
    }

    #[test]
    fn prop_block256_add_identity(a in any_block256()) {
        prop_assert_eq!(a + Block256::ZERO, a);
        prop_assert_eq!(Block256::ZERO + a, a);
    }

    #[test]
    fn prop_block256_mul_identity(a in any_block256()) {
        prop_assert_eq!(a * Block256::ONE, a);
        prop_assert_eq!(Block256::ONE * a, a);
    }

    #[test]
    fn prop_block256_additive_inverse(a in any_block256()) {
        prop_assert_eq!(a + a, Block256::ZERO);
    }

    #[test]
    fn prop_block256_mul_annihilation(a in any_block256()) {
        prop_assert_eq!(a * Block256::ZERO, Block256::ZERO);
        prop_assert_eq!(Block256::ZERO * a, Block256::ZERO);
    }

    #[test]
    fn prop_block256_commutativity(a in any_block256(), b in any_block256()) {
        prop_assert_eq!(a * b, b * a);
    }

    #[test]
    fn prop_block256_invert_roundtrip(a in any_block256()) {
        if a != Block256::ZERO {
            prop_assert_eq!(a * a.invert(), Block256::ONE);
        }
    }

    #[test]
    fn prop_block256_subfield_embedding_block128(a in any_block128(), b in any_block128()) {
        // Arithmetic in Block256 restricted
        // to embedded Block128 values must
        // agree with Block128 arithmetic.
        let a256 = Block256::from(a);
        let b256 = Block256::from(b);

        prop_assert_eq!((a256 + b256).split().0, a + b);
        prop_assert_eq!((a256 + b256).split().1, Block128::ZERO);

        prop_assert_eq!((a256 * b256).split().0, a * b);
        prop_assert_eq!((a256 * b256).split().1, Block128::ZERO);
    }

    #[test]
    fn prop_block256_hardware_iso_roundtrip(a in any_block256()) {
        prop_assert_eq!(a.to_hardware().to_tower(), a);
    }

    #[test]
    fn prop_block256_flat_roundtrip(lo in any::<u128>(), hi in any::<u128>()) {
        let flat = Flat::from_raw(Block256([lo, hi]));
        let tower = Block256::from_hardware(flat);
        prop_assert_eq!(tower.to_hardware(), flat);
    }

    #[test]
    fn prop_block256_mul_homomorphism(a in any_block256(), b in any_block256()) {
        let tower_product = a * b;
        let flat_product = Block256::mul_hardware(a.to_hardware(), b.to_hardware());
        prop_assert_eq!(tower_product.to_hardware(), flat_product);
    }

    #[test]
    fn prop_block256_add_homomorphism(a in any_block256(), b in any_block256()) {
        let tower_sum = a + b;
        let flat_sum = Block256::add_hardware(a.to_hardware(), b.to_hardware());
        prop_assert_eq!(tower_sum.to_hardware(), flat_sum);
    }

    #[test]
    fn prop_block256_promote_block8(val in any::<u8>().prop_map(Block8)) {
        let promoted = <Block256 as FlatPromote<Block8>>::promote_flat(val.to_hardware());
        let embedded = Block256::from(val).to_hardware();
        prop_assert_eq!(promoted, embedded);
    }

    #[test]
    fn prop_block256_promote_block16(val in any::<u16>().prop_map(Block16)) {
        let promoted = <Block256 as FlatPromote<Block16>>::promote_flat(val.to_hardware());
        let embedded = Block256::from(val).to_hardware();
        prop_assert_eq!(promoted, embedded);
    }

    #[test]
    fn prop_block256_promote_block32(val in any::<u32>().prop_map(Block32)) {
        let promoted = <Block256 as FlatPromote<Block32>>::promote_flat(val.to_hardware());
        let embedded = Block256::from(val).to_hardware();
        prop_assert_eq!(promoted, embedded);
    }

    #[test]
    fn prop_block256_promote_block64(val in any::<u64>().prop_map(Block64)) {
        let promoted = <Block256 as FlatPromote<Block64>>::promote_flat(val.to_hardware());
        let embedded = Block256::from(val).to_hardware();
        prop_assert_eq!(promoted, embedded);
    }

    #[test]
    fn prop_block256_promote_block128(val in any_block128()) {
        let promoted = <Block256 as FlatPromote<Block128>>::promote_flat(val.to_hardware());
        let embedded = Block256::from(val).to_hardware();
        prop_assert_eq!(promoted, embedded);
    }
}

// Tr_{GF(2^128)/GF(2)}(τ) = 1
// verifies that v² + v + τ is irreducible,
// validating the Block128 -> Block256 tower extension.
#[test]
fn block128_extension_tau_trace_is_one() {
    let tau = Block128::EXTENSION_TAU;

    let mut power = tau;
    let mut trace = tau;

    for _ in 1..128 {
        power = power * power;
        trace += power;
    }

    assert_eq!(
        trace,
        Block128::ONE,
        "Tr(τ₂₅₆) must be 1 for irreducibility"
    );
}

#[test]
fn block256_zero_invert_is_zero() {
    assert_eq!(Block256::ZERO.invert(), Block256::ZERO);
}
