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
    Bit, Block8, Block16, Block32, Block64, Block128, CanonicalDeserialize, CanonicalSerialize,
    TowerField,
};
use rand::{RngExt, rng};

// =================================================================
// GENERIC TEST RUNNER
// =================================================================

fn run_serialization_roundtrip<T>(val: T)
where
    T: TowerField + CanonicalSerialize + PartialEq + core::fmt::Debug,
{
    // Serialize using the trait method (allocating vec)
    let bytes = val.to_bytes();
    assert_eq!(
        bytes.len(),
        val.serialized_size(),
        "Serialized size mismatch for {:?}",
        val
    );

    let recovered = T::deserialize(&bytes).expect("Deserialization failed");
    assert_eq!(
        val, recovered,
        "Roundtrip mismatch.\nOriginal: {:?}\nBytes: {:?}\nRecovered: {:?}",
        val, bytes, recovered
    );
}

// =================================================================
// SPECIFIC TESTS (Endianness & Padding)
// =================================================================

#[test]
fn bit_serialization() {
    let zero = Bit::ZERO;
    let one = Bit::ONE;

    // Roundtrip
    run_serialization_roundtrip(zero);
    run_serialization_roundtrip(one);

    // Format check
    // Bit(0) -> [0x00]
    // Bit(1) -> [0x01]
    assert_eq!(zero.to_bytes(), vec![0x00], "Bit(0) must be 0x00");
    assert_eq!(one.to_bytes(), vec![0x01], "Bit(1) must be 0x01");

    // Deserialize check
    let rec_one = Bit::deserialize(&[1]).expect("Failed to deserialize Bit(1)");
    assert_eq!(rec_one, one);
}

#[test]
fn block8_serialization() {
    let mut rng = rng();
    for _ in 0..100 {
        let val = Block8(rng.random());
        run_serialization_roundtrip(val);
    }

    // Explicit check:
    // Block8(0xAB) -> [0xAB]
    let val = Block8(0xAB);
    assert_eq!(val.to_bytes(), vec![0xAB]);
}

#[test]
fn block16_endianness() {
    // Value: 0x1234
    // Little Endian: [0x34, 0x12]
    let val = Block16(0x1234);
    let expected_bytes = vec![0x34, 0x12];

    // Check Serialization
    assert_eq!(
        val.to_bytes(),
        expected_bytes,
        "Block16 must be Little Endian"
    );

    // Check Deserialization
    let recovered = Block16::deserialize(&expected_bytes).expect("Deserialize failed");
    assert_eq!(recovered, val);

    run_serialization_roundtrip(val);
}

#[test]
fn block32_endianness() {
    // Value: 0x12345678
    // Little Endian: [0x78, 0x56, 0x34, 0x12]
    let val = Block32(0x12345678);
    let expected_bytes = vec![0x78, 0x56, 0x34, 0x12];

    assert_eq!(
        val.to_bytes(),
        expected_bytes,
        "Block32 must be Little Endian"
    );

    let recovered = Block32::deserialize(&expected_bytes).expect("Deserialize failed");
    assert_eq!(recovered, val);

    run_serialization_roundtrip(val);
}

#[test]
fn block64_endianness() {
    // Value: 0x11223344_55667788
    // LE: [0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11]
    let val = Block64(0x11223344_55667788);
    let expected_bytes = vec![0x88, 0x77, 0x66, 0x55, 0x44, 0x33, 0x22, 0x11];

    assert_eq!(
        val.to_bytes(),
        expected_bytes,
        "Block64 must be Little Endian"
    );

    let recovered = Block64::deserialize(&expected_bytes).expect("Deserialize failed");
    assert_eq!(recovered, val);

    run_serialization_roundtrip(val);
}

#[test]
fn block128_endianness() {
    // Value: 1 (stored as u128)
    // LE: [1, 0, ..., 0] (16 bytes)
    let val = Block128::ONE;
    let mut expected_bytes = vec![0u8; 16];
    expected_bytes[0] = 1;

    assert_eq!(
        val.to_bytes(),
        expected_bytes,
        "Block128(1) must be Little Endian padded to 16 bytes"
    );

    let recovered = Block128::deserialize(&expected_bytes).expect("Deserialize failed");
    assert_eq!(recovered, val);

    // Max value check
    let max_val = Block128(u128::MAX);
    let max_bytes = vec![0xFFu8; 16];
    assert_eq!(max_val.to_bytes(), max_bytes);

    run_serialization_roundtrip(max_val);
}

#[test]
fn fuzz_all_blocks_roundtrip() {
    let mut rng = rng();

    for _ in 0..1000 {
        run_serialization_roundtrip(Block8(rng.random()));
        run_serialization_roundtrip(Block16(rng.random()));
        run_serialization_roundtrip(Block32(rng.random()));
        run_serialization_roundtrip(Block64(rng.random()));
        run_serialization_roundtrip(Block128(rng.random()));
    }
}
