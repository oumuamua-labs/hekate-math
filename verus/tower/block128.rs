// SPDX-License-Identifier: Apache-2.0
// This file is part of the hekate-math project.
// Copyright (C) 2026 Andrei Kochergin <andrei@oumuamua.dev>
// Copyright (C) 2026 Oumuamua Labs <info@oumuamua.dev>.
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

use vstd::prelude::*;

#[path = "block64.rs"]
pub mod b64;
use b64::{mul64_distrib_l, mul64_distrib_r, schoolbook64};

verus! {

pub open spec fn lo(x: u128) -> u64 {
    (x & 0xffffffffffffffff) as u64
}

pub open spec fn hi(x: u128) -> u64 {
    (x >> 64) as u64
}

pub open spec fn pack(l: u64, h: u64) -> u128 {
    (l as u128) | ((h as u128) << 64)
}

// GF(2^128) = GF(2^64)[X] / (X^2 + X + 0x2000_0000_0000_0000), naive schoolbook.
pub open spec fn schoolbook128(a: u128, b: u128) -> u128 {
    let a0 = lo(a);
    let a1 = hi(a);
    let b0 = lo(b);
    let b1 = hi(b);
    pack(
        schoolbook64(a0, b0) ^ schoolbook64(schoolbook64(a1, b1), 0x2000_0000_0000_0000),
        schoolbook64(a0, b1) ^ schoolbook64(a1, b0) ^ schoolbook64(a1, b1),
    )
}

// Block128::mul, block128.rs:110-121: Karatsuba, three base multiplies.
pub open spec fn mul128_k(a: u128, b: u128) -> u128 {
    let a0 = lo(a);
    let a1 = hi(a);
    let b0 = lo(b);
    let b1 = hi(b);
    let v0 = schoolbook64(a0, b0);
    let v1 = schoolbook64(a1, b1);
    let vs = schoolbook64(a0 ^ a1, b0 ^ b1);
    pack(v0 ^ schoolbook64(v1, 0x2000_0000_0000_0000), v0 ^ vs)
}

pub proof fn pack_xor(l1: u64, l2: u64, h1: u64, h2: u64)
    ensures pack(l1 ^ l2, h1 ^ h2) == pack(l1, h1) ^ pack(l2, h2)
{
    assert(pack(l1 ^ l2, h1 ^ h2) == pack(l1, h1) ^ pack(l2, h2)) by (bit_vector);
}

pub proof fn mul128_matches_schoolbook(a: u128, b: u128)
    ensures mul128_k(a, b) == schoolbook128(a, b)
{
    let a0 = lo(a);
    let a1 = hi(a);
    let b0 = lo(b);
    let b1 = hi(b);

    mul64_distrib_l(a0, a1, b0 ^ b1);
    mul64_distrib_r(a0, b0, b1);
    mul64_distrib_r(a1, b0, b1);

    let x00 = schoolbook64(a0, b0);
    let x01 = schoolbook64(a0, b1);
    let x10 = schoolbook64(a1, b0);
    let x11 = schoolbook64(a1, b1);

    assert(x00 ^ ((x00 ^ x01) ^ (x10 ^ x11)) == x01 ^ x10 ^ x11) by (bit_vector);
}

pub proof fn mul128_distrib_r(a: u128, b: u128, c: u128)
    ensures schoolbook128(a, b ^ c) == schoolbook128(a, b) ^ schoolbook128(a, c)
{
    let a0 = lo(a);
    let a1 = hi(a);
    let b0 = lo(b);
    let b1 = hi(b);
    let c0 = lo(c);
    let c1 = hi(c);

    assert(lo(b ^ c) == lo(b) ^ lo(c)) by (bit_vector);
    assert(hi(b ^ c) == hi(b) ^ hi(c)) by (bit_vector);

    mul64_distrib_r(a0, b0, c0);
    mul64_distrib_r(a1, b1, c1);
    mul64_distrib_r(a0, b1, c1);
    mul64_distrib_r(a1, b0, c0);
    mul64_distrib_l(schoolbook64(a1, b1), schoolbook64(a1, c1), 0x2000_0000_0000_0000);

    let ab0 = schoolbook64(a0, b0);
    let ac0 = schoolbook64(a0, c0);
    let ab1 = schoolbook64(a0, b1);
    let ac1 = schoolbook64(a0, c1);
    let xb0 = schoolbook64(a1, b0);
    let xc0 = schoolbook64(a1, c0);
    let xb1 = schoolbook64(a1, b1);
    let xc1 = schoolbook64(a1, c1);
    let tb = schoolbook64(xb1, 0x2000_0000_0000_0000);
    let tc = schoolbook64(xc1, 0x2000_0000_0000_0000);

    assert((ab0 ^ ac0) ^ (tb ^ tc) == (ab0 ^ tb) ^ (ac0 ^ tc)) by (bit_vector);
    assert((ab1 ^ ac1) ^ (xb0 ^ xc0) ^ (xb1 ^ xc1) == (ab1 ^ xb0 ^ xb1) ^ (ac1 ^ xc0 ^ xc1))
        by (bit_vector);

    pack_xor(ab0 ^ tb, ac0 ^ tc, ab1 ^ xb0 ^ xb1, ac1 ^ xc0 ^ xc1);
}

pub proof fn mul128_distrib_l(a: u128, d: u128, b: u128)
    ensures schoolbook128(a ^ d, b) == schoolbook128(a, b) ^ schoolbook128(d, b)
{
    let a0 = lo(a);
    let a1 = hi(a);
    let d0 = lo(d);
    let d1 = hi(d);
    let b0 = lo(b);
    let b1 = hi(b);

    assert(lo(a ^ d) == lo(a) ^ lo(d)) by (bit_vector);
    assert(hi(a ^ d) == hi(a) ^ hi(d)) by (bit_vector);

    mul64_distrib_l(a0, d0, b0);
    mul64_distrib_l(a1, d1, b1);
    mul64_distrib_l(a0, d0, b1);
    mul64_distrib_l(a1, d1, b0);
    mul64_distrib_l(schoolbook64(a1, b1), schoolbook64(d1, b1), 0x2000_0000_0000_0000);

    let ab0 = schoolbook64(a0, b0);
    let db0 = schoolbook64(d0, b0);
    let ab1 = schoolbook64(a0, b1);
    let db1 = schoolbook64(d0, b1);
    let xb0 = schoolbook64(a1, b0);
    let yb0 = schoolbook64(d1, b0);
    let xb1 = schoolbook64(a1, b1);
    let yb1 = schoolbook64(d1, b1);
    let ta = schoolbook64(xb1, 0x2000_0000_0000_0000);
    let td = schoolbook64(yb1, 0x2000_0000_0000_0000);

    assert((ab0 ^ db0) ^ (ta ^ td) == (ab0 ^ ta) ^ (db0 ^ td)) by (bit_vector);
    assert((ab1 ^ db1) ^ (xb0 ^ yb0) ^ (xb1 ^ yb1) == (ab1 ^ xb0 ^ xb1) ^ (db1 ^ yb0 ^ yb1))
        by (bit_vector);

    pack_xor(ab0 ^ ta, db0 ^ td, ab1 ^ xb0 ^ xb1, db1 ^ yb0 ^ yb1);
}

fn main() {}

}
