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

#[path = "block8.rs"]
pub mod b8;
use b8::{
    mul_tau8, mul_tau8_is_schoolbook, mul8_distrib_l, mul8_distrib_r, schoolbook8, schoolbook8_zero,
};

verus! {

pub open spec fn lo(x: u16) -> u8 {
    (x & 0xff) as u8
}

pub open spec fn hi(x: u16) -> u8 {
    (x >> 8) as u8
}

pub open spec fn pack(l: u8, h: u8) -> u16 {
    (l as u16) | ((h as u16) << 8)
}

// GF(2^16) = GF(2^8)[X] / (X^2 + X + 0x20), naive schoolbook.
pub open spec fn schoolbook16(a: u16, b: u16) -> u16 {
    let a0 = lo(a);
    let a1 = hi(a);
    let b0 = lo(b);
    let b1 = hi(b);
    pack(
        schoolbook8(a0, b0) ^ schoolbook8(schoolbook8(a1, b1), 0x20),
        schoolbook8(a0, b1) ^ schoolbook8(a1, b0) ^ schoolbook8(a1, b1),
    )
}

// Block16::mul, block16.rs:
// Karatsuba, three base multiplies.
pub open spec fn mul16_k(a: u16, b: u16) -> u16 {
    let a0 = lo(a);
    let a1 = hi(a);
    let b0 = lo(b);
    let b1 = hi(b);

    let v0 = schoolbook8(a0, b0);
    let v1 = schoolbook8(a1, b1);
    let vs = schoolbook8(a0 ^ a1, b0 ^ b1);

    pack(v0 ^ mul_tau8(v1), v0 ^ vs)
}

// Block16::mul_tau, block16.rs:
// τ² a1 + τ(a0 + a1) X.
pub open spec fn mul_tau16(a: u16) -> u16 {
    let a0 = lo(a);
    let a1 = hi(a);
    let t = mul_tau8(a1);

    pack(mul_tau8(t), mul_tau8(a0 ^ a1))
}

pub proof fn schoolbook16_zero(a: u16)
    ensures schoolbook16(a, 0) == 0
{
    mul16_distrib_r(a, 1, 1);
    assert(1u16 ^ 1u16 == 0u16) by (bit_vector);

    let p = schoolbook16(a, 1);
    assert(p ^ p == 0u16) by (bit_vector);
}

pub proof fn mul_tau16_is_schoolbook(a: u16)
    ensures mul_tau16(a) == schoolbook16(a, 0x2000)
{
    let a0 = lo(a);
    let a1 = hi(a);

    assert(lo(0x2000u16) == 0u8) by (bit_vector);
    assert(hi(0x2000u16) == 0x20u8) by (bit_vector);

    let t = mul_tau8(a1);

    mul_tau8_is_schoolbook(a1);
    mul_tau8_is_schoolbook(t);
    mul_tau8_is_schoolbook(a0 ^ a1);

    mul8_distrib_l(a0, a1, 0x20);

    schoolbook8_zero(a0);
    schoolbook8_zero(a1);

    let x0 = schoolbook8(a0, 0x20);
    let x1 = schoolbook8(a1, 0x20);
    let x11 = schoolbook8(x1, 0x20);

    assert(0u8 ^ x11 == x11) by (bit_vector);
    assert(x0 ^ 0u8 ^ x1 == x0 ^ x1) by (bit_vector);
}

pub proof fn pack_xor(l1: u8, l2: u8, h1: u8, h2: u8)
    ensures pack(l1 ^ l2, h1 ^ h2) == pack(l1, h1) ^ pack(l2, h2)
{
    assert(pack(l1 ^ l2, h1 ^ h2) == pack(l1, h1) ^ pack(l2, h2)) by (bit_vector);
}

pub proof fn mul16_matches_schoolbook(a: u16, b: u16)
    ensures mul16_k(a, b) == schoolbook16(a, b)
{
    let a0 = lo(a);
    let a1 = hi(a);
    let b0 = lo(b);
    let b1 = hi(b);

    mul_tau8_is_schoolbook(schoolbook8(a1, b1));
    mul8_distrib_l(a0, a1, b0 ^ b1);
    mul8_distrib_r(a0, b0, b1);
    mul8_distrib_r(a1, b0, b1);

    let x00 = schoolbook8(a0, b0);
    let x01 = schoolbook8(a0, b1);
    let x10 = schoolbook8(a1, b0);
    let x11 = schoolbook8(a1, b1);

    assert(x00 ^ ((x00 ^ x01) ^ (x10 ^ x11)) == x01 ^ x10 ^ x11) by (bit_vector);
}

pub proof fn mul16_distrib_r(a: u16, b: u16, c: u16)
    ensures schoolbook16(a, b ^ c) == schoolbook16(a, b) ^ schoolbook16(a, c)
{
    let a0 = lo(a);
    let a1 = hi(a);
    let b0 = lo(b);
    let b1 = hi(b);
    let c0 = lo(c);
    let c1 = hi(c);

    assert(lo(b ^ c) == lo(b) ^ lo(c)) by (bit_vector);
    assert(hi(b ^ c) == hi(b) ^ hi(c)) by (bit_vector);

    mul8_distrib_r(a0, b0, c0);
    mul8_distrib_r(a1, b1, c1);
    mul8_distrib_r(a0, b1, c1);
    mul8_distrib_r(a1, b0, c0);
    mul8_distrib_l(schoolbook8(a1, b1), schoolbook8(a1, c1), 0x20);

    let ab0 = schoolbook8(a0, b0);
    let ac0 = schoolbook8(a0, c0);
    let ab1 = schoolbook8(a0, b1);
    let ac1 = schoolbook8(a0, c1);
    let xb0 = schoolbook8(a1, b0);
    let xc0 = schoolbook8(a1, c0);
    let xb1 = schoolbook8(a1, b1);
    let xc1 = schoolbook8(a1, c1);
    let tb = schoolbook8(xb1, 0x20);
    let tc = schoolbook8(xc1, 0x20);

    assert((ab0 ^ ac0) ^ (tb ^ tc) == (ab0 ^ tb) ^ (ac0 ^ tc)) by (bit_vector);
    assert((ab1 ^ ac1) ^ (xb0 ^ xc0) ^ (xb1 ^ xc1) == (ab1 ^ xb0 ^ xb1) ^ (ac1 ^ xc0 ^ xc1))
        by (bit_vector);

    pack_xor(ab0 ^ tb, ac0 ^ tc, ab1 ^ xb0 ^ xb1, ac1 ^ xc0 ^ xc1);
}

pub proof fn mul16_distrib_l(a: u16, d: u16, b: u16)
    ensures schoolbook16(a ^ d, b) == schoolbook16(a, b) ^ schoolbook16(d, b)
{
    let a0 = lo(a);
    let a1 = hi(a);
    let d0 = lo(d);
    let d1 = hi(d);
    let b0 = lo(b);
    let b1 = hi(b);

    assert(lo(a ^ d) == lo(a) ^ lo(d)) by (bit_vector);
    assert(hi(a ^ d) == hi(a) ^ hi(d)) by (bit_vector);

    mul8_distrib_l(a0, d0, b0);
    mul8_distrib_l(a1, d1, b1);
    mul8_distrib_l(a0, d0, b1);
    mul8_distrib_l(a1, d1, b0);
    mul8_distrib_l(schoolbook8(a1, b1), schoolbook8(d1, b1), 0x20);

    let ab0 = schoolbook8(a0, b0);
    let db0 = schoolbook8(d0, b0);
    let ab1 = schoolbook8(a0, b1);
    let db1 = schoolbook8(d0, b1);
    let xb0 = schoolbook8(a1, b0);
    let yb0 = schoolbook8(d1, b0);
    let xb1 = schoolbook8(a1, b1);
    let yb1 = schoolbook8(d1, b1);
    let ta = schoolbook8(xb1, 0x20);
    let td = schoolbook8(yb1, 0x20);

    assert((ab0 ^ db0) ^ (ta ^ td) == (ab0 ^ ta) ^ (db0 ^ td)) by (bit_vector);
    assert((ab1 ^ db1) ^ (xb0 ^ yb0) ^ (xb1 ^ yb1) == (ab1 ^ xb0 ^ xb1) ^ (db1 ^ yb0 ^ yb1))
        by (bit_vector);

    pack_xor(ab0 ^ ta, db0 ^ td, ab1 ^ xb0 ^ xb1, db1 ^ yb0 ^ yb1);
}

fn main() {}

}
