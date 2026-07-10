// SPDX-License-Identifier: Apache-2.0
// This file is part of the hekate-math project.
// Copyright (C) 2026 Andrei Kochergin <andrei@oumuamua.dev>
// Copyright (C) 2026 Oumuamua Labs <info@oumuamua.dev>. All rights reserved.
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

#[path = "block128.rs"]
pub mod b128;
use b128::{mul128_distrib_l, mul128_distrib_r, schoolbook128};

verus! {

// GF(2^256) = GF(2^128)[X] / (X^2 + X + tau), tau = 2^125. No u256
// type, an element is the pair (lo, hi) of Block128 limbs and the
// product is returned as a pair. Top of the tower: nothing builds on
// it, only the correctness theorem is needed.
pub open spec fn schoolbook256(alo: u128, ahi: u128, blo: u128, bhi: u128) -> (u128, u128) {
    (
        schoolbook128(alo, blo)
            ^ schoolbook128(schoolbook128(ahi, bhi), 0x2000_0000_0000_0000_0000_0000_0000_0000),
        schoolbook128(alo, bhi) ^ schoolbook128(ahi, blo) ^ schoolbook128(ahi, bhi),
    )
}

// Block256::mul, block256.rs:100-112: Karatsuba, three base multiplies.
pub open spec fn mul256_k(alo: u128, ahi: u128, blo: u128, bhi: u128) -> (u128, u128) {
    let v0 = schoolbook128(alo, blo);
    let v1 = schoolbook128(ahi, bhi);
    let vs = schoolbook128(alo ^ ahi, blo ^ bhi);
    (
        v0 ^ schoolbook128(v1, 0x2000_0000_0000_0000_0000_0000_0000_0000),
        v0 ^ vs,
    )
}

pub proof fn mul256_matches_schoolbook(alo: u128, ahi: u128, blo: u128, bhi: u128)
    ensures mul256_k(alo, ahi, blo, bhi) == schoolbook256(alo, ahi, blo, bhi)
{
    mul128_distrib_l(alo, ahi, blo ^ bhi);
    mul128_distrib_r(alo, blo, bhi);
    mul128_distrib_r(ahi, blo, bhi);

    let x00 = schoolbook128(alo, blo);
    let x01 = schoolbook128(alo, bhi);
    let x10 = schoolbook128(ahi, blo);
    let x11 = schoolbook128(ahi, bhi);

    assert(x00 ^ ((x00 ^ x01) ^ (x10 ^ x11)) == x01 ^ x10 ^ x11) by (bit_vector);
}

fn main() {}

}