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

#[path = "gf_model.rs"]
pub mod gf_model;

#[path = "block256.rs"]
pub mod b256;

use b256::b128::b64::b32::b16::b8::{clmul8, reduce8, schoolbook8};
use b256::b128::b64::b32::b16::schoolbook16;
use b256::b128::b64::b32::schoolbook32;
use b256::b128::b64::schoolbook64;
use b256::b128::schoolbook128;
use b256::schoolbook256;

use gf_model::gf_mul_tower;

verus! {

// clmul8 output has degree < 15. Each term (a << j) has j <= 7, a < 2^8.
proof fn clmul8_bnd(a: u8, b: u8)
    ensures clmul8(a, b) < 0x8000,
{
    assert((if b & 0x01 != 0 { a as u16 } else { 0u16 }) ^
        (if b & 0x02 != 0 { (a as u16) << 1 } else { 0u16 }) ^
        (if b & 0x04 != 0 { (a as u16) << 2 } else { 0u16 }) ^
        (if b & 0x08 != 0 { (a as u16) << 3 } else { 0u16 }) ^
        (if b & 0x10 != 0 { (a as u16) << 4 } else { 0u16 }) ^
        (if b & 0x20 != 0 { (a as u16) << 5 } else { 0u16 }) ^
        (if b & 0x40 != 0 { (a as u16) << 6 } else { 0u16 }) ^
        (if b & 0x80 != 0 { (a as u16) << 7 } else { 0u16 }) <
        0x8000) by (bit_vector);
}

// clmul8's low-bit recursion: peel bit 0, halve b, shift the tail up one.
// The two sides are clmul8's (open) definition at b and at b / 2.
proof fn clmul8_rec(a: u8, b: u8)
    ensures clmul8(a, b) == (if b & 1 == 1 { a as u16 } else { 0 }) ^ (clmul8(a, b / 2) << 1),
{
    assert((if b & 0x01 != 0 { a as u16 } else { 0u16 }) ^
        (if b & 0x02 != 0 { (a as u16) << 1 } else { 0u16 }) ^
        (if b & 0x04 != 0 { (a as u16) << 2 } else { 0u16 }) ^
        (if b & 0x08 != 0 { (a as u16) << 3 } else { 0u16 }) ^
        (if b & 0x10 != 0 { (a as u16) << 4 } else { 0u16 }) ^
        (if b & 0x20 != 0 { (a as u16) << 5 } else { 0u16 }) ^
        (if b & 0x40 != 0 { (a as u16) << 6 } else { 0u16 }) ^
        (if b & 0x80 != 0 { (a as u16) << 7 } else { 0u16 }) ==
        (if b & 1 == 1 { a as u16 } else { 0u16 }) ^
        ((if (b / 2) & 0x01 != 0 { a as u16 } else { 0u16 }) ^
        (if (b / 2) & 0x02 != 0 { (a as u16) << 1 } else { 0u16 }) ^
        (if (b / 2) & 0x04 != 0 { (a as u16) << 2 } else { 0u16 }) ^
        (if (b / 2) & 0x08 != 0 { (a as u16) << 3 } else { 0u16 }) ^
        (if (b / 2) & 0x10 != 0 { (a as u16) << 4 } else { 0u16 }) ^
        (if (b / 2) & 0x20 != 0 { (a as u16) << 5 } else { 0u16 }) ^
        (if (b / 2) & 0x40 != 0 { (a as u16) << 6 } else { 0u16 }) ^
        (if (b / 2) & 0x80 != 0 { (a as u16) << 7 } else { 0u16 })) << 1) by (bit_vector);
}

// gf_model::xor on 16-bit values is native ^.
pub proof fn xor16(x: u16, y: u16)
    ensures gf_model::xor(x as nat, y as nat) == (x ^ y) as nat
    decreases x as nat + y as nat
{
    if x == 0 && y == 0 {
        assert(gf_model::xor(x as nat, y as nat) == 0) by {
            reveal_with_fuel(gf_model::xor, 1);
        }
        assert(x ^ y == 0) by (bit_vector) requires x == 0 && y == 0;
    } else {
        xor16(x / 2, y / 2);

        let xl = (x % 2) ^ (y % 2);
        let xh = (x / 2) ^ (y / 2);

        assert((x as nat) / 2 == (x / 2) as nat);
        assert((y as nat) / 2 == (y / 2) as nat);
        assert(gf_model::xor((x as nat) / 2, (y as nat) / 2) == xh as nat);

        assert(gf_model::xor(x as nat, y as nat) == ((x as nat) % 2 + (y as nat) % 2) % 2 + 2
            * gf_model::xor((x as nat) / 2, (y as nat) / 2)) by {
            reveal_with_fuel(gf_model::xor, 1);
        }

        assert((x % 2) ^ (y % 2) == ((x % 2) + (y % 2)) % 2) by (bit_vector);
        assert(((x as nat) % 2 + (y as nat) % 2) % 2 == xl as nat);

        assert(x ^ y == ((x % 2) ^ (y % 2)) + 2 * ((x / 2) ^ (y / 2))) by (bit_vector);
        assert((x ^ y) as nat == xl as nat + 2 * (xh as nat));

        assert(gf_model::xor(x as nat, y as nat) == xl as nat + 2 * (xh as nat));
    }
}

// A u16 left shift by one is doubling below the top bit.
proof fn shl1_u16(x: u16)
    requires x < 0x8000,
    ensures (x << 1) as nat == 2 * (x as nat),
{
    assert(x << 1 == x * 2) by (bit_vector) requires x < 0x8000;
}

// gf_model::clmul on u8 inputs equals block8's clmul8, by induction on b:
// clmul peels its low bit and doubles (split_low + distrib_r + shift_r),
// which clmul8_rec mirrors bit-for-bit.
proof fn clmul8_bridge(a: u8, b: u8)
    ensures gf_model::clmul(a as nat, b as nat) == clmul8(a, b) as nat,
    decreases b,
{
    if b == 0 {
        gf_model::clmul_zero_r(a as nat);
        assert((if b & 0x01 != 0 { a as u16 } else { 0u16 }) ^
            (if b & 0x02 != 0 { (a as u16) << 1 } else { 0u16 }) ^
            (if b & 0x04 != 0 { (a as u16) << 2 } else { 0u16 }) ^
            (if b & 0x08 != 0 { (a as u16) << 3 } else { 0u16 }) ^
            (if b & 0x10 != 0 { (a as u16) << 4 } else { 0u16 }) ^
            (if b & 0x20 != 0 { (a as u16) << 5 } else { 0u16 }) ^
            (if b & 0x40 != 0 { (a as u16) << 6 } else { 0u16 }) ^
            (if b & 0x80 != 0 { (a as u16) << 7 } else { 0u16 }) == 0) by (bit_vector)
            requires b == 0;
    } else {
        clmul8_bridge(a, b / 2);
        clmul8_rec(a, b);
        clmul8_bnd(a, b / 2);
        shl1_u16(clmul8(a, b / 2));
        xor16(if b & 1 == 1 { a as u16 } else { 0u16 }, clmul8(a, b / 2) << 1);

        assert(b & 1 == b % 2) by (bit_vector);
        assert((b as nat) / 2 == (b / 2) as nat);
        assert((b as nat) % 2 == (b % 2) as nat);

        gf_model::split_low(b as nat);
        gf_model::clmul_distrib_r(a as nat, 2 * ((b / 2) as nat), (b % 2) as nat);
        gf_model::clmul_shift_r(a as nat, (b / 2) as nat);

        if b % 2 == 1 {
            gf_model::clmul_one_r(a as nat);
        } else {
            gf_model::clmul_zero_r(a as nat);
        }

        gf_model::xor_comm(
            2 * gf_model::clmul(a as nat, (b / 2) as nat),
            if b & 1 == 1 { a as nat } else { 0nat },
        );
    }
}

// gf_model::xor on 8-bit values is native ^ (the u8 twin of xor16).
proof fn xor8(x: u8, y: u8)
    ensures gf_model::xor(x as nat, y as nat) == (x ^ y) as nat
    decreases x as nat + y as nat
{
    if x == 0 && y == 0 {
        assert(gf_model::xor(x as nat, y as nat) == 0) by {
            reveal_with_fuel(gf_model::xor, 1);
        }
        assert(x ^ y == 0) by (bit_vector) requires x == 0 && y == 0;
    } else {
        xor8(x / 2, y / 2);

        let xl = (x % 2) ^ (y % 2);
        let xh = (x / 2) ^ (y / 2);

        assert((x as nat) / 2 == (x / 2) as nat);
        assert((y as nat) / 2 == (y / 2) as nat);
        assert(gf_model::xor((x as nat) / 2, (y as nat) / 2) == xh as nat);

        assert(gf_model::xor(x as nat, y as nat) == ((x as nat) % 2 + (y as nat) % 2) % 2 + 2
            * gf_model::xor((x as nat) / 2, (y as nat) / 2)) by {
            reveal_with_fuel(gf_model::xor, 1);
        }

        assert((x % 2) ^ (y % 2) == ((x % 2) + (y % 2)) % 2) by (bit_vector);
        assert(((x as nat) % 2 + (y as nat) % 2) % 2 == xl as nat);
        assert(x ^ y == ((x % 2) ^ (y % 2)) + 2 * ((x / 2) ^ (y / 2))) by (bit_vector);
        assert((x ^ y) as nat == xl as nat + 2 * (xh as nat));
        assert(gf_model::xor(x as nat, y as nat) == xl as nat + 2 * (xh as nat));
    }
}

// reduce8 is GF(2)-linear: it XORs bit-selected constants, it distributes
// over ^. Read off reduce8's (open) definition; the two sides are its body at
// x ^ y and at x, y.
proof fn reduce8_lin(x: u16, y: u16)
    ensures reduce8(x ^ y) == reduce8(x) ^ reduce8(y),
{
    assert((((x ^ y) & 0xff) ^
        (if (x ^ y) & 0x0100 != 0 { 0x1bu16 } else { 0 }) ^
        (if (x ^ y) & 0x0200 != 0 { 0x36u16 } else { 0 }) ^
        (if (x ^ y) & 0x0400 != 0 { 0x6cu16 } else { 0 }) ^
        (if (x ^ y) & 0x0800 != 0 { 0xd8u16 } else { 0 }) ^
        (if (x ^ y) & 0x1000 != 0 { 0xabu16 } else { 0 }) ^
        (if (x ^ y) & 0x2000 != 0 { 0x4du16 } else { 0 }) ^
        (if (x ^ y) & 0x4000 != 0 { 0x9au16 } else { 0 })) as u8 ==
        ((x & 0xff) ^
        (if x & 0x0100 != 0 { 0x1bu16 } else { 0 }) ^
        (if x & 0x0200 != 0 { 0x36u16 } else { 0 }) ^
        (if x & 0x0400 != 0 { 0x6cu16 } else { 0 }) ^
        (if x & 0x0800 != 0 { 0xd8u16 } else { 0 }) ^
        (if x & 0x1000 != 0 { 0xabu16 } else { 0 }) ^
        (if x & 0x2000 != 0 { 0x4du16 } else { 0 }) ^
        (if x & 0x4000 != 0 { 0x9au16 } else { 0 })) as u8 ^
        ((y & 0xff) ^
        (if y & 0x0100 != 0 { 0x1bu16 } else { 0 }) ^
        (if y & 0x0200 != 0 { 0x36u16 } else { 0 }) ^
        (if y & 0x0400 != 0 { 0x6cu16 } else { 0 }) ^
        (if y & 0x0800 != 0 { 0xd8u16 } else { 0 }) ^
        (if y & 0x1000 != 0 { 0xabu16 } else { 0 }) ^
        (if y & 0x2000 != 0 { 0x4du16 } else { 0 }) ^
        (if y & 0x4000 != 0 { 0x9au16 } else { 0 })) as u8) by (bit_vector);
}

// reduce8 as a nat map distributes over gf_model::xor (its additivity, lifted
// through xor16 / reduce8_lin / xor8).
proof fn reduce8_add_helper(u: nat, v: nat)
    requires
        u < 0x10000,
        v < 0x10000,
    ensures
        reduce8(gf_model::xor(u, v) as u16) as nat == gf_model::xor(
            reduce8(u as u16) as nat,
            reduce8(v as u16) as nat,
        ),
{
    xor16(u as u16, v as u16);
    assert((u as u16) as nat == u);
    assert((v as u16) as nat == v);
    assert(gf_model::xor(u, v) as u16 == (u as u16) ^ (v as u16));

    reduce8_lin(u as u16, v as u16);
    xor8(reduce8(u as u16), reduce8(v as u16));
}

// pmod and reduce8 agree on each power-of-two basis vector below 2^15.
proof fn reduce8_basis(i: nat)
    requires i < 15,
    ensures gf_model::pmod(gf_model::pow2(i), gf_model::modulus(8)) == reduce8(
        gf_model::pow2(i) as u16,
    ) as nat,
{
    gf_model::pow2_mono(i, 14);
    assert(gf_model::pow2(14) == 0x4000) by (compute);

    if i == 0 {
        assert(gf_model::pmod(gf_model::pow2(0), gf_model::modulus(8))
            == reduce8(gf_model::pow2(0) as u16) as nat) by (compute);
    } else if i == 1 {
        assert(gf_model::pmod(gf_model::pow2(1), gf_model::modulus(8))
            == reduce8(gf_model::pow2(1) as u16) as nat) by (compute);
    } else if i == 2 {
        assert(gf_model::pmod(gf_model::pow2(2), gf_model::modulus(8))
            == reduce8(gf_model::pow2(2) as u16) as nat) by (compute);
    } else if i == 3 {
        assert(gf_model::pmod(gf_model::pow2(3), gf_model::modulus(8))
            == reduce8(gf_model::pow2(3) as u16) as nat) by (compute);
    } else if i == 4 {
        assert(gf_model::pmod(gf_model::pow2(4), gf_model::modulus(8))
            == reduce8(gf_model::pow2(4) as u16) as nat) by (compute);
    } else if i == 5 {
        assert(gf_model::pmod(gf_model::pow2(5), gf_model::modulus(8))
            == reduce8(gf_model::pow2(5) as u16) as nat) by (compute);
    } else if i == 6 {
        assert(gf_model::pmod(gf_model::pow2(6), gf_model::modulus(8))
            == reduce8(gf_model::pow2(6) as u16) as nat) by (compute);
    } else if i == 7 {
        assert(gf_model::pmod(gf_model::pow2(7), gf_model::modulus(8))
            == reduce8(gf_model::pow2(7) as u16) as nat) by (compute);
    } else if i == 8 {
        assert(gf_model::pmod(gf_model::pow2(8), gf_model::modulus(8))
            == reduce8(gf_model::pow2(8) as u16) as nat) by (compute);
    } else if i == 9 {
        assert(gf_model::pmod(gf_model::pow2(9), gf_model::modulus(8))
            == reduce8(gf_model::pow2(9) as u16) as nat) by (compute);
    } else if i == 10 {
        assert(gf_model::pmod(gf_model::pow2(10), gf_model::modulus(8))
            == reduce8(gf_model::pow2(10) as u16) as nat) by (compute);
    } else if i == 11 {
        assert(gf_model::pmod(gf_model::pow2(11), gf_model::modulus(8))
            == reduce8(gf_model::pow2(11) as u16) as nat) by (compute);
    } else if i == 12 {
        assert(gf_model::pmod(gf_model::pow2(12), gf_model::modulus(8))
            == reduce8(gf_model::pow2(12) as u16) as nat) by (compute);
    } else if i == 13 {
        assert(gf_model::pmod(gf_model::pow2(13), gf_model::modulus(8))
            == reduce8(gf_model::pow2(13) as u16) as nat) by (compute);
    } else {
        assert(gf_model::pmod(gf_model::pow2(14), gf_model::modulus(8))
            == reduce8(gf_model::pow2(14) as u16) as nat) by (compute);
    }
}

// Reduce reflection: `pmod(y, 0x11b) == reduce8(y)` for y below 2^15. Both are
// GF(2)-linear over xor and agree on the power basis (reduce8_basis),
// linear_determined_field extends the agreement to all y.
proof fn reduce8_bridge(y: u16)
    requires y < 0x8000,
    ensures gf_model::pmod(y as nat, gf_model::modulus(8)) == reduce8(y) as nat,
{
    let f = |n: nat| gf_model::pmod(n, gf_model::modulus(8));
    let g = |n: nat| reduce8(n as u16) as nat;

    gf_model::deg_modulus(8);

    assert forall|u: nat, v: nat| gf_model::in_field(u, 15) && gf_model::in_field(v, 15)
        implies #[trigger] f(gf_model::xor(u, v)) == gf_model::xor(f(u), f(v)) by {
        gf_model::pmod_additive(u, v, gf_model::modulus(8));
    }

    assert forall|u: nat, v: nat| gf_model::in_field(u, 15) && gf_model::in_field(v, 15)
        implies #[trigger] g(gf_model::xor(u, v)) == gf_model::xor(g(u), g(v)) by {
        gf_model::deg_upper(u, 15);
        gf_model::deg_upper(v, 15);
        assert(gf_model::pow2(15) == 0x8000) by (compute);
        reduce8_add_helper(u, v);
    }

    assert forall|i: nat| i < 15 implies #[trigger] f(gf_model::pow2(i)) == g(gf_model::pow2(i))
        by {
        reduce8_basis(i);
    }

    assert(gf_model::pow2(15) == 0x8000) by (compute);
    gf_model::deg_lt_conv(y as nat, 15);
    gf_model::linear_determined_field(f, g, y as nat, 15);
}

// Leaf: the u8 production oracle equals the nat field model at GF(2^8).
// schoolbook8 = reduce8 ∘ clmul8; gf_mul_tower bottoms out at gf_mul = pmod ∘ clmul.
proof fn bridge8(a: u8, b: u8)
    ensures schoolbook8(a, b) as nat == gf_mul_tower(a as nat, b as nat, 8),
{
    clmul8_bridge(a, b);
    clmul8_bnd(a, b);
    reduce8_bridge(clmul8(a, b));
}

// Split/pack a u16 into two u8 halves, matching lo_half/hi_half/pack at k = 16.
proof fn split16(a: u16)
    ensures
        ((a & 0xff) as u8) as nat == (a as nat) % gf_model::pow2(8),
        ((a >> 8) as u8) as nat == (a as nat) / gf_model::pow2(8),
{
    assert(gf_model::pow2(8) == 256) by (compute);
    assert(a & 0xff < 256) by (bit_vector);
    assert(a >> 8 < 256) by (bit_vector);
    assert(a & 0xff == a % 256) by (bit_vector);
    assert(a >> 8 == a / 256) by (bit_vector);
}

proof fn pack16(l: u8, h: u8)
    ensures ((l as u16) | ((h as u16) << 8)) as nat == (l as nat) + gf_model::pow2(8) * (h as nat),
{
    assert(gf_model::pow2(8) == 256) by (compute);
    assert((l as u16) | ((h as u16) << 8) == (l as u16) + (h as u16) * 256) by (bit_vector);
}

// Lift 8 -> 16: schoolbook16's four base multiplies and its pack are gf_mul_tower's,
// via bridge8 on each sub-product (tau_tower(8) = 0x20), xor8 on the combines, pack16.
pub proof fn bridge16(a: u16, b: u16)
    ensures schoolbook16(a, b) as nat == gf_mul_tower(a as nat, b as nat, 16),
{
    let a0 = (a & 0xff) as u8;
    let a1 = (a >> 8) as u8;
    let b0 = (b & 0xff) as u8;
    let b1 = (b >> 8) as u8;

    bridge8(a0, b0);
    bridge8(a0, b1);
    bridge8(a1, b0);
    bridge8(a1, b1);
    bridge8(schoolbook8(a1, b1), 0x20);

    split16(a);
    split16(b);
    assert(gf_model::tau_tower(8) == 0x20) by (compute);

    xor8(schoolbook8(a0, b0), schoolbook8(schoolbook8(a1, b1), 0x20));
    xor8(schoolbook8(a0, b1), schoolbook8(a1, b0));
    xor8(schoolbook8(a0, b1) ^ schoolbook8(a1, b0), schoolbook8(a1, b1));

    pack16(
        schoolbook8(a0, b0) ^ schoolbook8(schoolbook8(a1, b1), 0x20),
        schoolbook8(a0, b1) ^ schoolbook8(a1, b0) ^ schoolbook8(a1, b1),
    );
}

proof fn xor32(x: u32, y: u32)
    ensures gf_model::xor(x as nat, y as nat) == (x ^ y) as nat
    decreases x as nat + y as nat
{
    if x == 0 && y == 0 {
        assert(gf_model::xor(x as nat, y as nat) == 0) by {
            reveal_with_fuel(gf_model::xor, 1);
        }
        assert(x ^ y == 0) by (bit_vector) requires x == 0 && y == 0;
    } else {
        xor32(x / 2, y / 2);

        let xl = (x % 2) ^ (y % 2);
        let xh = (x / 2) ^ (y / 2);

        assert((x as nat) / 2 == (x / 2) as nat);
        assert((y as nat) / 2 == (y / 2) as nat);
        assert(gf_model::xor((x as nat) / 2, (y as nat) / 2) == xh as nat);

        assert(gf_model::xor(x as nat, y as nat) == ((x as nat) % 2 + (y as nat) % 2) % 2 + 2
            * gf_model::xor((x as nat) / 2, (y as nat) / 2)) by {
            reveal_with_fuel(gf_model::xor, 1);
        }

        assert((x % 2) ^ (y % 2) == ((x % 2) + (y % 2)) % 2) by (bit_vector);
        assert(((x as nat) % 2 + (y as nat) % 2) % 2 == xl as nat);
        assert(x ^ y == ((x % 2) ^ (y % 2)) + 2 * ((x / 2) ^ (y / 2))) by (bit_vector);
        assert((x ^ y) as nat == xl as nat + 2 * (xh as nat));
        assert(gf_model::xor(x as nat, y as nat) == xl as nat + 2 * (xh as nat));
    }
}

proof fn split32(a: u32)
    ensures
        ((a & 0xffff) as u16) as nat == (a as nat) % gf_model::pow2(16),
        ((a >> 16) as u16) as nat == (a as nat) / gf_model::pow2(16),
{
    assert(gf_model::pow2(16) == 0x10000) by (compute);
    assert(a & 0xffff < 0x10000) by (bit_vector);
    assert(a >> 16 < 0x10000) by (bit_vector);
    assert(a & 0xffff == a % 0x10000) by (bit_vector);
    assert(a >> 16 == a / 0x10000) by (bit_vector);
}

proof fn pack32(l: u16, h: u16)
    ensures ((l as u32) | ((h as u32) << 16)) as nat == (l as nat) + gf_model::pow2(16) * (h as nat),
{
    assert(gf_model::pow2(16) == 0x10000) by (compute);
    assert((l as u32) | ((h as u32) << 16) == (l as u32) + (h as u32) * 0x10000) by (bit_vector);
}

// Lift 16 -> 32 (tau_tower(16) = 0x2000).
proof fn bridge32(a: u32, b: u32)
    ensures schoolbook32(a, b) as nat == gf_mul_tower(a as nat, b as nat, 32),
{
    let a0 = (a & 0xffff) as u16;
    let a1 = (a >> 16) as u16;
    let b0 = (b & 0xffff) as u16;
    let b1 = (b >> 16) as u16;

    bridge16(a0, b0);
    bridge16(a0, b1);
    bridge16(a1, b0);
    bridge16(a1, b1);
    bridge16(schoolbook16(a1, b1), 0x2000);

    split32(a);
    split32(b);
    assert(gf_model::tau_tower(16) == 0x2000) by (compute);

    xor16(schoolbook16(a0, b0), schoolbook16(schoolbook16(a1, b1), 0x2000));
    xor16(schoolbook16(a0, b1), schoolbook16(a1, b0));
    xor16(schoolbook16(a0, b1) ^ schoolbook16(a1, b0), schoolbook16(a1, b1));

    pack32(
        schoolbook16(a0, b0) ^ schoolbook16(schoolbook16(a1, b1), 0x2000),
        schoolbook16(a0, b1) ^ schoolbook16(a1, b0) ^ schoolbook16(a1, b1),
    );
}

proof fn split64(a: u64)
    ensures
        ((a & 0xffffffff) as u32) as nat == (a as nat) % gf_model::pow2(32),
        ((a >> 32) as u32) as nat == (a as nat) / gf_model::pow2(32),
{
    assert(gf_model::pow2(32) == 0x1_0000_0000) by (compute);
    assert(a & 0xffffffff < 0x1_0000_0000) by (bit_vector);
    assert(a >> 32 < 0x1_0000_0000) by (bit_vector);
    assert(a & 0xffffffff == a % 0x1_0000_0000) by (bit_vector);
    assert(a >> 32 == a / 0x1_0000_0000) by (bit_vector);
}

proof fn pack64(l: u32, h: u32)
    ensures ((l as u64) | ((h as u64) << 32)) as nat == (l as nat) + gf_model::pow2(32) * (h as nat),
{
    assert(gf_model::pow2(32) == 0x1_0000_0000) by (compute);
    assert((l as u64) | ((h as u64) << 32) == (l as u64) + (h as u64) * 0x1_0000_0000)
        by (bit_vector);
}

// Lift 32 -> 64 (tau_tower(32) = 0x2000_0000).
proof fn bridge64(a: u64, b: u64)
    ensures schoolbook64(a, b) as nat == gf_mul_tower(a as nat, b as nat, 64),
{
    let a0 = (a & 0xffffffff) as u32;
    let a1 = (a >> 32) as u32;
    let b0 = (b & 0xffffffff) as u32;
    let b1 = (b >> 32) as u32;

    bridge32(a0, b0);
    bridge32(a0, b1);
    bridge32(a1, b0);
    bridge32(a1, b1);
    bridge32(schoolbook32(a1, b1), 0x2000_0000);

    split64(a);
    split64(b);
    assert(gf_model::tau_tower(32) == 0x2000_0000) by (compute);

    xor32(schoolbook32(a0, b0), schoolbook32(schoolbook32(a1, b1), 0x2000_0000));
    xor32(schoolbook32(a0, b1), schoolbook32(a1, b0));
    xor32(schoolbook32(a0, b1) ^ schoolbook32(a1, b0), schoolbook32(a1, b1));

    pack64(
        schoolbook32(a0, b0) ^ schoolbook32(schoolbook32(a1, b1), 0x2000_0000),
        schoolbook32(a0, b1) ^ schoolbook32(a1, b0) ^ schoolbook32(a1, b1),
    );
}

proof fn xor64(x: u64, y: u64)
    ensures gf_model::xor(x as nat, y as nat) == (x ^ y) as nat
    decreases x as nat + y as nat
{
    if x == 0 && y == 0 {
        assert(gf_model::xor(x as nat, y as nat) == 0) by {
            reveal_with_fuel(gf_model::xor, 1);
        }
        assert(x ^ y == 0) by (bit_vector) requires x == 0 && y == 0;
    } else {
        xor64(x / 2, y / 2);

        let xl = (x % 2) ^ (y % 2);
        let xh = (x / 2) ^ (y / 2);

        assert((x as nat) / 2 == (x / 2) as nat);
        assert((y as nat) / 2 == (y / 2) as nat);
        assert(gf_model::xor((x as nat) / 2, (y as nat) / 2) == xh as nat);

        assert(gf_model::xor(x as nat, y as nat) == ((x as nat) % 2 + (y as nat) % 2) % 2 + 2
            * gf_model::xor((x as nat) / 2, (y as nat) / 2)) by {
            reveal_with_fuel(gf_model::xor, 1);
        }

        assert((x % 2) ^ (y % 2) == ((x % 2) + (y % 2)) % 2) by (bit_vector);
        assert(((x as nat) % 2 + (y as nat) % 2) % 2 == xl as nat);
        assert(x ^ y == ((x % 2) ^ (y % 2)) + 2 * ((x / 2) ^ (y / 2))) by (bit_vector);
        assert((x ^ y) as nat == xl as nat + 2 * (xh as nat));
        assert(gf_model::xor(x as nat, y as nat) == xl as nat + 2 * (xh as nat));
    }
}

proof fn split128(a: u128)
    ensures
        ((a & 0xffffffffffffffff) as u64) as nat == (a as nat) % gf_model::pow2(64),
        ((a >> 64) as u64) as nat == (a as nat) / gf_model::pow2(64),
{
    assert(gf_model::pow2(64) == 0x1_0000_0000_0000_0000) by (compute);
    assert(a & 0xffffffffffffffff < 0x1_0000_0000_0000_0000) by (bit_vector);
    assert(a >> 64 < 0x1_0000_0000_0000_0000) by (bit_vector);
    assert(a & 0xffffffffffffffff == a % 0x1_0000_0000_0000_0000) by (bit_vector);
    assert(a >> 64 == a / 0x1_0000_0000_0000_0000) by (bit_vector);
}

proof fn pack128(l: u64, h: u64)
    ensures ((l as u128) | ((h as u128) << 64)) as nat == (l as nat) + gf_model::pow2(64) * (h
        as nat),
{
    assert(gf_model::pow2(64) == 0x1_0000_0000_0000_0000) by (compute);
    assert((l as u128) | ((h as u128) << 64) == (l as u128) + (h as u128)
        * 0x1_0000_0000_0000_0000) by (bit_vector);
}

// Lift 64 -> 128 (tau_tower(64) = 0x2000_0000_0000_0000).
proof fn bridge128(a: u128, b: u128)
    ensures schoolbook128(a, b) as nat == gf_mul_tower(a as nat, b as nat, 128),
{
    let a0 = (a & 0xffffffffffffffff) as u64;
    let a1 = (a >> 64) as u64;
    let b0 = (b & 0xffffffffffffffff) as u64;
    let b1 = (b >> 64) as u64;

    bridge64(a0, b0);
    bridge64(a0, b1);
    bridge64(a1, b0);
    bridge64(a1, b1);
    bridge64(schoolbook64(a1, b1), 0x2000_0000_0000_0000);

    split128(a);
    split128(b);
    assert(gf_model::tau_tower(64) == 0x2000_0000_0000_0000) by (compute);

    xor64(schoolbook64(a0, b0), schoolbook64(schoolbook64(a1, b1), 0x2000_0000_0000_0000));
    xor64(schoolbook64(a0, b1), schoolbook64(a1, b0));
    xor64(schoolbook64(a0, b1) ^ schoolbook64(a1, b0), schoolbook64(a1, b1));

    pack128(
        schoolbook64(a0, b0) ^ schoolbook64(schoolbook64(a1, b1), 0x2000_0000_0000_0000),
        schoolbook64(a0, b1) ^ schoolbook64(a1, b0) ^ schoolbook64(a1, b1),
    );
}

proof fn xor128(x: u128, y: u128)
    ensures gf_model::xor(x as nat, y as nat) == (x ^ y) as nat
    decreases x as nat + y as nat
{
    if x == 0 && y == 0 {
        assert(gf_model::xor(x as nat, y as nat) == 0) by {
            reveal_with_fuel(gf_model::xor, 1);
        }
        assert(x ^ y == 0) by (bit_vector) requires x == 0 && y == 0;
    } else {
        xor128(x / 2, y / 2);

        let xl = (x % 2) ^ (y % 2);
        let xh = (x / 2) ^ (y / 2);

        assert((x as nat) / 2 == (x / 2) as nat);
        assert((y as nat) / 2 == (y / 2) as nat);
        assert(gf_model::xor((x as nat) / 2, (y as nat) / 2) == xh as nat);

        assert(gf_model::xor(x as nat, y as nat) == ((x as nat) % 2 + (y as nat) % 2) % 2 + 2
            * gf_model::xor((x as nat) / 2, (y as nat) / 2)) by {
            reveal_with_fuel(gf_model::xor, 1);
        }

        assert((x % 2) ^ (y % 2) == ((x % 2) + (y % 2)) % 2) by (bit_vector);
        assert(((x as nat) % 2 + (y as nat) % 2) % 2 == xl as nat);
        assert(x ^ y == ((x % 2) ^ (y % 2)) + 2 * ((x / 2) ^ (y / 2))) by (bit_vector);
        assert((x ^ y) as nat == xl as nat + 2 * (xh as nat));
        assert(gf_model::xor(x as nat, y as nat) == xl as nat + 2 * (xh as nat));
    }
}

// Lift 128 -> 256 (tau_tower(128) = 2^125). GF(2^256) has no native u256, the
// element is the (lo, hi) pair of u128 limbs; the ensures packs it as lo + 2^128·hi.
proof fn bridge256(alo: u128, ahi: u128, blo: u128, bhi: u128)
    ensures
        (schoolbook256(alo, ahi, blo, bhi).0 as nat) + gf_model::pow2(128) * (schoolbook256(
            alo,
            ahi,
            blo,
            bhi,
        ).1 as nat) == gf_mul_tower(
            (alo as nat) + gf_model::pow2(128) * (ahi as nat),
            (blo as nat) + gf_model::pow2(128) * (bhi as nat),
            256,
        ),
{
    assert(gf_model::pow2(128) == 0x1_0000_0000_0000_0000_0000_0000_0000_0000) by (compute);
    assert((alo as nat) < gf_model::pow2(128));
    assert((blo as nat) < gf_model::pow2(128));

    gf_model::pack_mod_div(alo as nat, ahi as nat, 128);
    gf_model::pack_mod_div(blo as nat, bhi as nat, 128);

    bridge128(alo, blo);
    bridge128(alo, bhi);
    bridge128(ahi, blo);
    bridge128(ahi, bhi);
    bridge128(schoolbook128(ahi, bhi), 0x2000_0000_0000_0000_0000_0000_0000_0000);

    assert(gf_model::tau_tower(128) == 0x2000_0000_0000_0000_0000_0000_0000_0000) by (compute);

    xor128(
        schoolbook128(alo, blo),
        schoolbook128(schoolbook128(ahi, bhi), 0x2000_0000_0000_0000_0000_0000_0000_0000),
    );
    xor128(schoolbook128(alo, bhi), schoolbook128(ahi, blo));
    xor128(schoolbook128(alo, bhi) ^ schoolbook128(ahi, blo), schoolbook128(ahi, bhi));
}

fn main() {}

}
