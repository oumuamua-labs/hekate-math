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

//! Twins of the constant-time basis-conversion kernels:
//! `map_ct_{8,16,32,64}`, `map_ct_128_split`, and `lift_ct`
//! (src/towers/block*.rs). Each masked-accumulation loop is
//! proven to compute `bit_comb`, the XOR of `basis[i]` over
//! the set bits of the input, which is φ on the model columns
//! (`phi_is_bit_comb`). `mul_iso_N` and the non-aarch64
//! multiply fallback are composition lemmas over the twins.

use vstd::prelude::*;

#[path = "bridge.rs"]
pub mod bridge;

use bridge::gf_model::{
    bit_comb, bit_comb_additive, deg_lt_conv, deg_xor_lt, gf_mul, gf_mul_tower, gf_mul_tower_bound,
    gf_mul_tower_distrib_l, gf_mul_tower_distrib_r, in_field, phi, phi_additive, phi_columns,
    phi_inv_columns, phi_inv_is_bit_comb, phi_is_bit_comb, phi_multiplicative, phi_roundtrip, pow2,
    pow2_add, pow2_pos, tau_tower, thi, tlo, xor, xor_assoc, xor_bit_at, xor_bits, xor_comm,
    xor_self, xor_zero,
};
use bridge::{
    pow2_bridge, u128_pack, xor8_reflect, xor16_reflect, xor32_reflect, xor64_reflect,
    xor128_reflect,
};
use vstd::arithmetic::div_mod::{lemma_div_denominator, lemma_fundamental_div_mod};
use vstd::bits::lemma_u64_shr_is_div;

verus! {

// One loop step of every map_ct kernel: the extracted bit is
// the quotient bit, and the mask select is the basis gate.
proof fn bit_gate_u64(x: u64, i: u64)
    requires i < 64,
    ensures
        ((x >> i) & 1) as nat == ((x as nat) / pow2(i as nat)) % 2,
        ((x >> i) & 1) == 0 || ((x >> i) & 1) == 1,
{
    lemma_u64_shr_is_div(x, i);
    pow2_bridge(i as nat);

    assert(((x >> i) & 1) == (x >> i) % 2) by (bit_vector);
}

// u128 form of the same gate (vstd's shr lemma stops at u64).
pub proof fn u128_shr_div(x: u128, i: u128)
    requires i < 128,
    ensures (x >> i) as nat == (x as nat) / pow2(i as nat)
    decreases i
{
    if i == 0 {
        assert(pow2(0) == 1) by (compute);
        assert(x >> 0 == x) by (bit_vector);
    } else {
        u128_shr_div(x, (i - 1) as u128);

        assert(sub(i, 1u128) == (i - 1) as u128) by (bit_vector) requires 0 < i < 128u128;
        assert(x >> i == (x >> sub(i, 1u128)) >> 1) by (bit_vector) requires 0 < i < 128u128;
        assert((x >> sub(i, 1u128)) >> 1 == ((x >> sub(i, 1u128)) / 2)) by (bit_vector);

        bridge::gf_model::pow2_pos((i - 1) as nat);
        vstd::arithmetic::div_mod::lemma_div_denominator(
            x as int,
            pow2((i - 1) as nat) as int,
            2,
        );

        assert(pow2(i as nat) == pow2((i - 1) as nat) * 2) by {
            vstd::arithmetic::mul::lemma_mul_is_commutative(2, pow2((i - 1) as nat) as int);
        }
    }
}

proof fn bit_gate_u128(x: u128, i: u128)
    requires i < 128,
    ensures
        ((x >> i) & 1) as nat == ((x as nat) / pow2(i as nat)) % 2,
        ((x >> i) & 1) == 0 || ((x >> i) & 1) == 1,
{
    u128_shr_div(x, i);

    assert(((x >> i) & 1) == (x >> i) % 2) by (bit_vector);
}

// ============================================================
// map_ct twins: the masked accumulation computes bit_comb
// (block8.rs, block16.rs, block32.rs, block64.rs, block128.rs)
// ============================================================

fn map_ct_8_twin(x: u8, basis: &[u8; 8]) -> (r: u8)
    ensures r as nat == bit_comb(x as nat, basis@.map_values(|v: u8| v as nat), 8)
{
    let ghost s = basis@.map_values(|v: u8| v as nat);

    let mut acc: u8 = 0;
    let mut i: usize = 0;

    while i < 8
        invariant
            i <= 8,
            s == basis@.map_values(|v: u8| v as nat),
            acc as nat == bit_comb(x as nat, s, i as nat),
        decreases 8 - i,
    {
        let bit = (x >> i) & 1;
        let mask = 0u8.wrapping_sub(bit);
        let bv = basis[i];
        let gated = bv & mask;

        proof {
            bit_gate_u64(x as u64, i as u64);

            assert(((x as u64) >> (i as u64)) & 1 == ((x >> i) & 1) as u64) by (bit_vector)
                requires i < 8usize;
            assert(gated == (if bit == 1 { bv } else { 0u8 })) by (bit_vector)
                requires gated == bv & (0u8.wrapping_sub(bit)), bit < 2u8;
            assert(s[i as int] == bv as nat);

            xor8_reflect(acc, gated);
        }

        acc ^= gated;
        i += 1;
    }

    acc
}

fn map_ct_16_twin(x: u16, basis: &[u16; 16]) -> (r: u16)
    ensures r as nat == bit_comb(x as nat, basis@.map_values(|v: u16| v as nat), 16)
{
    let ghost s = basis@.map_values(|v: u16| v as nat);

    let mut acc: u16 = 0;
    let mut i: usize = 0;

    while i < 16
        invariant
            i <= 16,
            s == basis@.map_values(|v: u16| v as nat),
            acc as nat == bit_comb(x as nat, s, i as nat),
        decreases 16 - i,
    {
        let bit = (x >> i) & 1;
        let mask = 0u16.wrapping_sub(bit);
        let bv = basis[i];
        let gated = bv & mask;

        proof {
            bit_gate_u64(x as u64, i as u64);

            assert(((x as u64) >> (i as u64)) & 1 == ((x >> i) & 1) as u64) by (bit_vector)
                requires i < 16usize;
            assert(gated == (if bit == 1 { bv } else { 0u16 })) by (bit_vector)
                requires gated == bv & (0u16.wrapping_sub(bit)), bit < 2u16;
            assert(s[i as int] == bv as nat);

            xor16_reflect(acc, gated);
        }

        acc ^= gated;
        i += 1;
    }

    acc
}

fn map_ct_32_twin(x: u32, basis: &[u32; 32]) -> (r: u32)
    ensures r as nat == bit_comb(x as nat, basis@.map_values(|v: u32| v as nat), 32)
{
    let ghost s = basis@.map_values(|v: u32| v as nat);

    let mut acc: u32 = 0;
    let mut i: usize = 0;

    while i < 32
        invariant
            i <= 32,
            s == basis@.map_values(|v: u32| v as nat),
            acc as nat == bit_comb(x as nat, s, i as nat),
        decreases 32 - i,
    {
        let bit = (x >> i) & 1;
        let mask = 0u32.wrapping_sub(bit);
        let bv = basis[i];
        let gated = bv & mask;

        proof {
            bit_gate_u64(x as u64, i as u64);

            assert(((x as u64) >> (i as u64)) & 1 == ((x >> i) & 1) as u64) by (bit_vector)
                requires i < 32usize;
            assert(gated == (if bit == 1 { bv } else { 0u32 })) by (bit_vector)
                requires gated == bv & (0u32.wrapping_sub(bit)), bit < 2u32;
            assert(s[i as int] == bv as nat);

            xor32_reflect(acc, gated);
        }

        acc ^= gated;
        i += 1;
    }

    acc
}

fn map_ct_64_twin(x: u64, basis: &[u64; 64]) -> (r: u64)
    ensures r as nat == bit_comb(x as nat, basis@.map_values(|v: u64| v as nat), 64)
{
    let ghost s = basis@.map_values(|v: u64| v as nat);

    let mut acc: u64 = 0;
    let mut i: usize = 0;

    while i < 64
        invariant
            i <= 64,
            s == basis@.map_values(|v: u64| v as nat),
            acc as nat == bit_comb(x as nat, s, i as nat),
        decreases 64 - i,
    {
        let bit = (x >> i) & 1;
        let mask = 0u64.wrapping_sub(bit);
        let bv = basis[i];
        let gated = bv & mask;

        proof {
            bit_gate_u64(x, i as u64);

            assert(gated == (if bit == 1 { bv } else { 0u64 })) by (bit_vector)
                requires gated == bv & (0u64.wrapping_sub(bit)), bit < 2u64;
            assert(s[i as int] == bv as nat);

            xor64_reflect(acc, gated);
        }

        acc ^= gated;
        i += 1;
    }

    acc
}

// block128.rs: the accumulator is split into two
// u64 halves; the packed view carries the invariant.
fn map_ct_128_split_twin(x: u128, basis: &[u128; 128]) -> (r: u128)
    ensures r as nat == bit_comb(x as nat, basis@.map_values(|v: u128| v as nat), 128)
{
    let ghost s = basis@.map_values(|v: u128| v as nat);

    let mut acc_lo: u64 = 0;
    let mut acc_hi: u64 = 0;
    let mut i: usize = 0;

    proof {
        assert(((0u64 as u128) | ((0u64 as u128) << 64)) == 0) by (bit_vector);
    }

    while i < 128
        invariant
            i <= 128,
            s == basis@.map_values(|v: u128| v as nat),
            (((acc_lo as u128) | ((acc_hi as u128) << 64)) as nat)
                == bit_comb(x as nat, s, i as nat),
        decreases 128 - i,
    {
        let bit = ((x >> i) & 1) as u64;
        let mask = 0u64.wrapping_sub(bit);
        let b = basis[i];

        let ghost old_lo = acc_lo;
        let ghost old_hi = acc_hi;

        proof {
            bit_gate_u128(x, i as u128);

            assert((x >> (i as u128)) == (x >> i)) by (bit_vector) requires i < 128usize;

            // The split masked update is the packed
            // update by the duplicated mask.
            let m = 0u64.wrapping_sub(bit);

            assert(((old_lo ^ ((b as u64) & m)) as u128)
                | (((old_hi ^ (((b >> 64) as u64) & m)) as u128) << 64)
                == ((old_lo as u128) | ((old_hi as u128) << 64))
                    ^ (b & ((m as u128) | ((m as u128) << 64)))) by (bit_vector);
            assert(b & ((m as u128) | ((m as u128) << 64))
                == (if bit == 1 { b } else { 0u128 })) by (bit_vector)
                requires m == 0u64.wrapping_sub(bit), bit < 2u64;
            assert(s[i as int] == basis[i as int] as nat);

            xor128_reflect(
                (old_lo as u128) | ((old_hi as u128) << 64),
                b & ((m as u128) | ((m as u128) << 64)),
            );
        }

        acc_lo ^= (b as u64) & mask;
        acc_hi ^= ((b >> 64) as u64) & mask;
        i += 1;
    }

    (acc_lo as u128) | ((acc_hi as u128) << 64)
}

// lift_ct, block128.rs: the promote kernels' scalar
// core, same masked accumulation over the lifting basis.
fn lift_ct_twin(x: u64, basis: &[u128]) -> (r: u128)
    requires basis@.len() <= 64,
    ensures r as nat == bit_comb(x as nat, basis@.map_values(|v: u128| v as nat), basis@.len())
{
    let ghost s = basis@.map_values(|v: u128| v as nat);
    let n = basis.len();

    let mut acc: u128 = 0;
    let mut i: usize = 0;

    while i < n
        invariant
            i <= n,
            n == basis@.len() <= 64,
            s == basis@.map_values(|v: u128| v as nat),
            acc as nat == bit_comb(x as nat, s, i as nat),
        decreases n - i,
    {
        let bit = (x >> i) & 1;
        let mask = 0u128.wrapping_sub(bit as u128);
        let bv = basis[i];
        let gated = bv & mask;

        proof {
            bit_gate_u64(x, i as u64);

            assert(gated == (if bit == 1 { bv } else { 0u128 })) by (bit_vector)
                requires
                    gated == bv & (0u128.wrapping_sub(bit as u128)),
                    bit < 2u64;
            assert(s[i as int] == bv as nat);

            xor128_reflect(acc, gated);
        }

        acc ^= gated;
        i += 1;
    }

    acc
}

fn lift_ct_16_twin(x: u16, basis: &[u16]) -> (r: u16)
    requires basis@.len() <= 16,
    ensures r as nat == bit_comb(x as nat, basis@.map_values(|v: u16| v as nat), basis@.len())
{
    let ghost s = basis@.map_values(|v: u16| v as nat);
    let n = basis.len();

    let mut acc: u16 = 0;
    let mut i: usize = 0;

    while i < n
        invariant
            i <= n,
            n == basis@.len() <= 16,
            s == basis@.map_values(|v: u16| v as nat),
            acc as nat == bit_comb(x as nat, s, i as nat),
        decreases n - i,
    {
        let bit = (x >> i) & 1;
        let mask = 0u16.wrapping_sub(bit);
        let bv = basis[i];
        let gated = bv & mask;

        proof {
            bit_gate_u64(x as u64, i as u64);

            assert(((x as u64) >> (i as u64)) & 1 == ((x >> i) & 1) as u64) by (bit_vector)
                requires i < 16usize;
            assert(gated == (if bit == 1 { bv } else { 0u16 })) by (bit_vector)
                requires gated == bv & (0u16.wrapping_sub(bit)), bit < 2u16;
            assert(s[i as int] == bv as nat);

            xor16_reflect(acc, gated);
        }

        acc ^= gated;
        i += 1;
    }

    acc
}

fn lift_ct_32_twin(x: u32, basis: &[u32]) -> (r: u32)
    requires basis@.len() <= 32,
    ensures r as nat == bit_comb(x as nat, basis@.map_values(|v: u32| v as nat), basis@.len())
{
    let ghost s = basis@.map_values(|v: u32| v as nat);
    let n = basis.len();

    let mut acc: u32 = 0;
    let mut i: usize = 0;

    while i < n
        invariant
            i <= n,
            n == basis@.len() <= 32,
            s == basis@.map_values(|v: u32| v as nat),
            acc as nat == bit_comb(x as nat, s, i as nat),
        decreases n - i,
    {
        let bit = (x >> i) & 1;
        let mask = 0u32.wrapping_sub(bit);
        let bv = basis[i];
        let gated = bv & mask;

        proof {
            bit_gate_u64(x as u64, i as u64);

            assert(((x as u64) >> (i as u64)) & 1 == ((x >> i) & 1) as u64) by (bit_vector)
                requires i < 32usize;
            assert(gated == (if bit == 1 { bv } else { 0u32 })) by (bit_vector)
                requires gated == bv & (0u32.wrapping_sub(bit)), bit < 2u32;
            assert(s[i as int] == bv as nat);

            xor32_reflect(acc, gated);
        }

        acc ^= gated;
        i += 1;
    }

    acc
}

fn lift_ct_64_twin(x: u64, basis: &[u64]) -> (r: u64)
    requires basis@.len() <= 64,
    ensures r as nat == bit_comb(x as nat, basis@.map_values(|v: u64| v as nat), basis@.len())
{
    let ghost s = basis@.map_values(|v: u64| v as nat);
    let n = basis.len();

    let mut acc: u64 = 0;
    let mut i: usize = 0;

    while i < n
        invariant
            i <= n,
            n == basis@.len() <= 64,
            s == basis@.map_values(|v: u64| v as nat),
            acc as nat == bit_comb(x as nat, s, i as nat),
        decreases n - i,
    {
        let bit = (x >> i) & 1;
        let mask = 0u64.wrapping_sub(bit);
        let bv = basis[i];
        let gated = bv & mask;

        proof {
            bit_gate_u64(x, i as u64);

            assert(gated == (if bit == 1 { bv } else { 0u64 })) by (bit_vector)
                requires gated == bv & (0u64.wrapping_sub(bit)), bit < 2u64;
            assert(s[i as int] == bv as nat);

            xor64_reflect(acc, gated);
        }

        acc ^= gated;
        i += 1;
    }

    acc
}

// ============================================================
// tower_bit_from_hardware: parity(v & row_k) is bit
// k of the column map (block{8,16,32,64,128}.rs).
// ============================================================

pub open spec fn bit(x: nat, j: nat) -> nat {
    (x / pow2(j)) % 2
}

pub open spec fn ones(n: nat) -> Seq<nat> {
    Seq::new(n, |j: int| 1nat)
}

pub open spec fn par(x: nat, n: nat) -> nat {
    bit_comb(x, ones(n), n)
}

pub open spec fn row(cols: Seq<nat>, k: nat, n: nat) -> Seq<nat> {
    Seq::new(n, |j: int| bit(cols[j], k))
}

pub open spec fn mask_bits(m: nat, n: nat) -> Seq<nat> {
    Seq::new(n, |j: int| bit(m, j as nat))
}

proof fn xor01(p: nat, q: nat)
    requires p < 2, q < 2
    ensures xor(p, q) == (p + q) % 2, xor(p, q) < 2
{
    xor_bits(p, q);
    xor_zero(0);

    lemma_fundamental_div_mod(xor(p, q) as int, 2);
}

proof fn bit_comb_01(v: nat, s: Seq<nat>, n: nat)
    requires forall|j: int| 0 <= j < n ==> #[trigger] s[j] < 2
    ensures bit_comb(v, s, n) < 2
    decreases n
{
    if n == 0 {
    } else {
        let m = (n - 1) as nat;
        let g: nat = if (v / pow2(m)) % 2 == 1 { s[m as int] } else { 0 };

        bit_comb_01(v, s, m);
        xor01(bit_comb(v, s, m), g);
    }
}

proof fn bit_comb_prefix(v: nat, s1: Seq<nat>, s2: Seq<nat>, n: nat)
    requires forall|j: int| 0 <= j < n ==> #[trigger] s1[j] == s2[j]
    ensures bit_comb(v, s1, n) == bit_comb(v, s2, n)
    decreases n
{
    if n == 0 {
    } else {
        bit_comb_prefix(v, s1, s2, (n - 1) as nat);
    }
}

proof fn bit_comb_input(x: nat, y: nat, s: Seq<nat>, n: nat)
    requires forall|j: nat| j < n ==> #[trigger] bit(x, j) == bit(y, j)
    ensures bit_comb(x, s, n) == bit_comb(y, s, n)
    decreases n
{
    if n == 0 {
    } else {
        let m = (n - 1) as nat;

        bit_comb_input(x, y, s, m);
        assert(bit(x, m) == bit(y, m));
    }
}

proof fn bit_comb_bit(v: nat, cols: Seq<nat>, n: nat, k: nat)
    ensures bit(bit_comb(v, cols, n), k) == bit_comb(v, row(cols, k, n), n)
    decreases n
{
    pow2_pos(k);

    if n == 0 {
    } else {
        let m = (n - 1) as nat;
        let a = bit_comb(v, cols, m);
        let g: nat = if (v / pow2(m)) % 2 == 1 { cols[m as int] } else { 0 };

        bit_comb_bit(v, cols, m, k);
        bit_comb_prefix(v, row(cols, k, n), row(cols, k, m), m);

        xor_bit_at(a, g, k);

        assert forall|j: int| 0 <= j < m implies #[trigger] row(cols, k, m)[j] < 2 by {
        }

        bit_comb_01(v, row(cols, k, m), m);
        xor01(bit(a, k), bit(g, k));
    }
}

proof fn par_add(x: nat, a: nat, b: nat)
    ensures par(x, a + b) == xor(par(x, a), par(x / pow2(a), b))
    decreases b
{
    pow2_pos(a);

    if b == 0 {
        xor_zero(par(x, a));
    } else {
        let b1 = (b - 1) as nat;
        let g: nat = if (x / pow2(a + b1)) % 2 == 1 { 1 } else { 0 };

        pow2_pos(a + b1);
        par_add(x, a, b1);
        bit_comb_prefix(x, ones(a + b), ones(a + b1), a + b1);
        bit_comb_prefix(x / pow2(a), ones(b), ones(b1), b1);

        pow2_pos(a);
        pow2_pos(b1);

        lemma_div_denominator(x as int, pow2(a) as int, pow2(b1) as int);

        pow2_add(a, b1);

        assert((x / pow2(a)) / pow2(b1) == x / pow2(a + b1));
        assert(par(x, a + b) == xor(par(x, a + b1), g));
        assert(par(x / pow2(a), b) == xor(par(x / pow2(a), b1), g));

        xor_assoc(par(x, a), par(x / pow2(a), b1), g);

        assert(par(x, a + b) == xor(xor(par(x, a), par(x / pow2(a), b1)), g));
        assert(par(x, a + b) == xor(par(x, a), xor(par(x / pow2(a), b1), g)));
    }
}

proof fn par_and64(v: u64, m: u64, n: nat)
    requires n <= 64
    ensures par((v & m) as nat, n) == bit_comb(v as nat, mask_bits(m as nat, n), n)
    decreases n
{
    if n == 0 {
    } else {
        let j = (n - 1) as nat;

        par_and64(v, m, j);
        bit_comb_prefix((v & m) as nat, ones(n), ones(j), j);
        bit_comb_prefix(v as nat, mask_bits(m as nat, n), mask_bits(m as nat, j), j);

        let ju = j as u64;
        let bv = (v >> ju) & 1;
        let bm = (m >> ju) & 1;
        let bvm = ((v & m) >> ju) & 1;

        pow2_pos(j);

        bit_gate_u64(v & m, ju);
        bit_gate_u64(v, ju);
        bit_gate_u64(m, ju);

        assert(bvm == (if bv == 1 && bm == 1 { 1u64 } else { 0u64 })) by (bit_vector)
            requires
                ju < 64,
                bv == (v >> ju) & 1,
                bm == (m >> ju) & 1,
                bvm == ((v & m) >> ju) & 1,
        ;

        assert(par((v & m) as nat, n) == xor(
            bit_comb((v & m) as nat, ones(n), j),
            if bit((v & m) as nat, j) == 1 { 1nat } else { 0nat },
        ));
        assert(bit_comb(v as nat, mask_bits(m as nat, n), n) == xor(
            bit_comb(v as nat, mask_bits(m as nat, n), j),
            if bit(v as nat, j) == 1 { bit(m as nat, j) } else { 0nat },
        ));
    }
}

proof fn par_and128(v: u128, m: u128, n: nat)
    requires n <= 128
    ensures par((v & m) as nat, n) == bit_comb(v as nat, mask_bits(m as nat, n), n)
    decreases n
{
    if n == 0 {
    } else {
        let j = (n - 1) as nat;

        par_and128(v, m, j);
        bit_comb_prefix((v & m) as nat, ones(n), ones(j), j);
        bit_comb_prefix(v as nat, mask_bits(m as nat, n), mask_bits(m as nat, j), j);

        let ju = j as u128;
        let bv = (v >> ju) & 1;
        let bm = (m >> ju) & 1;
        let bvm = ((v & m) >> ju) & 1;

        pow2_pos(j);

        bit_gate_u128(v & m, ju);
        bit_gate_u128(v, ju);
        bit_gate_u128(m, ju);

        assert(bvm == (if bv == 1 && bm == 1 { 1u128 } else { 0u128 })) by (bit_vector)
            requires
                ju < 128,
                bv == (v >> ju) & 1,
                bm == (m >> ju) & 1,
                bvm == ((v & m) >> ju) & 1,
        ;

        assert(par((v & m) as nat, n) == xor(
            bit_comb((v & m) as nat, ones(n), j),
            if bit((v & m) as nat, j) == 1 { 1nat } else { 0nat },
        ));
        assert(bit_comb(v as nat, mask_bits(m as nat, n), n) == xor(
            bit_comb(v as nat, mask_bits(m as nat, n), j),
            if bit(v as nat, j) == 1 { bit(m as nat, j) } else { 0nat },
        ));
    }
}

pub proof fn parity_row_is_bit64(v: u64, mask: u64, cols: Seq<nat>, k: nat, n: nat)
    requires
        n <= 64,
        forall|j: int| 0 <= j < n ==> #[trigger] bit(mask as nat, j as nat) == bit(cols[j], k),
    ensures par((v & mask) as nat, n) == bit(bit_comb(v as nat, cols, n), k)
{
    par_and64(v, mask, n);
    bit_comb_bit(v as nat, cols, n, k);
    bit_comb_prefix(v as nat, mask_bits(mask as nat, n), row(cols, k, n), n);
}

pub proof fn parity_row_is_bit128(v: u128, mask: u128, cols: Seq<nat>, k: nat)
    requires
        forall|j: int| 0 <= j < 128 ==> #[trigger] bit(mask as nat, j as nat) == bit(cols[j], k),
    ensures par((v & mask) as nat, 128) == bit(bit_comb(v as nat, cols, 128), k)
{
    par_and128(v, mask, 128);
    bit_comb_bit(v as nat, cols, 128, k);
    bit_comb_prefix(v as nat, mask_bits(mask as nat, 128), row(cols, k, 128), 128);
}

proof fn par_one(x: nat)
    ensures par(x, 1) == x % 2
{
    assert(pow2(0) == 1) by (compute);

    pow2_pos(0);

    assert(ones(1)[0] == 1);
    assert(x / pow2(0) == x);
    assert(bit_comb(x, ones(1), 0) == 0);
    assert(par(x, 1) == xor(0, if x % 2 == 1 { 1nat } else { 0nat }));

    xor_zero(if x % 2 == 1 { 1nat } else { 0nat });
}

proof fn stage64(w: u64, m: u64)
    requires 0 < m, 2 * m <= 64
    ensures par((w ^ (w >> m)) as nat, m as nat) == par(w as nat, 2 * (m as nat))
{
    xor64_reflect(w, w >> m);
    lemma_u64_shr_is_div(w, m);
    pow2_bridge(m as nat);
    par_add(w as nat, m as nat, m as nat);
    bit_comb_additive(w as nat, (w >> m) as nat, ones(m as nat), m as nat);
}

proof fn stage128(w: u128, m: u128)
    requires 0 < m, 2 * m <= 128
    ensures par((w ^ (w >> m)) as nat, m as nat) == par(w as nat, 2 * (m as nat))
{
    xor128_reflect(w, w >> m);
    u128_shr_div(w, m);
    par_add(w as nat, m as nat, m as nat);
    bit_comb_additive(w as nat, (w >> m) as nat, ones(m as nat), m as nat);
}

fn tower_bit_8_twin(v: u8, mask: u8) -> (r: u8)
    ensures r as nat == par((v & mask) as nat, 8)
{
    let w0 = v & mask;
    let w1 = w0 ^ (w0 >> 4);
    let w2 = w1 ^ (w1 >> 2);
    let w3 = w2 ^ (w2 >> 1);

    proof {
        assert((w0 as u64) ^ ((w0 as u64) >> 4) == w1 as u64) by (bit_vector)
            requires w1 == w0 ^ (w0 >> 4);
        assert((w1 as u64) ^ ((w1 as u64) >> 2) == w2 as u64) by (bit_vector)
            requires w2 == w1 ^ (w1 >> 2);
        assert((w2 as u64) ^ ((w2 as u64) >> 1) == w3 as u64) by (bit_vector)
            requires w3 == w2 ^ (w2 >> 1);

        stage64(w0 as u64, 4);
        stage64(w1 as u64, 2);
        stage64(w2 as u64, 1);
        par_one(w3 as nat);

        assert(w3 & 1 == w3 % 2) by (bit_vector);
    }

    w3 & 1
}

fn tower_bit_16_twin(v: u16, mask: u16) -> (r: u8)
    ensures r as nat == par((v & mask) as nat, 16)
{
    let w0 = v & mask;
    let w1 = w0 ^ (w0 >> 8);
    let w2 = w1 ^ (w1 >> 4);
    let w3 = w2 ^ (w2 >> 2);
    let w4 = w3 ^ (w3 >> 1);

    proof {
        assert((w0 as u64) ^ ((w0 as u64) >> 8) == w1 as u64) by (bit_vector)
            requires w1 == w0 ^ (w0 >> 8);
        assert((w1 as u64) ^ ((w1 as u64) >> 4) == w2 as u64) by (bit_vector)
            requires w2 == w1 ^ (w1 >> 4);
        assert((w2 as u64) ^ ((w2 as u64) >> 2) == w3 as u64) by (bit_vector)
            requires w3 == w2 ^ (w2 >> 2);
        assert((w3 as u64) ^ ((w3 as u64) >> 1) == w4 as u64) by (bit_vector)
            requires w4 == w3 ^ (w3 >> 1);

        stage64(w0 as u64, 8);
        stage64(w1 as u64, 4);
        stage64(w2 as u64, 2);
        stage64(w3 as u64, 1);
        par_one(w4 as nat);

        assert(w4 & 1 == w4 % 2) by (bit_vector);
    }

    (w4 & 1) as u8
}

fn tower_bit_32_twin(v: u32, mask: u32) -> (r: u8)
    ensures r as nat == par((v & mask) as nat, 32)
{
    let w0 = v & mask;
    let w1 = w0 ^ (w0 >> 16);
    let w2 = w1 ^ (w1 >> 8);
    let w3 = w2 ^ (w2 >> 4);
    let w4 = w3 ^ (w3 >> 2);
    let w5 = w4 ^ (w4 >> 1);

    proof {
        assert((w0 as u64) ^ ((w0 as u64) >> 16) == w1 as u64) by (bit_vector)
            requires w1 == w0 ^ (w0 >> 16);
        assert((w1 as u64) ^ ((w1 as u64) >> 8) == w2 as u64) by (bit_vector)
            requires w2 == w1 ^ (w1 >> 8);
        assert((w2 as u64) ^ ((w2 as u64) >> 4) == w3 as u64) by (bit_vector)
            requires w3 == w2 ^ (w2 >> 4);
        assert((w3 as u64) ^ ((w3 as u64) >> 2) == w4 as u64) by (bit_vector)
            requires w4 == w3 ^ (w3 >> 2);
        assert((w4 as u64) ^ ((w4 as u64) >> 1) == w5 as u64) by (bit_vector)
            requires w5 == w4 ^ (w4 >> 1);

        stage64(w0 as u64, 16);
        stage64(w1 as u64, 8);
        stage64(w2 as u64, 4);
        stage64(w3 as u64, 2);
        stage64(w4 as u64, 1);
        par_one(w5 as nat);

        assert(w5 & 1 == w5 % 2) by (bit_vector);
    }

    (w5 & 1) as u8
}

fn tower_bit_64_twin(v: u64, mask: u64) -> (r: u8)
    ensures r as nat == par((v & mask) as nat, 64)
{
    let w0 = v & mask;
    let w1 = w0 ^ (w0 >> 32);
    let w2 = w1 ^ (w1 >> 16);
    let w3 = w2 ^ (w2 >> 8);
    let w4 = w3 ^ (w3 >> 4);

    proof {
        assert(w4 & 0xF < 16) by (bit_vector);
    }

    let idx = (w4 & 0xF) as u8;

    proof {
        stage64(w0, 32);
        stage64(w1, 16);
        stage64(w2, 8);
        stage64(w3, 4);

        assert forall|j: nat| j < 4 implies #[trigger] bit(w4 as nat, j) == bit(idx as nat, j) by {
            let ju = j as u64;

            bit_gate_u64(w4, ju);
            bit_gate_u64(idx as u64, ju);

            assert((w4 >> ju) & 1 == ((idx as u64) >> ju) & 1) by (bit_vector)
                requires ju < 4, idx == (w4 & 0xF) as u8;
        }

        bit_comb_input(w4 as nat, idx as nat, ones(4), 4);

        let b0 = bit(idx as nat, 0);
        let b1 = bit(idx as nat, 1);
        let b2 = bit(idx as nat, 2);
        let b3 = bit(idx as nat, 3);

        bit_gate_u64(idx as u64, 0);
        bit_gate_u64(idx as u64, 1);
        bit_gate_u64(idx as u64, 2);
        bit_gate_u64(idx as u64, 3);

        assert(pow2(0) == 1 && pow2(1) == 2 && pow2(2) == 4 && pow2(3) == 8) by (compute);

        pow2_pos(0);
        pow2_pos(1);
        pow2_pos(2);
        pow2_pos(3);

        let s = ones(4);
        let i = idx as nat;

        assert(s[0] == 1 && s[1] == 1 && s[2] == 1 && s[3] == 1);
        assert(bit_comb(i, s, 0) == 0);
        assert(bit_comb(i, s, 1) == xor(bit_comb(i, s, 0), if b0 == 1 { 1nat } else { 0nat }));
        assert(bit_comb(i, s, 2) == xor(bit_comb(i, s, 1), if b1 == 1 { 1nat } else { 0nat }));
        assert(bit_comb(i, s, 3) == xor(bit_comb(i, s, 2), if b2 == 1 { 1nat } else { 0nat }));
        assert(bit_comb(i, s, 4) == xor(bit_comb(i, s, 3), if b3 == 1 { 1nat } else { 0nat }));

        xor_zero(b0);
        xor01(b0, b1);
        xor01((b0 + b1) % 2, b2);
        xor01(((b0 + b1) % 2 + b2) % 2, b3);

        assert(par(i, 4) == (((b0 + b1) % 2 + b2) % 2 + b3) % 2);

        let u = idx as u64;

        assert(u >> 0 == u) by (bit_vector);
        assert(((0x6996u16 >> idx) & 1) as u64 == (0x6996u64 >> u) & 1) by (bit_vector)
            requires u == idx as u64, idx < 16;
        assert((0x6996u64 >> u) & 1 == ((((u & 1) + ((u >> 1) & 1)) % 2 + ((u >> 2) & 1)) % 2 + ((u
            >> 3) & 1)) % 2) by (bit_vector)
            requires u < 16;
    }

    ((0x6996u16 >> idx) & 1) as u8
}

fn tower_bit_128_twin(v: u128, mask: u128) -> (r: u8)
    ensures r as nat == par((v & mask) as nat, 128)
{
    let w0 = v & mask;
    let w1 = w0 ^ (w0 >> 64);
    let w2 = w1 ^ (w1 >> 32);
    let w3 = w2 ^ (w2 >> 16);
    let w4 = w3 ^ (w3 >> 8);
    let w5 = w4 ^ (w4 >> 4);
    let w6 = w5 ^ (w5 >> 2);
    let w7 = w6 ^ (w6 >> 1);

    proof {
        stage128(w0, 64);
        stage128(w1, 32);
        stage128(w2, 16);
        stage128(w3, 8);
        stage128(w4, 4);
        stage128(w5, 2);
        stage128(w6, 1);
        par_one(w7 as nat);

        assert(w7 & 1 == w7 % 2) by (bit_vector);
    }

    (w7 & 1) as u8
}

pub proof fn mul_iso_correct(a: nat, b: nat, t2f: Seq<nat>, f2t: Seq<nat>, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        in_field(a, k),
        in_field(b, k),
        t2f == phi_columns(k),
        f2t == phi_inv_columns(k),
    ensures
        bit_comb(gf_mul(bit_comb(a, t2f, k), bit_comb(b, t2f, k), k), f2t, k)
            == gf_mul_tower(a, b, k)
{
    phi_is_bit_comb(a, k);
    phi_is_bit_comb(b, k);
    phi_multiplicative(a, b, k);
    phi_inv_is_bit_comb(gf_mul(phi(a, k), phi(b, k), k), k);

    gf_mul_tower_bound(a, b, k);
    deg_lt_conv(gf_mul_tower(a, b, k), k);
    phi_roundtrip(gf_mul_tower(a, b, k), k);
}

pub proof fn fallback_mul_correct(x: nat, y: nat, t2f: Seq<nat>, f2t: Seq<nat>, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        in_field(x, k),
        in_field(y, k),
        t2f == phi_columns(k),
        f2t == phi_inv_columns(k),
    ensures
        bit_comb(
            gf_mul_tower(
                bit_comb(bit_comb(x, t2f, k), f2t, k),
                bit_comb(bit_comb(y, t2f, k), f2t, k),
                k,
            ),
            t2f,
            k,
        ) == gf_mul(bit_comb(x, t2f, k), bit_comb(y, t2f, k), k)
{
    phi_is_bit_comb(x, k);
    phi_is_bit_comb(y, k);
    phi_inv_is_bit_comb(phi(x, k), k);
    phi_inv_is_bit_comb(phi(y, k), k);
    phi_roundtrip(x, k);
    phi_roundtrip(y, k);

    phi_is_bit_comb(gf_mul_tower(x, y, k), k);
    phi_multiplicative(x, y, k);
}

// ============================================================
// The flat-256 glue, block256.rs:
// pair-Karatsuba over the flat-128 field is the tower
// quadratic extension seen through φ, half by half.
// ============================================================

pub open spec fn mul_hardware_256_twin(
    a0: nat, a1: nat, b0: nat, b1: nat, tau_flat: nat,
) -> (nat, nat) {
    let v0 = gf_mul(a0, b0, 128);
    let v1 = gf_mul(a1, b1, 128);
    let v_sum = gf_mul(xor(a0, a1), xor(b0, b1), 128);

    (xor(v0, gf_mul(v1, tau_flat, 128)), xor(v0, v_sum))
}

proof fn tower_in_field(x: nat, y: nat)
    requires in_field(x, 128), in_field(y, 128),
    ensures in_field(gf_mul_tower(x, y, 128), 128)
{
    gf_mul_tower_bound(x, y, 128);
    deg_lt_conv(gf_mul_tower(x, y, 128), 128);
}

// p00 ^ (p00 ^ p01 ^ p10 ^ p11) == p01 ^ p10 ^ p11:
// the Karatsuba diagonal cancels.
proof fn karatsuba_cancel(p00: nat, p01: nat, p10: nat, p11: nat)
    ensures xor(p00, xor(xor(p00, p01), xor(p10, p11))) == xor(xor(p01, p10), p11)
{
    xor_assoc(p00, p01, xor(p10, p11));
    xor_assoc(p00, p00, xor(p01, xor(p10, p11)));
    xor_self(p00);
    xor_zero(xor(p01, xor(p10, p11)));
    xor_assoc(p01, p10, p11);
}

proof fn quad_hi_half(x0: nat, x1: nat, y0: nat, y1: nat)
    requires
        in_field(x0, 128),
        in_field(x1, 128),
        in_field(y0, 128),
        in_field(y1, 128),
    ensures xor(
        gf_mul(phi(x0, 128), phi(y0, 128), 128),
        gf_mul(
            xor(phi(x0, 128), phi(x1, 128)),
            xor(phi(y0, 128), phi(y1, 128)),
            128,
        ),
    ) == phi(thi(x0, x1, y0, y1, 128), 128)
{
    let xs = xor(x0, x1);
    let ys = xor(y0, y1);
    let p00 = gf_mul_tower(x0, y0, 128);
    let p01 = gf_mul_tower(x0, y1, 128);
    let p10 = gf_mul_tower(x1, y0, 128);
    let p11 = gf_mul_tower(x1, y1, 128);

    deg_xor_lt(x0, x1, 128);
    deg_xor_lt(y0, y1, 128);
    phi_additive(x0, x1, 128);
    phi_additive(y0, y1, 128);
    phi_multiplicative(x0, y0, 128);
    phi_multiplicative(xs, ys, 128);

    // v_sum's tower pre-image expands to all four products
    gf_mul_tower_distrib_l(x0, x1, ys, 128);
    gf_mul_tower_distrib_r(x0, y0, y1, 128);
    gf_mul_tower_distrib_r(x1, y0, y1, 128);

    karatsuba_cancel(p00, p01, p10, p11);

    tower_in_field(x0, y0);
    tower_in_field(xs, ys);

    phi_additive(p00, gf_mul_tower(xs, ys, 128), 128);
}

proof fn quad_lo_half(x0: nat, x1: nat, y0: nat, y1: nat)
    requires
        in_field(x0, 128),
        in_field(x1, 128),
        in_field(y0, 128),
        in_field(y1, 128),
    ensures xor(
        gf_mul(phi(x0, 128), phi(y0, 128), 128),
        gf_mul(gf_mul(phi(x1, 128), phi(y1, 128), 128), phi(tau_tower(128), 128), 128),
    ) == phi(tlo(x0, x1, y0, y1, 128), 128)
{
    let p00 = gf_mul_tower(x0, y0, 128);
    let p11 = gf_mul_tower(x1, y1, 128);

    assert(in_field(tau_tower(128), 128)) by {
        assert(pow2(128) == 0x1_0000_0000_0000_0000_0000_0000_0000_0000) by (compute);

        deg_lt_conv(tau_tower(128), 128);
    }

    phi_multiplicative(x0, y0, 128);
    phi_multiplicative(x1, y1, 128);

    tower_in_field(x1, y1);

    phi_multiplicative(p11, tau_tower(128), 128);

    tower_in_field(x0, y0);
    tower_in_field(p11, tau_tower(128));

    phi_additive(p00, gf_mul_tower(p11, tau_tower(128), 128), 128);
}

// With TAU_FLAT == φ(tau_tower(128)), the build-checked constant
// row, the production Karatsuba computes φ(tlo), φ(thi) of the
// tower halves: the pair extension is the image of the tower field.
pub proof fn mul_hardware_256_correct(x0: nat, x1: nat, y0: nat, y1: nat)
    requires
        in_field(x0, 128),
        in_field(x1, 128),
        in_field(y0, 128),
        in_field(y1, 128),
    ensures ({
        let r = mul_hardware_256_twin(
            phi(x0, 128), phi(x1, 128), phi(y0, 128), phi(y1, 128),
            phi(tau_tower(128), 128),
        );

        r.0 == phi(tlo(x0, x1, y0, y1, 128), 128) && r.1 == phi(thi(x0, x1, y0, y1, 128), 128)
    })
{
    quad_lo_half(x0, x1, y0, y1);
    quad_hi_half(x0, x1, y0, y1);
}

fn main() {
}

} // verus!
