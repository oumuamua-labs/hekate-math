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

//! Twins of the scalar NEON flat multiplies (src/towers/
//! block{8,16,32,64,128}.rs `mod neon`), each proven equal to
//! `gf_model::gf_mul` at its width. The twins transcribe the
//! production dataflow over the instruction model; every
//! PMULL becomes `clmul` through the bridge, every fold is
//! `fold_step`, and the residual-degree arguments that let
//! the kernels drop high lanes become theorems.

use vstd::prelude::*;

#[path = "bridge.rs"]
pub mod bridge;

use bridge::gf_model::{
    clmul, clmul_distrib_l, clmul_zero_r, deg_clmul, deg_lt_conv, deg_upper, gf_mul,
    lo_plus_hipart_is_xor, pow2, pow2_add, pow2_mono, pow2_pos, xor, xor_assoc, xor_comm,
    xor_lt_pow2, xor_mul_pow2, xor_rearrange4,
};
use bridge::neon_model::{clmul8_lane, hi8, hi64, lo8, lo64, vdup_m8, vmull_p8_m, vmull_p64_m};
use bridge::{
    clmul_bound, clmul_shift_limb, clmul8_bridge, clmul64_bridge, fold_step, pmod_below, r_poly,
    schoolbook_clmul, u128_pack, u128_split, xor8_reflect, xor16_reflect, xor32_reflect,
    xor64_reflect, xor128_reflect,
};
use vstd::arithmetic::mul::{
    lemma_mul_is_associative, lemma_mul_is_commutative, lemma_mul_strict_inequality,
};

verus! {

// ============================================================
// Width and split helpers
// ============================================================

// The u128 lane-0 read is total below 2^64.
proof fn lo64_total(x: u128)
    requires x < 0x1_0000_0000_0000_0000,
    ensures lo64(x) as nat == x as nat
{
    assert((x as u64) as u128 == x) by (bit_vector)
        requires x < 0x1_0000_0000_0000_0000u128;
}

proof fn u64_split16(x: u64)
    requires x < 0x1_0000_0000,
    ensures
        x as nat == xor(((x & 0xFFFF) as u16) as nat, pow2(16) * (((x >> 16) as u16) as nat)),
        (((x & 0xFFFF) as u16) as nat) < pow2(16),
        (((x >> 16) as u16) as nat) < pow2(16),
{
    assert(pow2(16) == 0x10000) by (compute);
    assert(x == ((x & 0xFFFF) as u16) as u64 + 0x10000 * (((x >> 16) as u16) as u64) &&
        (((x & 0xFFFF) as u16) as u64) < 0x10000 &&
        (((x >> 16) as u16) as u64) < 0x10000) by (bit_vector)
        requires x < 0x1_0000_0000u64;

    lo_plus_hipart_is_xor(16, ((x & 0xFFFF) as u16) as nat, ((x >> 16) as u16) as nat);
}

proof fn u64_split32(x: u64)
    ensures
        x as nat == xor(
            ((x & 0xFFFF_FFFF) as u32) as nat,
            pow2(32) * (((x >> 32) as u32) as nat),
        ),
        (((x & 0xFFFF_FFFF) as u32) as nat) < pow2(32),
        (((x >> 32) as u32) as nat) < pow2(32),
{
    assert(pow2(32) == 0x1_0000_0000) by (compute);
    assert(x == ((x & 0xFFFF_FFFF) as u32) as u64 + 0x1_0000_0000 * (((x >> 32) as u32) as u64) &&
        (((x & 0xFFFF_FFFF) as u32) as u64) < 0x1_0000_0000 &&
        (((x >> 32) as u32) as u64) < 0x1_0000_0000) by (bit_vector);

    lo_plus_hipart_is_xor(32, ((x & 0xFFFF_FFFF) as u32) as nat, ((x >> 32) as u32) as nat);
}

pub proof fn u16_split8(x: u16)
    ensures
        x as nat == xor((lo8(x)) as nat, pow2(8) * ((hi8(x)) as nat)),
        ((lo8(x)) as nat) < pow2(8),
        ((hi8(x)) as nat) < pow2(8),
{
    assert(pow2(8) == 0x100) by (compute);
    assert(x == (x as u8) as u16 + 0x100 * (((x >> 8) as u8) as u16) &&
        ((x as u8) as u16) < 0x100 &&
        (((x >> 8) as u8) as u16) < 0x100) by (bit_vector);

    lo_plus_hipart_is_xor(8, (x as u8) as nat, ((x >> 8) as u8) as nat);
}

// ============================================================
// mul_flat_16, block16.rs:605-643
// ============================================================

pub open spec fn mul_flat_16_twin(a: u16, b: u16) -> u16 {
    let prod = lo64(vmull_p64_m(a as u64, b as u64));
    let l = (prod & 0xFFFF) as u16;
    let h = (prod >> 16) as u16;

    let h_red = lo64(vmull_p64_m(h as u64, 0x2b));
    let folded = (h_red & 0xFFFF) as u16;
    let carry = (h_red >> 16) as u16;

    let c_red = lo64(vmull_p64_m(carry as u64, 0x2b));

    (l ^ folded) ^ (c_red as u16)
}

pub proof fn mul_flat_16_correct(a: u16, b: u16)
    ensures mul_flat_16_twin(a, b) as nat == gf_mul(a as nat, b as nat, 16)
{
    assert(pow2(16) == 0x10000) by (compute);
    assert(pow2(31) == 0x8000_0000) by (compute);
    assert(pow2(6) == 0x40) by (compute);
    assert(pow2(15) == 0x8000) by (compute);
    assert(pow2(20) == 0x10_0000) by (compute);
    assert(pow2(4) == 0x10) by (compute);
    assert(pow2(9) == 0x200) by (compute);

    // Product: PMULL is clmul, degree < 31.
    clmul64_bridge(a as u64, b as u64);
    clmul_bound(a as nat, b as nat, 16, 16);

    let pr = vmull_p64_m(a as u64, b as u64);
    let prn = clmul(a as nat, b as nat);

    lo64_total(pr);

    let prod = lo64(pr);
    let l = (prod & 0xFFFF) as u16;
    let h = (prod >> 16) as u16;

    u64_split16(prod);

    assert(prn == xor(l as nat, pow2(16) * (h as nat)));
    assert(((prod >> 16) as u16) < 0x8000) by (bit_vector)
        requires prod < 0x8000_0000u64;

    // First fold: pmod(prn) == pmod(l ^ clmul(h, 0x2b)).
    fold_step(l as nat, h as nat, 16);

    // clmul(h, 0x2b): degree < 20, so the carry is 4 bits.
    clmul64_bridge(h as u64, 0x2b);
    clmul_bound(h as nat, 0x2b, 15, 6);

    let hr = vmull_p64_m(h as u64, 0x2b);
    let hrn = clmul(h as nat, 0x2b);

    lo64_total(hr);

    let h_red = lo64(hr);
    let folded = (h_red & 0xFFFF) as u16;
    let carry = (h_red >> 16) as u16;

    u64_split16(h_red);

    assert(hrn == xor(folded as nat, pow2(16) * (carry as nat)));
    assert((carry as nat) < pow2(4)) by {
        assert(h_red < 0x10_0000);
        assert(((h_red >> 16) as u16) < 0x10) by (bit_vector) requires h_red < 0x10_0000u64;
    }

    // Regroup and fold the carry.
    xor_assoc(l as nat, folded as nat, pow2(16) * (carry as nat));
    fold_step(xor(l as nat, folded as nat), carry as nat, 16);

    // clmul(carry, 0x2b): degree < 9, already reduced.
    clmul64_bridge(carry as u64, 0x2b);
    clmul_bound(carry as nat, 0x2b, 4, 6);

    let cr = vmull_p64_m(carry as u64, 0x2b);
    let crn = clmul(carry as nat, 0x2b);

    lo64_total(cr);

    let c_red = lo64(cr);

    assert((c_red as u16) as nat == crn) by {
        assert(c_red < 0x200);
        assert((c_red as u16) as u64 == c_red) by (bit_vector) requires c_red < 0x200u64;
    }

    // The result is reduced; pmod is the identity on it.
    xor16_reflect(l, folded);
    xor16_reflect(l ^ folded, c_red as u16);
    xor_lt_pow2(l as nat, folded as nat, 16);
    pow2_mono(9, 16);
    xor_lt_pow2(xor(l as nat, folded as nat), crn, 16);
    deg_lt_conv(xor(xor(l as nat, folded as nat), crn), 16);
    pmod_below(xor(xor(l as nat, folded as nat), crn), 16);
}

// ============================================================
// mul_flat_32, block32.rs:608-644
// ============================================================

pub open spec fn mul_flat_32_twin(a: u32, b: u32) -> u32 {
    let prod = lo64(vmull_p64_m(a as u64, b as u64));
    let l = (prod & 0xFFFF_FFFF) as u32;
    let h = (prod >> 32) as u32;

    let h_red = lo64(vmull_p64_m(h as u64, 0x8d));
    let folded = (h_red & 0xFFFF_FFFF) as u32;
    let carry = (h_red >> 32) as u32;

    let c_red = lo64(vmull_p64_m(carry as u64, 0x8d));

    (l ^ folded) ^ (c_red as u32)
}

pub proof fn mul_flat_32_correct(a: u32, b: u32)
    ensures mul_flat_32_twin(a, b) as nat == gf_mul(a as nat, b as nat, 32)
{
    assert(pow2(32) == 0x1_0000_0000) by (compute);
    assert(pow2(63) == 0x8000_0000_0000_0000) by (compute);
    assert(pow2(8) == 0x100) by (compute);
    assert(pow2(31) == 0x8000_0000) by (compute);
    assert(pow2(38) == 0x40_0000_0000) by (compute);
    assert(pow2(6) == 0x40) by (compute);
    assert(pow2(13) == 0x2000) by (compute);

    clmul64_bridge(a as u64, b as u64);
    clmul_bound(a as nat, b as nat, 32, 32);

    let pr = vmull_p64_m(a as u64, b as u64);
    let prn = clmul(a as nat, b as nat);

    lo64_total(pr);

    let prod = lo64(pr);
    let l = (prod & 0xFFFF_FFFF) as u32;
    let h = (prod >> 32) as u32;

    u64_split32(prod);

    assert(prn == xor(l as nat, pow2(32) * (h as nat)));
    assert(((prod >> 32) as u32) < 0x8000_0000) by (bit_vector)
        requires prod < 0x8000_0000_0000_0000u64;

    fold_step(l as nat, h as nat, 32);

    // clmul(h, 0x8d): degree < 38, so the carry is 6 bits.
    clmul64_bridge(h as u64, 0x8d);
    clmul_bound(h as nat, 0x8d, 31, 8);

    let hr = vmull_p64_m(h as u64, 0x8d);
    let hrn = clmul(h as nat, 0x8d);

    lo64_total(hr);

    let h_red = lo64(hr);
    let folded = (h_red & 0xFFFF_FFFF) as u32;
    let carry = (h_red >> 32) as u32;

    u64_split32(h_red);

    assert(hrn == xor(folded as nat, pow2(32) * (carry as nat)));
    assert((carry as nat) < pow2(6)) by {
        assert(h_red < 0x40_0000_0000);
        assert(((h_red >> 32) as u32) < 0x40) by (bit_vector) requires h_red < 0x40_0000_0000u64;
    }

    xor_assoc(l as nat, folded as nat, pow2(32) * (carry as nat));
    fold_step(xor(l as nat, folded as nat), carry as nat, 32);

    // clmul(carry, 0x8d): degree < 13, already reduced.
    clmul64_bridge(carry as u64, 0x8d);
    clmul_bound(carry as nat, 0x8d, 6, 8);

    let cr = vmull_p64_m(carry as u64, 0x8d);
    let crn = clmul(carry as nat, 0x8d);

    lo64_total(cr);

    let c_red = lo64(cr);

    assert((c_red as u32) as nat == crn) by {
        assert(c_red < 0x2000);
        assert((c_red as u32) as u64 == c_red) by (bit_vector) requires c_red < 0x2000u64;
    }

    xor32_reflect(l, folded);
    xor32_reflect(l ^ folded, c_red as u32);
    xor_lt_pow2(l as nat, folded as nat, 32);
    pow2_mono(13, 32);
    xor_lt_pow2(xor(l as nat, folded as nat), crn, 32);
    deg_lt_conv(xor(xor(l as nat, folded as nat), crn), 32);
    pmod_below(xor(xor(l as nat, folded as nat), crn), 32);
}

// ============================================================
// mul_8, block8.rs:679-722: the tower Mul dispatch at 8 bits
// ============================================================

pub open spec fn mul_8_twin(a: u8, b: u8) -> u8 {
    let prod = vmull_p8_m(vdup_m8(a, 8), vdup_m8(b, 8))[0];
    let l = lo8(prod);
    let h = hi8(prod);

    let h_red = vmull_p8_m(vdup_m8(h, 8), vdup_m8(0x1b, 8))[0];
    let folded = lo8(h_red);
    let carry = hi8(h_red);

    let c_red = vmull_p8_m(vdup_m8(carry, 8), vdup_m8(0x1b, 8))[0];

    (l ^ folded) ^ lo8(c_red)
}

pub proof fn mul_8_correct(a: u8, b: u8)
    ensures mul_8_twin(a, b) as nat == gf_mul(a as nat, b as nat, 8)
{
    assert(pow2(8) == 0x100) by (compute);
    assert(pow2(5) == 0x20) by (compute);
    assert(pow2(7) == 0x80) by (compute);
    assert(pow2(12) == 0x1000) by (compute);
    assert(pow2(3) == 8) by (compute);

    // Lane 0 of PMULL over broadcast inputs is the scalar clmul.
    assert(vmull_p8_m(vdup_m8(a, 8), vdup_m8(b, 8))[0] == clmul8_lane(a, b));

    clmul8_bridge(a, b);

    let prod = clmul8_lane(a, b);
    let prn = clmul(a as nat, b as nat);

    u16_split8(prod);

    let l = lo8(prod);
    let h = hi8(prod);

    assert(prn == xor(l as nat, pow2(8) * (h as nat)));

    fold_step(l as nat, h as nat, 8);

    // clmul(h, 0x1b): degree < 12, so the carry is 4 bits.
    assert(vmull_p8_m(vdup_m8(h, 8), vdup_m8(0x1b, 8))[0] == clmul8_lane(h, 0x1b));

    clmul8_bridge(h, 0x1b);
    clmul_bound(h as nat, 0x1b, 8, 5);

    let h_red = clmul8_lane(h, 0x1b);
    let hrn = clmul(h as nat, 0x1b);

    u16_split8(h_red);

    let folded = lo8(h_red);
    let carry = hi8(h_red);

    assert(hrn == xor(folded as nat, pow2(8) * (carry as nat)));

    xor_assoc(l as nat, folded as nat, pow2(8) * (carry as nat));
    fold_step(xor(l as nat, folded as nat), carry as nat, 8);

    // clmul(carry, 0x1b): degree < 8 twice over — carry < 2^4
    // and 0x1b < 2^5 keep the last product below 2^8, so the
    // low byte is the whole value.
    assert(vmull_p8_m(vdup_m8(carry, 8), vdup_m8(0x1b, 8))[0] == clmul8_lane(carry, 0x1b));

    clmul8_bridge(carry, 0x1b);

    assert((carry as nat) < pow2(4)) by {
        assert(pow2(4) == 0x10) by (compute);
        assert(h_red < 0x1000);
        assert(((h_red >> 8) as u8) < 0x10) by (bit_vector) requires h_red < 0x1000u16;
    }

    clmul_bound(carry as nat, 0x1b, 4, 5);

    let c_red = clmul8_lane(carry, 0x1b);
    let crn = clmul(carry as nat, 0x1b);

    assert((lo8(c_red)) as nat == crn) by {
        assert(pow2(8) == 0x100) by (compute);
        assert(c_red < 0x100);
        assert((c_red as u8) as u16 == c_red) by (bit_vector) requires c_red < 0x100u16;
    }

    xor8_reflect(l, folded);
    xor8_reflect(l ^ folded, lo8(c_red));
    xor_lt_pow2(l as nat, folded as nat, 8);
    xor_lt_pow2(xor(l as nat, folded as nat), crn, 8);
    deg_lt_conv(xor(xor(l as nat, folded as nat), crn), 8);
    pmod_below(xor(xor(l as nat, folded as nat), crn), 8);
}

// ============================================================
// mul_flat_64, block64.rs:644-668
// ============================================================

pub open spec fn mul_flat_64_twin(a: u64, b: u64) -> u64 {
    let prod = vmull_p64_m(a, b);
    let l = lo64(prod);
    let h = hi64(prod);

    let h_red = vmull_p64_m(h, 0x1b);
    let folded = lo64(h_red);
    let carry = hi64(h_red);

    let carry_red = vmull_p64_m(carry, 0x1b);

    (l ^ folded) ^ lo64(carry_red)
}

pub proof fn mul_flat_64_correct(a: u64, b: u64)
    ensures mul_flat_64_twin(a, b) as nat == gf_mul(a as nat, b as nat, 64)
{
    assert(pow2(64) == 0x1_0000_0000_0000_0000) by (compute);
    assert(pow2(127) == 0x8000_0000_0000_0000_0000_0000_0000_0000) by (compute);
    assert(pow2(63) == 0x8000_0000_0000_0000) by (compute);
    assert(pow2(5) == 0x20) by (compute);
    assert(pow2(67) == 0x8_0000_0000_0000_0000) by (compute);
    assert(pow2(3) == 8) by (compute);
    assert(pow2(7) == 0x80) by (compute);

    clmul64_bridge(a, b);
    clmul_bound(a as nat, b as nat, 64, 64);

    let prod = vmull_p64_m(a, b);
    let prn = clmul(a as nat, b as nat);
    let l = lo64(prod);
    let h = hi64(prod);

    u128_split(prod);

    assert(prn == xor(l as nat, pow2(64) * (h as nat)));

    fold_step(l as nat, h as nat, 64);

    // clmul(h, 0x1b): degree < 67, so the carry is 3 bits
    assert(((prod >> 64) as u64) < 0x8000_0000_0000_0000) by (bit_vector)
        requires prod < 0x8000_0000_0000_0000_0000_0000_0000_0000u128;

    clmul64_bridge(h, 0x1b);
    clmul_bound(h as nat, 0x1b, 63, 5);

    let h_red = vmull_p64_m(h, 0x1b);
    let hrn = clmul(h as nat, 0x1b);
    let folded = lo64(h_red);
    let carry = hi64(h_red);

    u128_split(h_red);

    assert(hrn == xor(folded as nat, pow2(64) * (carry as nat)));
    assert(((h_red >> 64) as u64) < 8) by (bit_vector)
        requires h_red < 0x8_0000_0000_0000_0000u128;

    xor_assoc(l as nat, folded as nat, pow2(64) * (carry as nat));
    fold_step(xor(l as nat, folded as nat), carry as nat, 64);

    // clmul(carry, 0x1b): degree < 7, already reduced
    clmul64_bridge(carry, 0x1b);
    clmul_bound(carry as nat, 0x1b, 3, 5);

    let cr = vmull_p64_m(carry, 0x1b);
    let crn = clmul(carry as nat, 0x1b);

    lo64_total(cr);

    xor64_reflect(l, folded);
    xor64_reflect(l ^ folded, lo64(cr));
    xor_lt_pow2(l as nat, folded as nat, 64);
    pow2_mono(7, 64);
    xor_lt_pow2(xor(l as nat, folded as nat), crn, 64);
    deg_lt_conv(xor(xor(l as nat, folded as nat), crn), 64);
    pmod_below(xor(xor(l as nat, folded as nat), crn), 64);
}

// ============================================================
// mul_flat_128, block128.rs:874-921: two-limb
// schoolbook, four product PMULLs, two-stage 0x87 fold
// ============================================================

pub open spec fn mul_flat_128_twin(a: u128, b: u128) -> u128 {
    let a0 = lo64(a);
    let a1 = hi64(a);
    let b0 = lo64(b);
    let b1 = hi64(b);

    let d0 = vmull_p64_m(a0, b0);
    let d2 = vmull_p64_m(a1, b1);
    let x0 = vmull_p64_m(a0, b1);
    let x1 = vmull_p64_m(a1, b0);

    let mid = x0 ^ x1;

    let c0 = lo64(d0);
    let c1 = hi64(d0) ^ lo64(mid);
    let c2 = lo64(d2) ^ hi64(mid);
    let c3 = hi64(d2);

    let p0 = vmull_p64_m(c2, 0x87);
    let p1 = vmull_p64_m(c3, 0x87);

    let folded_0 = lo64(p0);
    let folded_1 = hi64(p0) ^ lo64(p1);
    let carry = hi64(p1);

    let final_0 = c0 ^ folded_0;
    let final_1 = c1 ^ folded_1;

    // deg(carry·R) < 14; the high lane is zero.
    let carry_mul = vmull_p64_m(carry, 0x87);

    (((final_0 as u128) | ((final_1 as u128) << 64))) ^ carry_mul
}

proof fn mul_comm_p64(x: nat)
    ensures pow2(64) * x == x * pow2(64)
{
    lemma_mul_is_commutative(pow2(64) as int, x as int);
}

pub proof fn mul_flat_128_correct(a: u128, b: u128)
    ensures mul_flat_128_twin(a, b) as nat == gf_mul(a as nat, b as nat, 128)
{
    let p = pow2(64);

    assert(pow2(64) == 0x1_0000_0000_0000_0000) by (compute);
    assert(pow2(8) == 0x100) by (compute);
    assert(pow2(71) == 0x80_0000_0000_0000_0000) by (compute);
    assert(pow2(7) == 0x80) by (compute);
    assert(pow2(14) == 0x4000) by (compute);

    let a0 = lo64(a);
    let a1 = hi64(a);
    let b0 = lo64(b);
    let b1 = hi64(b);

    // The packed operands split into limb xor-forms
    u128_split(a);
    u128_split(b);
    mul_comm_p64(a1 as nat);
    mul_comm_p64(b1 as nat);

    // Schoolbook at the clmul level
    schoolbook_clmul(a0 as nat, a1 as nat, b0 as nat, b1 as nat, 64);

    let d0 = vmull_p64_m(a0, b0);
    let d2 = vmull_p64_m(a1, b1);
    let x0 = vmull_p64_m(a0, b1);
    let x1 = vmull_p64_m(a1, b0);
    let dd0 = clmul(a0 as nat, b0 as nat);
    let dd2 = clmul(a1 as nat, b1 as nat);
    let midn = xor(clmul(a0 as nat, b1 as nat), clmul(a1 as nat, b0 as nat));

    clmul64_bridge(a0, b0);
    clmul64_bridge(a1, b1);
    clmul64_bridge(a0, b1);
    clmul64_bridge(a1, b0);

    let prn = clmul(a as nat, b as nat);

    assert(prn == xor(dd0, xor(midn * p, dd2 * p * p)));

    // The four products in u128 lane view
    let mid = x0 ^ x1;

    xor128_reflect(x0, x1);

    assert(mid as nat == midn);

    let c0 = lo64(d0);
    let c1 = hi64(d0) ^ lo64(mid);
    let c2 = lo64(d2) ^ hi64(mid);
    let c3 = hi64(d2);

    u128_split(d0);
    u128_split(mid);
    u128_split(d2);
    xor64_reflect(hi64(d0), lo64(mid));
    xor64_reflect(lo64(d2), hi64(mid));

    let hd0 = hi64(d0) as nat;
    let lm = lo64(mid) as nat;
    let hm = hi64(mid) as nat;
    let ld2 = lo64(d2) as nat;
    let c0n = c0 as nat;
    let c1n = c1 as nat;
    let c2n = c2 as nat;
    let c3n = c3 as nat;

    // Regroup the three split products by lane weight:
    // prn == c0 ^ p·c1 ^ p²·c2 ^ p³·c3.
    assert(midn * p == xor(p * lm, p * (p * hm))) by {
        mul_comm_p64(midn);
        xor_mul_pow2(64, lm, p * hm);
    }

    assert(dd2 * p * p == xor(p * (p * ld2), p * (p * (p * c3n)))) by {
        mul_comm_p64(dd2);
        xor_mul_pow2(64, ld2, p * c3n);

        assert(p * dd2 == xor(p * ld2, p * (p * c3n)));

        mul_comm_p64(dd2 * p);
        xor_mul_pow2(64, p * ld2, p * (p * c3n));

        assert(p * (dd2 * p) == xor(p * (p * ld2), p * (p * (p * c3n))));
        assert(dd2 * p * p == p * (dd2 * p)) by {
            lemma_mul_is_commutative((dd2 * p) as int, p as int);
        }
    }

    let w1 = p * c1n;
    let w2 = p * (p * c2n);
    let w3 = p * (p * (p * c3n));

    assert(prn == xor(c0n, xor(w1, xor(w2, w3)))) by {
        let w = xor(w2, w3);

        // Merge the two weight-p and the two weight-p² terms
        xor_mul_pow2(64, hd0, lm);
        xor_comm(hm, ld2);
        xor_mul_pow2(64, hm, ld2);
        xor_mul_pow2(64, p * hm, p * ld2);

        assert(w1 == xor(p * hd0, p * lm));
        assert(w2 == xor(p * (p * hm), p * (p * ld2)));

        // (p·lm ^ p²·hm) ^ (p²·ld2 ^ w3) == p·lm ^ (w2 ^ w3)
        xor_assoc(p * (p * hm), p * (p * ld2), w3);
        xor_assoc(p * lm, p * (p * hm), xor(p * (p * ld2), w3));

        // (c0 ^ p·hd0) ^ (p·lm ^ w) == c0 ^ (w1 ^ w)
        xor_assoc(p * hd0, p * lm, w);
        xor_assoc(c0n, p * hd0, xor(p * lm, w));
    }

    // Halve: prn == L ^ 2^128·H with L, H the 128-bit rows
    let ln = xor(c0n, w1);
    let hn = xor(c2n, p * c3n);

    pow2_add(64, 64);

    assert(prn == xor(ln, pow2(128) * hn)) by {
        mul_comm_p64(p * c2n);
        lemma_mul_is_associative(p as int, p as int, c2n as int);

        assert(w2 == (p * p) * c2n);

        mul_comm_p64(p * (p * c3n));
        lemma_mul_is_associative(p as int, p as int, (p * c3n) as int);

        assert(w3 == (p * p) * (p * c3n));

        xor_mul_pow2(128, c2n, p * c3n);

        assert(xor(w2, w3) == pow2(128) * hn);

        xor_assoc(c0n, w1, xor(w2, w3));
    }

    fold_step(ln, hn, 128);

    // clmul(H, 0x87) through the two fold products
    let p0 = vmull_p64_m(c2, 0x87);
    let p1 = vmull_p64_m(c3, 0x87);
    let pp0 = clmul(c2n, 0x87);
    let pp1 = clmul(c3n, 0x87);

    clmul64_bridge(c2, 0x87);
    clmul64_bridge(c3, 0x87);
    clmul_bound(c2n, 0x87, 64, 8);
    clmul_bound(c3n, 0x87, 64, 8);

    let chn = clmul(hn, 0x87);

    assert(chn == xor(pp0, pp1 * p)) by {
        clmul_distrib_l(c2n, p * c3n, 0x87);
        mul_comm_p64(c3n);
        clmul_shift_limb(c3n, 0x87, 64);
    }

    let f0 = lo64(p0);
    let hp0 = hi64(p0) as nat;
    let lp1 = lo64(p1) as nat;
    let carry = hi64(p1);
    let folded_1 = hi64(p0) ^ lo64(p1);

    u128_split(p0);
    u128_split(p1);
    xor64_reflect(hi64(p0), lo64(p1));

    assert((carry as nat) < pow2(7)) by {
        assert(((p1 >> 64) as u64) < 0x80) by (bit_vector)
            requires p1 < 0x80_0000_0000_0000_0000u128;
    }

    // chn == f0 ^ p·folded_1 ^ p²·carry
    let cyn = carry as nat;
    let f1n = folded_1 as nat;

    assert(chn == xor(f0 as nat, xor(p * f1n, pow2(128) * cyn))) by {
        mul_comm_p64(pp1);
        xor_mul_pow2(64, lp1, p * cyn);

        assert(pp1 * p == xor(p * lp1, p * (p * cyn)));
        assert(p * (p * cyn) == pow2(128) * cyn) by {
            lemma_mul_is_associative(p as int, p as int, cyn as int);
        }

        xor_mul_pow2(64, hp0, lp1);

        assert(xor(p * hp0, p * lp1) == p * f1n);

        // (f0 ^ p·hp0) ^ (p·lp1 ^ p²·cy) regroups
        xor_assoc(f0 as nat, p * hp0, xor(p * lp1, pow2(128) * cyn));
        xor_assoc(p * hp0, p * lp1, pow2(128) * cyn);
    }

    // L ^ clmul(H, 0x87) == F0 ^ p·F1 ^ p²·carry
    let final_0 = c0 ^ f0;
    let final_1 = c1 ^ folded_1;
    let ff0 = final_0 as nat;
    let ff1 = final_1 as nat;

    xor64_reflect(c0, f0);
    xor64_reflect(c1, folded_1);

    assert(xor(ln, chn) == xor(xor(ff0, p * ff1), pow2(128) * cyn)) by {
        xor_rearrange4(c0n, w1, f0 as nat, xor(p * f1n, pow2(128) * cyn));

        assert(xor(w1, xor(p * f1n, pow2(128) * cyn))
            == xor(p * ff1, pow2(128) * cyn)) by {
            xor_assoc(w1, p * f1n, pow2(128) * cyn);
            xor_mul_pow2(64, c1n, f1n);
        }

        xor_assoc(ff0, p * ff1, pow2(128) * cyn);
    }

    fold_step(xor(ff0, p * ff1), cyn, 128);

    // clmul(carry, 0x87): degree < 14, already reduced
    clmul64_bridge(carry, 0x87);
    clmul_bound(cyn, 0x87, 7, 8);

    let cr = vmull_p64_m(carry, 0x87);
    let crn = clmul(cyn, 0x87);

    lo64_total(cr);

    let carry_res = lo64(cr);
    let res_lo = final_0 ^ carry_res;
    let packed = (final_0 as u128) | ((final_1 as u128) << 64);

    xor64_reflect(final_0, carry_res);

    // cr < 2^64; the xor lands entirely in the low lane.
    assert(packed ^ cr == (res_lo as u128) | ((final_1 as u128) << 64)) by (bit_vector)
        requires
            packed == (final_0 as u128) | ((final_1 as u128) << 64),
            res_lo == final_0 ^ (cr as u64),
            cr < 0x1_0000_0000_0000_0000u128;

    // Reassociate the low-lane carry into F0
    assert(xor(xor(ff0, p * ff1), crn) == xor(res_lo as nat, p * ff1)) by {
        xor_assoc(ff0, p * ff1, crn);
        xor_comm(p * ff1, crn);
        xor_assoc(ff0, crn, p * ff1);
    }

    // The packed result is reduced
    u128_pack(res_lo, final_1);
    pow2_mono(14, 64);
    xor_lt_pow2(ff0, crn, 64);

    assert((p * ff1) < pow2(128)) by {
        lemma_mul_strict_inequality(ff1 as int, pow2(64) as int, p as int);
        lemma_mul_is_commutative(ff1 as int, p as int);
    }

    pow2_mono(64, 128);
    xor_lt_pow2(res_lo as nat, p * ff1, 128);
    deg_lt_conv(xor(res_lo as nat, p * ff1), 128);
    pmod_below(xor(res_lo as nat, p * ff1), 128);
}

fn main() {
}

} // verus!
