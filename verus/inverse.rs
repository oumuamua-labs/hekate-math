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

//! Twins of `TowerField::invert`: the norm recursion of
//! src/towers/block{16,32,64,128,256}.rs down to the Fermat
//! chain `a^254` of block8.rs, each proven `is_correct_inverse`.

use vstd::prelude::*;

#[path = "algebra.rs"]
pub mod algebra;

use algebra::bridge;
use algebra::bridge::b256::b128::b64::b32::b16::b8::{
    mul_tau8, mul_tau8_is_schoolbook, schoolbook8,
};
use algebra::bridge::b256::b128::b64::b32::b16::{
    hi as hi16, lo as lo16, mul_tau16, mul_tau16_is_schoolbook, mul16_k, mul16_matches_schoolbook,
    pack as pk16, schoolbook16,
};
use algebra::bridge::b256::b128::b64::b32::{
    hi as hi32, lo as lo32, mul_tau32, mul_tau32_is_schoolbook, mul32_k, mul32_matches_schoolbook,
    pack as pk32, schoolbook32,
};
use algebra::bridge::b256::b128::b64::{
    hi as hi64, lo as lo64, mul_tau64, mul_tau64_is_schoolbook, mul64_k, mul64_matches_schoolbook,
    pack as pk64, schoolbook64,
};
use algebra::bridge::b256::b128::{
    hi as hi128, lo as lo128, mul_tau128, mul_tau128_is_schoolbook, mul128_k,
    mul128_matches_schoolbook, pack as pk128, schoolbook128,
};
use algebra::bridge::gf_model::{
    deg_lt_conv, deg_upper, ext_norm, gf_mul_tower, gf_mul_tower_assoc, gf_mul_tower_bound,
    gf_mul_tower_comm, gf_mul_tower_distrib_l, gf_mul_tower_distrib_r, gf_mul_tower_zero_l,
    gf_mul_tower_zero_r, hi_half, in_field, is_correct_inverse, lo_half, pack_mod_div, pow_2exp,
    pow2, pow2_add, quad_ext_inverse, tau_tower, trace_spec, xor, xor_assoc, xor_comm, xor_eq_zero,
    xor_lt_pow2, xor_self, xor_zero,
};
use algebra::{
    frobenius_and_trace, frobenius_order, halves, one_in_field, sq_of_product, square8_spread,
    square8_spread_is_schoolbook, square16_is_schoolbook, square16_twin, square32_is_schoolbook,
    square32_twin, square64_is_schoolbook, square64_twin, square128_is_schoolbook, square128_twin,
    tau_in_field, tower_one, trace_additive, trace_idempotent, trace_of_square,
};
use bridge::{
    bridge8, bridge16, bridge32, bridge64, bridge128, pack16, pack32, pack64, pack128, split16,
    split32, split64, split128, xor8, xor16, xor32, xor64, xor128,
};

verus! {

// ============================================================
// GF(2^8): a^-1 = a^254, block8.rs
// ============================================================

pub open spec fn inv8_twin(x: u8) -> u8 {
    let x2 = schoolbook8(x, x);
    let x4 = schoolbook8(x2, x2);
    let x8 = schoolbook8(x4, x4);
    let x16 = schoolbook8(x8, x8);
    let x32 = schoolbook8(x16, x16);
    let x64 = schoolbook8(x32, x32);
    let x128 = schoolbook8(x64, x64);

    schoolbook8(
        schoolbook8(schoolbook8(schoolbook8(schoolbook8(schoolbook8(x128, x64), x32), x16), x8), x4),
        x2,
    )
}

pub open spec fn powm(x: nat, n: nat) -> nat
    decreases n
{
    if n == 0 {
        1
    } else {
        gf_mul_tower(powm(x, (n - 1) as nat), x, 8)
    }
}

proof fn powm_in_field(x: nat, n: nat)
    requires in_field(x, 8)
    ensures in_field(powm(x, n), 8)
{
    assert(pow2(8) == 256) by (compute);

    if n == 0 {
        deg_lt_conv(1, 8);
    } else {
        gf_mul_tower_bound(powm(x, (n - 1) as nat), x, 8);
        deg_lt_conv(powm(x, n), 8);
    }
}

proof fn powm_add(x: nat, a: nat, b: nat)
    requires in_field(x, 8)
    ensures powm(x, a + b) == gf_mul_tower(powm(x, a), powm(x, b), 8)
    decreases b
{
    if b == 0 {
        powm_in_field(x, a);
        tower_one(powm(x, a), 8);
    } else {
        powm_add(x, a, (b - 1) as nat);
        gf_mul_tower_assoc(powm(x, a), powm(x, (b - 1) as nat), x, 8);
    }
}

proof fn pow_2exp_is_powm(x: nat, j: nat)
    requires in_field(x, 8)
    ensures pow_2exp(x, j, 8) == powm(x, pow2(j))
    decreases j
{
    if j == 0 {
        assert(pow2(0) == 1) by (compute);
        assert(powm(x, 0) == 1);
        assert(powm(x, 1) == gf_mul_tower(1, x, 8));

        tower_one(x, 8);
    } else {
        let h = pow2((j - 1) as nat);

        pow_2exp_is_powm(x, (j - 1) as nat);
        assert(pow2(j) == h + h);
        powm_add(x, h, h);
    }
}

proof fn no_zero_divisors8(u: u8, v: u8)
    requires schoolbook8(u, v) == 0
    ensures u == 0 || v == 0
{
    assert(u == 0 || v == 0 || schoolbook8(u, v) != 0) by (bit_vector);
}

proof fn no_zero_divisors8_nat(a: nat, b: nat)
    requires
        in_field(a, 8),
        in_field(b, 8),
        gf_mul_tower(a, b, 8) == 0,
    ensures a == 0 || b == 0
{
    assert(pow2(8) == 256) by (compute);

    deg_upper(a, 8);
    deg_upper(b, 8);

    let u = a as u8;
    let v = b as u8;

    bridge8(u, v);
    no_zero_divisors8(u, v);
}

pub proof fn inv8_correct(x: u8)
    ensures is_correct_inverse(x as nat, inv8_twin(x) as nat, 8)
{
    let r = inv8_twin(x);

    assert(pow2(8) == 256) by (compute);
    deg_lt_conv(r as nat, 8);

    if x == 0 {
        assert(inv8_twin(0) == 0) by (compute);
    } else {
        let xn = x as nat;

        deg_lt_conv(xn, 8);

        let x2 = schoolbook8(x, x);
        let x4 = schoolbook8(x2, x2);
        let x8 = schoolbook8(x4, x4);
        let x16 = schoolbook8(x8, x8);
        let x32 = schoolbook8(x16, x16);
        let x64 = schoolbook8(x32, x32);
        let x128 = schoolbook8(x64, x64);

        bridge8(x, x);
        bridge8(x2, x2);
        bridge8(x4, x4);
        bridge8(x8, x8);
        bridge8(x16, x16);
        bridge8(x32, x32);
        bridge8(x64, x64);

        assert(pow_2exp(xn, 0, 8) == xn);
        assert(x2 as nat == pow_2exp(xn, 1, 8));
        assert(x4 as nat == pow_2exp(xn, 2, 8));
        assert(x8 as nat == pow_2exp(xn, 3, 8));
        assert(x16 as nat == pow_2exp(xn, 4, 8));
        assert(x32 as nat == pow_2exp(xn, 5, 8));
        assert(x64 as nat == pow_2exp(xn, 6, 8));
        assert(x128 as nat == pow_2exp(xn, 7, 8));

        assert(pow2(1) == 2 && pow2(2) == 4 && pow2(3) == 8 && pow2(4) == 16 && pow2(5) == 32
            && pow2(6) == 64 && pow2(7) == 128) by (compute);

        pow_2exp_is_powm(xn, 1);
        pow_2exp_is_powm(xn, 2);
        pow_2exp_is_powm(xn, 3);
        pow_2exp_is_powm(xn, 4);
        pow_2exp_is_powm(xn, 5);
        pow_2exp_is_powm(xn, 6);
        pow_2exp_is_powm(xn, 7);

        let m1 = schoolbook8(x128, x64);
        let m2 = schoolbook8(m1, x32);
        let m3 = schoolbook8(m2, x16);
        let m4 = schoolbook8(m3, x8);
        let m5 = schoolbook8(m4, x4);

        bridge8(x128, x64);
        bridge8(m1, x32);
        bridge8(m2, x16);
        bridge8(m3, x8);
        bridge8(m4, x4);
        bridge8(m5, x2);

        powm_add(xn, 128, 64);
        powm_add(xn, 192, 32);
        powm_add(xn, 224, 16);
        powm_add(xn, 240, 8);
        powm_add(xn, 248, 4);
        powm_add(xn, 252, 2);

        assert(r as nat == powm(xn, 254));

        let y = gf_mul_tower(r as nat, xn, 8);

        assert(y == powm(xn, 255));
        assert(gf_mul_tower(y, xn, 8) == powm(xn, 256));

        pow_2exp_is_powm(xn, 8);
        frobenius_order(xn, 8);

        assert(gf_mul_tower(y, xn, 8) == xn);

        gf_mul_tower_comm(y, xn, 8);
        gf_mul_tower_distrib_r(xn, y, 1, 8);
        tower_one(xn, 8);
        xor_self(xn);

        assert(gf_mul_tower(xn, xor(y, 1), 8) == 0);

        powm_in_field(xn, 255);
        deg_lt_conv(1, 8);
        deg_upper(y, 8);
        xor_lt_pow2(y, 1, 8);
        deg_lt_conv(xor(y, 1), 8);
        no_zero_divisors8_nat(xn, xor(y, 1));

        xor_assoc(y, 1, 1);
        xor_self(1);
        xor_zero(y);
        xor_zero(1);

        assert(y == 1);

        gf_mul_tower_comm(xn, r as nat, 8);
    }
}

// ============================================================
// GF(2^2m): a^-1 = conj(a) · N(a)^-1, block{16..256}.rs
// ============================================================

pub proof fn norm_nonzero(a: nat, k: nat, w: nat)
    requires
        k == 16 || k == 32 || k == 64 || k == 128 || k == 256,
        in_field(a, k),
        a != 0,
        is_correct_inverse(
            if hi_half(a, k) == 0 { lo_half(a, k) } else { hi_half(a, k) },
            w,
            (k / 2) as nat,
        ),
    ensures ext_norm(lo_half(a, k), hi_half(a, k), (k / 2) as nat) != 0
{
    hide(gf_mul_tower);

    let m = (k / 2) as nat;
    let lo = lo_half(a, k);
    let hi = hi_half(a, k);
    let t = tau_tower(m);
    let ww = gf_mul_tower(w, w, m);
    let ll = gf_mul_tower(lo, lo, m);
    let nrm = ext_norm(lo, hi, m);

    halves(a, k);
    frobenius_and_trace(m);
    tau_in_field(m);
    one_in_field(m);
    tower_one(1, m);
    gf_mul_tower_zero_l(ww, m);

    if hi == 0 {
        gf_mul_tower_zero_r(lo, m);
        gf_mul_tower_zero_l(0, m);
        gf_mul_tower_zero_l(t, m);
        xor_zero(ll);
        sq_of_product(lo, w, m);

        assert(a == lo + pow2(m) * 0);
        assert(nrm == ll);
    } else {
        let u = gf_mul_tower(lo, w, m);
        let uu = gf_mul_tower(u, u, m);
        let s = trace_spec(u, m, m);
        let lh = gf_mul_tower(lo, hi, m);
        let hh = gf_mul_tower(hi, hi, m);

        gf_mul_tower_bound(lo, w, m);
        deg_lt_conv(u, m);

        gf_mul_tower_distrib_l(xor(ll, lh), gf_mul_tower(hh, t, m), ww, m);
        gf_mul_tower_distrib_l(ll, lh, ww, m);
        sq_of_product(lo, w, m);

        gf_mul_tower_assoc(lo, hi, ww, m);
        gf_mul_tower_assoc(hi, w, w, m);
        tower_one(w, m);

        gf_mul_tower_assoc(hh, t, ww, m);
        gf_mul_tower_comm(t, ww, m);
        gf_mul_tower_assoc(hh, ww, t, m);
        sq_of_product(hi, w, m);
        tower_one(t, m);

        assert(gf_mul_tower(nrm, ww, m) == xor(xor(uu, u), t));

        if nrm == 0 {
            xor_eq_zero(xor(uu, u), t);
            trace_additive(uu, u, m, m);
            trace_of_square(u, m, m);
            trace_idempotent(u, m);
            xor_self(s);
        }
    }
}

pub open spec fn inv16_twin(a: u16) -> u16 {
    let l = lo16(a);
    let h = hi16(a);

    let norm = mul_tau8(square8_spread(h)) ^ schoolbook8(h, l) ^ square8_spread(l);
    let ninv = inv8_twin(norm);

    pk16(schoolbook8(h ^ l, ninv), schoolbook8(h, ninv))
}

pub proof fn inv16_correct(a: u16)
    ensures is_correct_inverse(a as nat, inv16_twin(a) as nat, 16)
{
    let l = lo16(a);
    let h = hi16(a);

    let ln = l as nat;
    let hn = h as nat;

    let sh = square8_spread(h);
    let sl = square8_spread(l);

    let t = mul_tau8(sh);
    let c = schoolbook8(h, l);

    let norm = t ^ c ^ sl;
    let ninv = inv8_twin(norm);

    assert(pow2(16) == 0x1_0000) by (compute);

    deg_lt_conv(a as nat, 16);
    split16(a);

    square8_spread_is_schoolbook(h);
    square8_spread_is_schoolbook(l);

    mul_tau8_is_schoolbook(sh);

    bridge8(h, h);
    bridge8(l, l);
    bridge8(sh, 0x20);
    bridge8(h, l);

    gf_mul_tower_comm(hn, ln, 8);

    assert(tau_tower(8) == 0x20) by (compute);

    xor8(t, c);
    xor8(t ^ c, sl);

    let t1 = gf_mul_tower(ln, ln, 8);
    let t2 = gf_mul_tower(ln, hn, 8);
    let t3 = gf_mul_tower(gf_mul_tower(hn, hn, 8), tau_tower(8), 8);

    xor_comm(xor(t3, t2), t1);
    xor_comm(t3, t2);
    xor_assoc(t1, t2, t3);

    assert(norm as nat == ext_norm(ln, hn, 8));

    inv8_correct(norm);

    let s = if h == 0 { l } else { h };

    inv8_correct(s);

    if a != 0 {
        norm_nonzero(a as nat, 16, inv8_twin(s) as nat);
    }

    quad_ext_inverse(a as nat, 16, ninv as nat);

    xor8(h, l);
    bridge8(h ^ l, ninv);
    bridge8(h, ninv);
    pack16(schoolbook8(h ^ l, ninv), schoolbook8(h, ninv));
}

pub open spec fn inv32_twin(a: u32) -> u32 {
    let l = lo32(a);
    let h = hi32(a);

    let norm = mul_tau16(square16_twin(h)) ^ mul16_k(h, l) ^ square16_twin(l);
    let ninv = inv16_twin(norm);

    pk32(mul16_k(h ^ l, ninv), mul16_k(h, ninv))
}

pub proof fn inv32_correct(a: u32)
    ensures is_correct_inverse(a as nat, inv32_twin(a) as nat, 32)
{
    hide(gf_mul_tower);
    hide(schoolbook16);
    hide(mul16_k);
    hide(square16_twin);
    hide(mul_tau16);
    hide(inv16_twin);

    let l = lo32(a);
    let h = hi32(a);

    let ln = l as nat;
    let hn = h as nat;

    let sh = square16_twin(h);
    let sl = square16_twin(l);

    let t = mul_tau16(sh);
    let c = mul16_k(h, l);

    let norm = t ^ c ^ sl;
    let ninv = inv16_twin(norm);

    assert(pow2(32) == 0x1_0000_0000) by (compute);

    deg_lt_conv(a as nat, 32);
    split32(a);

    square16_is_schoolbook(h);
    square16_is_schoolbook(l);

    mul_tau16_is_schoolbook(sh);
    mul16_matches_schoolbook(h, l);

    bridge16(h, h);
    bridge16(l, l);
    bridge16(sh, 0x2000);
    bridge16(h, l);

    gf_mul_tower_comm(hn, ln, 16);

    assert(tau_tower(16) == 0x2000) by (compute);

    xor16(t, c);
    xor16(t ^ c, sl);

    let t1 = gf_mul_tower(ln, ln, 16);
    let t2 = gf_mul_tower(ln, hn, 16);
    let t3 = gf_mul_tower(gf_mul_tower(hn, hn, 16), tau_tower(16), 16);

    xor_comm(xor(t3, t2), t1);
    xor_comm(t3, t2);
    xor_assoc(t1, t2, t3);

    assert(norm as nat == ext_norm(ln, hn, 16));

    inv16_correct(norm);

    let s = if h == 0 { l } else { h };

    inv16_correct(s);

    if a != 0 {
        norm_nonzero(a as nat, 32, inv16_twin(s) as nat);
    }

    quad_ext_inverse(a as nat, 32, ninv as nat);

    xor16(h, l);
    mul16_matches_schoolbook(h ^ l, ninv);
    mul16_matches_schoolbook(h, ninv);
    bridge16(h ^ l, ninv);
    bridge16(h, ninv);
    pack32(mul16_k(h ^ l, ninv), mul16_k(h, ninv));
}

pub open spec fn inv64_twin(a: u64) -> u64 {
    let l = lo64(a);
    let h = hi64(a);

    let norm = mul_tau32(square32_twin(h)) ^ mul32_k(h, l) ^ square32_twin(l);
    let ninv = inv32_twin(norm);

    pk64(mul32_k(h ^ l, ninv), mul32_k(h, ninv))
}

pub proof fn inv64_correct(a: u64)
    ensures is_correct_inverse(a as nat, inv64_twin(a) as nat, 64)
{
    hide(gf_mul_tower);
    hide(schoolbook32);
    hide(mul32_k);
    hide(square32_twin);
    hide(mul_tau32);
    hide(inv32_twin);

    let l = lo64(a);
    let h = hi64(a);

    let ln = l as nat;
    let hn = h as nat;

    let sh = square32_twin(h);
    let sl = square32_twin(l);

    let t = mul_tau32(sh);
    let c = mul32_k(h, l);

    let norm = t ^ c ^ sl;
    let ninv = inv32_twin(norm);

    assert(pow2(64) == 0x1_0000_0000_0000_0000) by (compute);

    deg_lt_conv(a as nat, 64);
    split64(a);

    square32_is_schoolbook(h);
    square32_is_schoolbook(l);

    mul_tau32_is_schoolbook(sh);
    mul32_matches_schoolbook(h, l);

    bridge32(h, h);
    bridge32(l, l);
    bridge32(sh, 0x2000_0000);
    bridge32(h, l);

    gf_mul_tower_comm(hn, ln, 32);

    assert(tau_tower(32) == 0x2000_0000) by (compute);

    xor32(t, c);
    xor32(t ^ c, sl);

    let t1 = gf_mul_tower(ln, ln, 32);
    let t2 = gf_mul_tower(ln, hn, 32);
    let t3 = gf_mul_tower(gf_mul_tower(hn, hn, 32), tau_tower(32), 32);

    xor_comm(xor(t3, t2), t1);
    xor_comm(t3, t2);
    xor_assoc(t1, t2, t3);

    assert(norm as nat == ext_norm(ln, hn, 32));

    inv32_correct(norm);

    let s = if h == 0 { l } else { h };

    inv32_correct(s);

    if a != 0 {
        norm_nonzero(a as nat, 64, inv32_twin(s) as nat);
    }

    quad_ext_inverse(a as nat, 64, ninv as nat);

    xor32(h, l);
    mul32_matches_schoolbook(h ^ l, ninv);
    mul32_matches_schoolbook(h, ninv);
    bridge32(h ^ l, ninv);
    bridge32(h, ninv);
    pack64(mul32_k(h ^ l, ninv), mul32_k(h, ninv));
}

pub open spec fn inv128_twin(a: u128) -> u128 {
    let l = lo128(a);
    let h = hi128(a);

    let norm = mul_tau64(square64_twin(h)) ^ mul64_k(h, l) ^ square64_twin(l);
    let ninv = inv64_twin(norm);

    pk128(mul64_k(h ^ l, ninv), mul64_k(h, ninv))
}

pub proof fn inv128_correct(a: u128)
    ensures is_correct_inverse(a as nat, inv128_twin(a) as nat, 128)
{
    hide(gf_mul_tower);
    hide(schoolbook64);
    hide(mul64_k);
    hide(square64_twin);
    hide(mul_tau64);
    hide(inv64_twin);

    let l = lo128(a);
    let h = hi128(a);

    let ln = l as nat;
    let hn = h as nat;

    let sh = square64_twin(h);
    let sl = square64_twin(l);

    let t = mul_tau64(sh);
    let c = mul64_k(h, l);

    let norm = t ^ c ^ sl;
    let ninv = inv64_twin(norm);

    assert(pow2(128) == 0x1_0000_0000_0000_0000_0000_0000_0000_0000) by (compute);

    deg_lt_conv(a as nat, 128);
    split128(a);

    square64_is_schoolbook(h);
    square64_is_schoolbook(l);

    mul_tau64_is_schoolbook(sh);
    mul64_matches_schoolbook(h, l);

    bridge64(h, h);
    bridge64(l, l);
    bridge64(sh, 0x2000_0000_0000_0000);
    bridge64(h, l);

    gf_mul_tower_comm(hn, ln, 64);

    assert(tau_tower(64) == 0x2000_0000_0000_0000) by (compute);

    xor64(t, c);
    xor64(t ^ c, sl);

    let t1 = gf_mul_tower(ln, ln, 64);
    let t2 = gf_mul_tower(ln, hn, 64);
    let t3 = gf_mul_tower(gf_mul_tower(hn, hn, 64), tau_tower(64), 64);

    xor_comm(xor(t3, t2), t1);
    xor_comm(t3, t2);
    xor_assoc(t1, t2, t3);

    assert(norm as nat == ext_norm(ln, hn, 64));

    inv64_correct(norm);

    let s = if h == 0 { l } else { h };

    inv64_correct(s);

    if a != 0 {
        norm_nonzero(a as nat, 128, inv64_twin(s) as nat);
    }

    quad_ext_inverse(a as nat, 128, ninv as nat);

    xor64(h, l);
    mul64_matches_schoolbook(h ^ l, ninv);
    mul64_matches_schoolbook(h, ninv);
    bridge64(h ^ l, ninv);
    bridge64(h, ninv);
    pack128(mul64_k(h ^ l, ninv), mul64_k(h, ninv));
}

pub open spec fn inv256_twin(alo: u128, ahi: u128) -> (u128, u128) {
    let norm = mul_tau128(square128_twin(ahi)) ^ mul128_k(ahi, alo) ^ square128_twin(alo);
    let ninv = inv128_twin(norm);

    (mul128_k(ahi ^ alo, ninv), mul128_k(ahi, ninv))
}

pub proof fn inv256_correct(alo: u128, ahi: u128)
    ensures ({
        let r = inv256_twin(alo, ahi);

        is_correct_inverse(
            (alo as nat) + pow2(128) * (ahi as nat),
            (r.0 as nat) + pow2(128) * (r.1 as nat),
            256,
        )
    })
{
    hide(gf_mul_tower);
    hide(schoolbook128);
    hide(mul128_k);
    hide(square128_twin);
    hide(mul_tau128);
    hide(inv128_twin);

    let a = (alo as nat) + pow2(128) * (ahi as nat);

    let ln = alo as nat;
    let hn = ahi as nat;

    let sh = square128_twin(ahi);
    let sl = square128_twin(alo);

    let t = mul_tau128(sh);
    let c = mul128_k(ahi, alo);

    let norm = t ^ c ^ sl;
    let ninv = inv128_twin(norm);

    assert(pow2(128) == 0x1_0000_0000_0000_0000_0000_0000_0000_0000) by (compute);

    pow2_add(128, 128);
    assert(ln + pow2(128) * hn < pow2(256)) by (nonlinear_arith)
        requires
            ln < pow2(128),
            hn < pow2(128),
            pow2(256) == pow2(128) * pow2(128),
            pow2(128) > 0,
    ;
    deg_lt_conv(a, 256);
    pack_mod_div(ln, hn, 128);

    square128_is_schoolbook(ahi);
    square128_is_schoolbook(alo);

    mul_tau128_is_schoolbook(sh);
    mul128_matches_schoolbook(ahi, alo);

    bridge128(ahi, ahi);
    bridge128(alo, alo);
    bridge128(sh, 0x2000_0000_0000_0000_0000_0000_0000_0000);
    bridge128(ahi, alo);

    gf_mul_tower_comm(hn, ln, 128);

    assert(tau_tower(128) == 0x2000_0000_0000_0000_0000_0000_0000_0000) by (compute);

    xor128(t, c);
    xor128(t ^ c, sl);

    let t1 = gf_mul_tower(ln, ln, 128);
    let t2 = gf_mul_tower(ln, hn, 128);
    let t3 = gf_mul_tower(gf_mul_tower(hn, hn, 128), tau_tower(128), 128);

    xor_comm(xor(t3, t2), t1);
    xor_comm(t3, t2);
    xor_assoc(t1, t2, t3);

    assert(norm as nat == ext_norm(ln, hn, 128));

    inv128_correct(norm);

    let s = if ahi == 0 { alo } else { ahi };

    inv128_correct(s);

    if a != 0 {
        norm_nonzero(a, 256, inv128_twin(s) as nat);
    }

    quad_ext_inverse(a, 256, ninv as nat);

    xor128(ahi, alo);
    mul128_matches_schoolbook(ahi ^ alo, ninv);
    mul128_matches_schoolbook(ahi, ninv);
    bridge128(ahi ^ alo, ninv);
    bridge128(ahi, ninv);
}

fn main() {}

}
