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

//! Twins of `BinaryFieldExtras`: the macro-generated `square`
//! override at 16/32/64/128, the default `frobenius` (with its
//! `k % BITS` reduction) and the default `trace` loop, each
//! tied to the `gf_model` tower semantics. `solve_quadratic`'s
//! value path is the proven `map_ct` fold (flat/convert.rs);
//! its basis constants are discharged at build time
//! (TRUSTED_AXIOMS.md). Frobenius order and Tr(τ_m) = 1 hold
//! at every level, by tower induction from GF(2^8).

use vstd::prelude::*;

#[path = "tower/bridge.rs"]
pub mod bridge;

use bridge::b256::b128::b64::b32::b16::b8::{mul_tau8, mul_tau8_is_schoolbook, schoolbook8};
use bridge::b256::b128::b64::b32::b16::{
    hi, lo, mul_tau16, mul_tau16_is_schoolbook, pack, schoolbook16,
};
use bridge::b256::b128::b64::b32::{
    hi as hi32, lo as lo32, mul_tau32, mul_tau32_is_schoolbook, pack as pack32, schoolbook32,
};
use bridge::b256::b128::b64::{
    hi as hi64, lo as lo64, mul_tau64, mul_tau64_is_schoolbook, pack as pack64, schoolbook64,
};
use bridge::b256::b128::{hi as hi128, lo as lo128, pack as pack128, schoolbook128};
use bridge::gf_model::{
    clmul_one_r, deg_lt_conv, deg_modulus, deg_upper, deg_xor_lt, gf_mul_tower, gf_mul_tower_assoc,
    gf_mul_tower_bound, gf_mul_tower_comm, gf_mul_tower_distrib_r, gf_mul_tower_sq_additive,
    gf_mul_tower_unfold, gf_mul_tower_zero_l, gf_mul_tower_zero_r, hi_half, in_field,
    linear_determined_field, lo_half, lo_plus_hipart_is_xor, modulus, pack_mod_div, pmod, pow_2exp,
    pow_2exp_add, pow_2exp_additive, pow2, pow2_add, pow2_pos, split_pack, tau_tower, trace_spec,
    trace_sq_shift, xor, xor_assoc, xor_lt_pow2, xor_pack, xor_rearrange4, xor_self, xor_zero,
};
use bridge::{bridge16, bridge32, bridge64, bridge128, xor16};

verus! {

// Block8::square, block8.rs:
// carryless bit spread, then two folds of the high half by 0x1b.
pub open spec fn square8_spread(a: u8) -> u8 {
    let s0 = a as u16;
    let s1 = (s0 | (s0 << 4)) & 0x0f0f;
    let s2 = (s1 | (s1 << 2)) & 0x3333;
    let s3 = (s2 | (s2 << 1)) & 0x5555;

    let h1 = s3 >> 8;
    let t1 = (s3 & 0x00ff) ^ (h1 ^ (h1 << 1) ^ (h1 << 3) ^ (h1 << 4));

    let h2 = t1 >> 8;
    ((t1 & 0x00ff) ^ (h2 ^ (h2 << 1) ^ (h2 << 3) ^ (h2 << 4))) as u8
}

pub proof fn square8_spread_is_schoolbook(a: u8)
    ensures square8_spread(a) == schoolbook8(a, a)
{
    assert(square8_spread(a) == schoolbook8(a, a)) by (bit_vector);
}

pub proof fn schoolbook8_comm(a: u8, b: u8)
    ensures schoolbook8(a, b) == schoolbook8(b, a)
{
    assert(schoolbook8(a, b) == schoolbook8(b, a)) by (bit_vector);
}

// The impl_binary_field_extras! square shape (src/algebra.rs),
// instantiated at 16/32/64/128 in the tower files: no cross
// term, new_lo = lo^2 + tau * hi^2, new_hi = hi^2.
pub open spec fn square16_twin(x: u16) -> u16 {
    let l2 = square8_spread(lo(x));
    let h2 = square8_spread(hi(x));

    pack(l2 ^ mul_tau8(h2), h2)
}

pub proof fn square16_is_schoolbook(x: u16)
    ensures square16_twin(x) == schoolbook16(x, x)
{
    let l = lo(x);
    let h = hi(x);

    square8_spread_is_schoolbook(l);
    square8_spread_is_schoolbook(h);

    mul_tau8_is_schoolbook(square8_spread(h));

    schoolbook8_comm(l, h);

    let c = schoolbook8(l, h);
    let v = schoolbook8(h, h);

    assert(c ^ c ^ v == v) by (bit_vector);
    assert(square16_twin(x) == schoolbook16(x, x));
}

pub proof fn square16_twin_correct(x: u16)
    ensures square16_twin(x) as nat == gf_mul_tower(x as nat, x as nat, 16)
{
    square16_is_schoolbook(x);
    bridge16(x, x);
}

// schoolbookN commutes: both operand orders
// bridge to the same gf_mul_tower product.
pub proof fn schoolbook16_comm(a: u16, b: u16)
    ensures schoolbook16(a, b) == schoolbook16(b, a)
{
    bridge16(a, b);
    bridge16(b, a);
    gf_mul_tower_comm(a as nat, b as nat, 16);
}

pub proof fn schoolbook32_comm(a: u32, b: u32)
    ensures schoolbook32(a, b) == schoolbook32(b, a)
{
    bridge32(a, b);
    bridge32(b, a);
    gf_mul_tower_comm(a as nat, b as nat, 32);
}

pub proof fn schoolbook64_comm(a: u64, b: u64)
    ensures schoolbook64(a, b) == schoolbook64(b, a)
{
    bridge64(a, b);
    bridge64(b, a);
    gf_mul_tower_comm(a as nat, b as nat, 64);
}

// The same split-square shape one level up per width; each tau
// literal is tau_tower(N/2), pinned by compute in bridge.rs.
pub open spec fn square32_twin(x: u32) -> u32 {
    let l2 = square16_twin(lo32(x));
    let h2 = square16_twin(hi32(x));

    pack32(l2 ^ mul_tau16(h2), h2)
}

pub proof fn square32_is_schoolbook(x: u32)
    ensures square32_twin(x) == schoolbook32(x, x)
{
    let l = lo32(x);
    let h = hi32(x);

    square16_is_schoolbook(l);
    square16_is_schoolbook(h);

    mul_tau16_is_schoolbook(square16_twin(h));

    schoolbook16_comm(l, h);

    let c = schoolbook16(l, h);
    let v = schoolbook16(h, h);

    assert(c ^ c ^ v == v) by (bit_vector);
    assert(square32_twin(x) == schoolbook32(x, x));
}

pub proof fn square32_twin_correct(x: u32)
    ensures square32_twin(x) as nat == gf_mul_tower(x as nat, x as nat, 32)
{
    square32_is_schoolbook(x);
    bridge32(x, x);
}

pub open spec fn square64_twin(x: u64) -> u64 {
    let l2 = square32_twin(lo64(x));
    let h2 = square32_twin(hi64(x));

    pack64(l2 ^ mul_tau32(h2), h2)
}

pub proof fn square64_is_schoolbook(x: u64)
    ensures square64_twin(x) == schoolbook64(x, x)
{
    let l = lo64(x);
    let h = hi64(x);

    square32_is_schoolbook(l);
    square32_is_schoolbook(h);

    mul_tau32_is_schoolbook(square32_twin(h));

    schoolbook32_comm(l, h);

    let c = schoolbook32(l, h);
    let v = schoolbook32(h, h);

    assert(c ^ c ^ v == v) by (bit_vector);
    assert(square64_twin(x) == schoolbook64(x, x));
}

pub proof fn square64_twin_correct(x: u64)
    ensures square64_twin(x) as nat == gf_mul_tower(x as nat, x as nat, 64)
{
    square64_is_schoolbook(x);
    bridge64(x, x);
}

pub open spec fn square128_twin(x: u128) -> u128 {
    let l2 = square64_twin(lo128(x));
    let h2 = square64_twin(hi128(x));

    pack128(l2 ^ mul_tau64(h2), h2)
}

pub proof fn square128_is_schoolbook(x: u128)
    ensures square128_twin(x) == schoolbook128(x, x)
{
    let l = lo128(x);
    let h = hi128(x);

    square64_is_schoolbook(l);
    square64_is_schoolbook(h);

    mul_tau64_is_schoolbook(square64_twin(h));

    schoolbook64_comm(l, h);

    let c = schoolbook64(l, h);
    let v = schoolbook64(h, h);

    assert(c ^ c ^ v == v) by (bit_vector);
    assert(square128_twin(x) == schoolbook128(x, x));
}

pub proof fn square128_twin_correct(x: u128)
    ensures square128_twin(x) as nat == gf_mul_tower(x as nat, x as nat, 128)
{
    square128_is_schoolbook(x);
    bridge128(x, x);
}

// The default frobenius loop, algebra.rs:
// acc squared `reps` times.
pub open spec fn sq_iter16(x: u16, n: nat) -> u16
    decreases n
{
    if n == 0 {
        x
    } else {
        square16_twin(sq_iter16(x, (n - 1) as nat))
    }
}

pub open spec fn frobenius16_twin(x: u16, k: u32) -> u16 {
    sq_iter16(x, (k % 16) as nat)
}

pub proof fn sq_iter16_reflect(x: u16, n: nat)
    ensures sq_iter16(x, n) as nat == pow_2exp(x as nat, n, 16)
    decreases n
{
    if n == 0 {
    } else {
        sq_iter16_reflect(x, (n - 1) as nat);
        square16_twin_correct(sq_iter16(x, (n - 1) as nat));
    }
}

proof fn u16_in_field(x: u16)
    ensures bridge::gf_model::in_field(x as nat, 16)
{
    assert(pow2(16) == 0x10000) by (compute);
    deg_lt_conv(x as nat, 16);
}

// The `k % BITS` reduction computes the full
// k-fold Frobenius, x^(2^k), for every k.
pub proof fn frobenius16_semantics(x: u16, k: u32)
    ensures frobenius16_twin(x, k) as nat == pow_2exp(x as nat, k as nat, 16)
{
    sq_iter16_reflect(x, (k % 16) as nat);
    u16_in_field(x);
    frobenius_mod_cycle(x as nat, k as nat, 16);

    assert((k % 16) as nat == (k as nat) % 16);
}

// The default trace loop, algebra.rs:
// acc accumulates the Frobenius orbit.
pub open spec fn trace_iter16(x: u16, n: nat) -> u16
    decreases n
{
    if n == 0 {
        0
    } else {
        trace_iter16(x, (n - 1) as nat) ^ sq_iter16(x, (n - 1) as nat)
    }
}

pub proof fn trace_iter16_reflect(x: u16, n: nat)
    ensures trace_iter16(x, n) as nat == trace_spec(x as nat, n, 16)
    decreases n
{
    if n == 0 {
    } else {
        trace_iter16_reflect(x, (n - 1) as nat);
        sq_iter16_reflect(x, (n - 1) as nat);
        xor16(trace_iter16(x, (n - 1) as nat), sq_iter16(x, (n - 1) as nat));
    }
}

// The trace is fixed by squaring, Tr(x)^2 == Tr(x).
// Membership in {0, 1} additionally needs zero-divisor
// freedom; build/main.rs::write_algebra_extras_16 checks it
// exhaustively on all 2^16 inputs.
pub proof fn trace16_idempotent(x: u16)
    ensures ({
        let t = trace_iter16(x, 16);
        square16_twin(t) == t
    })
{
    let t = trace_iter16(x, 16);

    trace_iter16_reflect(x, 16);
    square16_twin_correct(t);
    u16_in_field(x);
    trace_idempotent(x as nat, 16);

    assert(square16_twin(t) as nat == t as nat);
}

pub proof fn frobenius_and_trace(k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures
        forall|x: nat| in_field(x, k) ==> #[trigger] pow_2exp(x, k, k) == x,
        trace_spec(tau_tower(k), k, k) == 1,
    decreases k
{
    if k == 8 {
        frobenius_and_trace8();
    } else {
        let m = (k / 2) as nat;

        frobenius_and_trace(m);

        assert forall|x: nat| in_field(x, k) implies #[trigger] pow_2exp(x, k, k) == x by {
            frobenius_lift(x, k);
        }

        trace_lift(k);
    }
}

// x^(2^k) == x for every field element.
pub proof fn frobenius_order(x: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        in_field(x, k),
    ensures pow_2exp(x, k, k) == x
{
    frobenius_and_trace(k);
}

// Justifies production frobenius's `k % BITS` reduction.
pub proof fn frobenius_mod_cycle(x: nat, e: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        in_field(x, k),
    ensures pow_2exp(x, e, k) == pow_2exp(x, (e % k) as nat, k)
    decreases e
{
    if e < k {
        vstd::arithmetic::div_mod::lemma_small_mod(e, k);
    } else {
        pow_2exp_add(x, k, (e - k) as nat, k);
        frobenius_order(x, k);
        frobenius_mod_cycle(x, (e - k) as nat, k);

        vstd::arithmetic::div_mod::lemma_mod_sub_multiples_vanish(e as int, k as int);
    }
}

// Tr(x)^2 == Tr(x): the trace lands in the
// Frobenius-fixed subfield GF(2).
pub proof fn trace_idempotent(x: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        in_field(x, k),
    ensures ({
        let t = trace_spec(x, k, k);
        gf_mul_tower(t, t, k) == t
    })
{
    trace_sq_shift(x, k, k);
    frobenius_order(x, k);

    let t = trace_spec(x, k, k);

    assert(trace_spec(x, k + 1, k) == xor(t, x));

    xor_assoc(t, x, x);
    xor_self(x);
    xor_zero(t);
}

proof fn frobenius_and_trace8()
    ensures
        forall|x: nat| in_field(x, 8) ==> #[trigger] pow_2exp(x, 8, 8) == x,
        trace_spec(tau_tower(8), 8, 8) == 1,
{
    let f = |y: nat| pow_2exp(y, 8, 8);
    let g = |y: nat| y;

    assert(trace_spec(tau_tower(8), 8, 8) == 1) by (compute);

    assert forall|u: nat, v: nat| in_field(u, 8) && in_field(v, 8)
        implies #[trigger] f(xor(u, v)) == xor(f(u), f(v)) by {
        pow_2exp_additive(u, v, 8, 8);
    }

    assert forall|u: nat, v: nat| in_field(u, 8) && in_field(v, 8)
        implies #[trigger] g(xor(u, v)) == xor(g(u), g(v)) by {
    }

    assert forall|i: nat| i < 8 implies #[trigger] f(pow2(i)) == g(pow2(i)) by {
        if i == 0 {
            assert(pow_2exp(pow2(0), 8, 8) == pow2(0)) by (compute);
        } else if i == 1 {
            assert(pow_2exp(pow2(1), 8, 8) == pow2(1)) by (compute);
        } else if i == 2 {
            assert(pow_2exp(pow2(2), 8, 8) == pow2(2)) by (compute);
        } else if i == 3 {
            assert(pow_2exp(pow2(3), 8, 8) == pow2(3)) by (compute);
        } else if i == 4 {
            assert(pow_2exp(pow2(4), 8, 8) == pow2(4)) by (compute);
        } else if i == 5 {
            assert(pow_2exp(pow2(5), 8, 8) == pow2(5)) by (compute);
        } else if i == 6 {
            assert(pow_2exp(pow2(6), 8, 8) == pow2(6)) by (compute);
        } else {
            assert(pow_2exp(pow2(7), 8, 8) == pow2(7)) by (compute);
        }
    }

    assert forall|x: nat| in_field(x, 8) implies #[trigger] pow_2exp(x, 8, 8) == x by {
        linear_determined_field(f, g, x, 8);
    }
}

proof fn frobenius_lift(x: nat, k: nat)
    requires
        k == 16 || k == 32 || k == 64 || k == 128,
        in_field(x, k),
        forall|y: nat| in_field(y, (k / 2) as nat)
            ==> #[trigger] pow_2exp(y, (k / 2) as nat, (k / 2) as nat) == y,
        trace_spec(tau_tower((k / 2) as nat), (k / 2) as nat, (k / 2) as nat) == 1,
    ensures pow_2exp(x, k, k) == x
{
    hide(gf_mul_tower);

    let m = (k / 2) as nat;
    let x0 = lo_half(x, k);
    let x1 = hi_half(x, k);
    let y0 = xor(x0, x1);
    let y = y0 + pow2(m) * x1;

    halves(x, k);
    half_frobenius(x, k);
    xor_lt_pow2(x0, x1, m);
    pack_mod_div(y0, x1, m);
    pack_in_field(y0, x1, k);
    half_frobenius(y, k);

    xor_assoc(x0, x1, x1);
    xor_self(x1);
    xor_zero(x0);

    pow_2exp_add(x, m, m, k);

    assert(m + m == k);
}

proof fn trace_lift(k: nat)
    requires
        k == 16 || k == 32 || k == 64 || k == 128,
        forall|y: nat| in_field(y, (k / 2) as nat)
            ==> #[trigger] pow_2exp(y, (k / 2) as nat, (k / 2) as nat) == y,
        trace_spec(tau_tower((k / 2) as nat), (k / 2) as nat, (k / 2) as nat) == 1,
    ensures trace_spec(tau_tower(k), k, k) == 1
{
    hide(gf_mul_tower);

    let m = (k / 2) as nat;
    let t = tau_tower(m);
    let tk = tau_tower(k);
    let y = pow_2exp(tk, m, k);

    tau_step(k);
    tau_in_field(m);
    deg_upper(t, m);
    pow2_pos(m);

    assert(tk == 0 + pow2(m) * t);

    pack_mod_div(0, t, m);
    pack_in_field(0, t, k);
    half_frobenius(tk, k);
    xor_zero(t);

    trace_split(tk, m, m, k);
    trace_additive(tk, y, m, k);
    xor_pack(0, t, t, t, m);
    xor_self(t);
    embed_trace(t, m, k);

    assert(m + m == k);
}

proof fn half_frobenius(x: nat, k: nat)
    requires
        k == 16 || k == 32 || k == 64 || k == 128,
        in_field(x, k),
        forall|y: nat| in_field(y, (k / 2) as nat)
            ==> #[trigger] pow_2exp(y, (k / 2) as nat, (k / 2) as nat) == y,
        trace_spec(tau_tower((k / 2) as nat), (k / 2) as nat, (k / 2) as nat) == 1,
    ensures
        pow_2exp(x, (k / 2) as nat, k)
            == xor(lo_half(x, k), hi_half(x, k)) + pow2((k / 2) as nat) * hi_half(x, k),
{
    hide(gf_mul_tower);

    let m = (k / 2) as nat;
    let v = pow2(m);
    let x0 = lo_half(x, k);
    let x1 = hi_half(x, k);
    let x1v = gf_mul_tower(x1, v, k);

    halves(x, k);
    split_pack(x, m);
    mul_by_v(x1, k);
    pow_2exp_additive(x0, x1v, m, k);

    embed_pow(x0, m, k);
    embed_pow(x1, m, k);
    pow_2exp_mul(x1, v, m, k);
    v_chain(k, m);

    gf_mul_tower_distrib_r(x1, 1, v, k);
    tower_one(x1, k);

    xor_assoc(x0, x1, v * x1);
    xor_lt_pow2(x0, x1, m);
    lo_plus_hipart_is_xor(m, xor(x0, x1), x1);
}

proof fn v_chain(k: nat, j: nat)
    requires k == 16 || k == 32 || k == 64 || k == 128,
    ensures
        pow_2exp(pow2((k / 2) as nat), j, k)
            == xor(trace_spec(tau_tower((k / 2) as nat), j, (k / 2) as nat), pow2((k / 2) as nat)),
    decreases j
{
    hide(gf_mul_tower);

    let m = (k / 2) as nat;
    let t = tau_tower(m);
    let v = pow2(m);

    if j == 0 {
        xor_zero(v);
    } else {
        let j1 = (j - 1) as nat;
        let s = trace_spec(t, j1, m);
        let s1 = trace_spec(t, j, m);

        v_chain(k, j1);
        tau_in_field(m);
        trace_in_field(t, j1, m);

        gf_mul_tower_sq_additive(s, v, k);
        embed_mul(s, s, k);
        v_square(k);
        trace_sq_shift(t, j1, m);

        assert(j1 + 1 == j);

        xor_assoc(s1, t, xor(t, v));
        xor_assoc(t, t, v);
        xor_self(t);
        xor_zero(v);
    }
}

pub proof fn pow_2exp_mul(a: nat, b: nat, e: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures
        pow_2exp(gf_mul_tower(a, b, k), e, k)
            == gf_mul_tower(pow_2exp(a, e, k), pow_2exp(b, e, k), k),
    decreases e
{
    hide(gf_mul_tower);

    if e > 0 {
        let e1 = (e - 1) as nat;

        pow_2exp_mul(a, b, e1, k);
        sq_of_product(pow_2exp(a, e1, k), pow_2exp(b, e1, k), k);
    }
}

pub proof fn sq_of_product(x: nat, y: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures
        gf_mul_tower(gf_mul_tower(x, y, k), gf_mul_tower(x, y, k), k)
            == gf_mul_tower(gf_mul_tower(x, x, k), gf_mul_tower(y, y, k), k),
{
    hide(gf_mul_tower);

    let xy = gf_mul_tower(x, y, k);

    gf_mul_tower_assoc(x, y, xy, k);
    gf_mul_tower_assoc(y, x, y, k);
    gf_mul_tower_comm(y, x, k);
    gf_mul_tower_assoc(x, y, y, k);
    gf_mul_tower_assoc(x, x, gf_mul_tower(y, y, k), k);
}

pub proof fn trace_additive(u: nat, w: nat, n: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures trace_spec(xor(u, w), n, k) == xor(trace_spec(u, n, k), trace_spec(w, n, k))
    decreases n
{
    hide(gf_mul_tower);

    if n == 0 {
        xor_zero(0);
    } else {
        let n1 = (n - 1) as nat;

        trace_additive(u, w, n1, k);
        pow_2exp_additive(u, w, n1, k);
        xor_rearrange4(
            trace_spec(u, n1, k),
            trace_spec(w, n1, k),
            pow_2exp(u, n1, k),
            pow_2exp(w, n1, k),
        );
    }
}

pub proof fn trace_split(x: nat, a: nat, b: nat, k: nat)
    ensures
        trace_spec(x, a + b, k)
            == xor(trace_spec(x, a, k), trace_spec(pow_2exp(x, a, k), b, k)),
    decreases b
{
    hide(gf_mul_tower);

    if b == 0 {
        xor_zero(trace_spec(x, a, k));
    } else {
        let b1 = (b - 1) as nat;
        let y = pow_2exp(x, a, k);

        trace_split(x, a, b1, k);
        pow_2exp_add(x, a, b1, k);
        xor_assoc(trace_spec(x, a, k), trace_spec(y, b1, k), pow_2exp(y, b1, k));

        assert(a + b1 == (a + b - 1) as nat);
    }
}

pub proof fn trace_of_square(t: nat, n: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures
        trace_spec(gf_mul_tower(t, t, k), n, k)
            == gf_mul_tower(trace_spec(t, n, k), trace_spec(t, n, k), k),
    decreases n
{
    hide(gf_mul_tower);

    if n == 0 {
        gf_mul_tower_zero_l(0, k);
    } else {
        let n1 = (n - 1) as nat;
        let s1 = trace_spec(t, n1, k);
        let p = pow_2exp(t, n1, k);

        trace_of_square(t, n1, k);
        pow_2exp_add(t, 1, n1, k);
        gf_mul_tower_sq_additive(s1, p, k);

        assert(pow_2exp(t, 0, k) == t);
        assert(pow_2exp(t, 1, k) == gf_mul_tower(t, t, k));
        assert(1 + n1 == n);
    }
}

pub proof fn trace_in_field(x: nat, n: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        in_field(x, k),
    ensures in_field(trace_spec(x, n, k), k)
    decreases n
{
    hide(gf_mul_tower);

    pow2_pos(k);

    if n == 0 {
        deg_lt_conv(0, k);
    } else {
        let n1 = (n - 1) as nat;

        trace_in_field(x, n1, k);
        pow_2exp_in_field(x, n1, k);
        deg_xor_lt(trace_spec(x, n1, k), pow_2exp(x, n1, k), k);
    }
}

pub proof fn pow_2exp_in_field(x: nat, e: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        in_field(x, k),
    ensures in_field(pow_2exp(x, e, k), k)
{
    hide(gf_mul_tower);

    if e > 0 {
        let p = pow_2exp(x, (e - 1) as nat, k);

        gf_mul_tower_bound(p, p, k);
        deg_lt_conv(gf_mul_tower(p, p, k), k);
    }
}

pub proof fn embed_mul(a: nat, b: nat, k: nat)
    requires
        k == 16 || k == 32 || k == 64 || k == 128,
        in_field(a, (k / 2) as nat),
        in_field(b, (k / 2) as nat),
    ensures gf_mul_tower(a, b, k) == gf_mul_tower(a, b, (k / 2) as nat)
{
    hide(gf_mul_tower);

    let m = (k / 2) as nat;

    sub_halves(a, k);
    sub_halves(b, k);

    gf_mul_tower_unfold(a, b, k);
    gf_mul_tower_zero_l(0, m);
    gf_mul_tower_zero_l(b, m);
    gf_mul_tower_zero_r(a, m);
    gf_mul_tower_zero_l(tau_tower(m), m);

    xor_zero(gf_mul_tower(a, b, m));
    xor_zero(0);

    assert(gf_mul_tower(a, b, k) == gf_mul_tower(a, b, m) + pow2(m) * 0);
}

pub proof fn embed_pow(a: nat, e: nat, k: nat)
    requires
        k == 16 || k == 32 || k == 64 || k == 128,
        in_field(a, (k / 2) as nat),
    ensures pow_2exp(a, e, k) == pow_2exp(a, e, (k / 2) as nat)
    decreases e
{
    hide(gf_mul_tower);

    let m = (k / 2) as nat;

    if e > 0 {
        let e1 = (e - 1) as nat;
        let p = pow_2exp(a, e1, m);

        embed_pow(a, e1, k);
        pow_2exp_in_field(a, e1, m);
        embed_mul(p, p, k);
    }
}

pub proof fn embed_trace(a: nat, n: nat, k: nat)
    requires
        k == 16 || k == 32 || k == 64 || k == 128,
        in_field(a, (k / 2) as nat),
    ensures trace_spec(a, n, k) == trace_spec(a, n, (k / 2) as nat)
    decreases n
{
    hide(gf_mul_tower);

    if n > 0 {
        embed_trace(a, (n - 1) as nat, k);
        embed_pow(a, (n - 1) as nat, k);
    }
}

proof fn mul_by_v(c: nat, k: nat)
    requires
        k == 16 || k == 32 || k == 64 || k == 128,
        in_field(c, (k / 2) as nat),
    ensures gf_mul_tower(c, pow2((k / 2) as nat), k) == pow2((k / 2) as nat) * c
{
    hide(gf_mul_tower);

    let m = (k / 2) as nat;

    sub_halves(c, k);
    v_halves(k);
    tower_one(c, m);

    gf_mul_tower_unfold(c, pow2(m), k);
    gf_mul_tower_zero_r(c, m);
    gf_mul_tower_zero_l(0, m);
    gf_mul_tower_zero_l(1, m);
    gf_mul_tower_zero_l(tau_tower(m), m);

    xor_zero(c);
    xor_zero(0);
}

proof fn v_square(k: nat)
    requires k == 16 || k == 32 || k == 64 || k == 128,
    ensures
        gf_mul_tower(pow2((k / 2) as nat), pow2((k / 2) as nat), k)
            == xor(tau_tower((k / 2) as nat), pow2((k / 2) as nat)),
{
    hide(gf_mul_tower);

    let m = (k / 2) as nat;
    let t = tau_tower(m);

    v_halves(k);
    tau_in_field(m);
    one_in_field(m);
    tower_one(1, m);
    tower_one(t, m);

    gf_mul_tower_unfold(pow2(m), pow2(m), k);
    gf_mul_tower_zero_l(0, m);
    gf_mul_tower_zero_l(1, m);
    gf_mul_tower_zero_r(1, m);

    xor_zero(t);
    xor_zero(0);
    xor_zero(1);

    deg_upper(t, m);
    lo_plus_hipart_is_xor(m, t, 1);
}

pub proof fn tower_one(x: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        in_field(x, k),
    ensures
        gf_mul_tower(x, 1, k) == x,
        gf_mul_tower(1, x, k) == x,
    decreases k
{
    hide(gf_mul_tower);

    gf_mul_tower_comm(1, x, k);

    if k == 8 {
        reveal(gf_mul_tower);
        deg_modulus(8);
        clmul_one_r(x);

        assert(pmod(x, modulus(8)) == x);
    } else {
        let m = (k / 2) as nat;
        let x0 = lo_half(x, k);
        let x1 = hi_half(x, k);

        halves(x, k);
        one_in_field(m);
        sub_halves(1, k);

        tower_one(x0, m);
        tower_one(x1, m);

        gf_mul_tower_unfold(x, 1, k);
        gf_mul_tower_zero_r(x0, m);
        gf_mul_tower_zero_r(x1, m);
        gf_mul_tower_zero_l(tau_tower(m), m);

        xor_zero(x0);
        xor_zero(x1);
    }
}

pub proof fn halves(x: nat, k: nat)
    requires
        k == 16 || k == 32 || k == 64 || k == 128 || k == 256,
        in_field(x, k),
    ensures
        in_field(lo_half(x, k), (k / 2) as nat),
        in_field(hi_half(x, k), (k / 2) as nat),
        lo_half(x, k) < pow2((k / 2) as nat),
        hi_half(x, k) < pow2((k / 2) as nat),
        x == lo_half(x, k) + pow2((k / 2) as nat) * hi_half(x, k),
{
    let m = (k / 2) as nat;
    let p = pow2(m);

    pow2_pos(m);
    pow2_add(m, m);
    deg_upper(x, k);

    assert(m + m == k);

    vstd::arithmetic::div_mod::lemma_fundamental_div_mod(x as int, p as int);
    vstd::arithmetic::div_mod::lemma_mod_pos_bound(x as int, p as int);
    vstd::arithmetic::div_mod::lemma_multiply_divide_lt(x as int, p as int, p as int);

    deg_lt_conv(x % p, m);
    deg_lt_conv(x / p, m);
}

proof fn sub_halves(a: nat, k: nat)
    requires
        k == 16 || k == 32 || k == 64 || k == 128 || k == 256,
        in_field(a, (k / 2) as nat),
    ensures
        lo_half(a, k) == a,
        hi_half(a, k) == 0,
{
    let m = (k / 2) as nat;

    deg_upper(a, m);
    pack_mod_div(a, 0, m);

    assert(a + pow2(m) * 0 == a);
}

proof fn v_halves(k: nat)
    requires k == 16 || k == 32 || k == 64 || k == 128,
    ensures
        lo_half(pow2((k / 2) as nat), k) == 0,
        hi_half(pow2((k / 2) as nat), k) == 1,
{
    let m = (k / 2) as nat;

    pow2_pos(m);
    pack_mod_div(0, 1, m);

    assert(0 + pow2(m) * 1 == pow2(m));
}

proof fn pack_in_field(lo: nat, hi: nat, k: nat)
    requires
        k == 16 || k == 32 || k == 64 || k == 128 || k == 256,
        lo < pow2((k / 2) as nat),
        hi < pow2((k / 2) as nat),
    ensures in_field(lo + pow2((k / 2) as nat) * hi, k)
{
    let m = (k / 2) as nat;

    pow2_pos(m);
    pow2_add(m, m);

    assert(m + m == k);
    assert(lo + pow2(m) * hi < pow2(k)) by (nonlinear_arith)
        requires
            lo < pow2(m),
            hi < pow2(m),
            pow2(k) == pow2(m) * pow2(m),
            pow2(m) > 0;

    deg_lt_conv(lo + pow2(m) * hi, k);
}

pub proof fn one_in_field(k: nat)
    requires k >= 1,
    ensures in_field(1, k)
{
    pow2_pos((k - 1) as nat);

    assert(pow2(k) == 2 * pow2((k - 1) as nat));

    deg_lt_conv(1, k);
}

pub proof fn tau_in_field(m: nat)
    requires m == 8 || m == 16 || m == 32 || m == 64 || m == 128,
    ensures in_field(tau_tower(m), m)
{
    if m == 8 {
        assert(tau_tower(8) < pow2(8)) by (compute);
    } else if m == 16 {
        assert(tau_tower(16) < pow2(16)) by (compute);
    } else if m == 32 {
        assert(tau_tower(32) < pow2(32)) by (compute);
    } else if m == 64 {
        assert(tau_tower(64) < pow2(64)) by (compute);
    } else {
        assert(tau_tower(128) < pow2(128)) by (compute);
    }

    deg_lt_conv(tau_tower(m), m);
}

proof fn tau_step(k: nat)
    requires k == 16 || k == 32 || k == 64 || k == 128,
    ensures tau_tower(k) == pow2((k / 2) as nat) * tau_tower((k / 2) as nat)
{
    if k == 16 {
        assert(tau_tower(16) == pow2(8) * tau_tower(8)) by (compute);
    } else if k == 32 {
        assert(tau_tower(32) == pow2(16) * tau_tower(16)) by (compute);
    } else if k == 64 {
        assert(tau_tower(64) == pow2(32) * tau_tower(32)) by (compute);
    } else {
        assert(tau_tower(128) == pow2(64) * tau_tower(64)) by (compute);
    }
}

fn main() {}

}
