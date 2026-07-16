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
//! value path is the proven `map_ct` fold (neon/convert.rs);
//! its basis constants are discharged at build time
//! (TRUSTED_AXIOMS.md).

use vstd::prelude::*;

#[path = "tower/bridge.rs"]
pub mod bridge;

use bridge::b256::b128::b64::b32::b16::b8::schoolbook8;
use bridge::b256::b128::b64::b32::b16::{hi, lo, pack, schoolbook16};
use bridge::b256::b128::b64::b32::{hi as hi32, lo as lo32, pack as pack32, schoolbook32};
use bridge::b256::b128::b64::{hi as hi64, lo as lo64, pack as pack64, schoolbook64};
use bridge::b256::b128::{hi as hi128, lo as lo128, pack as pack128, schoolbook128};
use bridge::gf_model::{
    deg_lt_conv, frobenius_mod_cycle, gf_mul_tower, gf_mul_tower_comm, pow_2exp, pow2,
    trace_idempotent, trace_spec,
};
use bridge::{bridge16, bridge32, bridge64, bridge128, xor16};

verus! {

// Block8::square, block8.rs:72-85: carryless bit spread,
// then two folds of the high half by 0x1b.
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

    pack(l2 ^ schoolbook8(h2, 0x20), h2)
}

pub proof fn square16_is_schoolbook(x: u16)
    ensures square16_twin(x) == schoolbook16(x, x)
{
    let l = lo(x);
    let h = hi(x);

    square8_spread_is_schoolbook(l);
    square8_spread_is_schoolbook(h);
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

    pack32(l2 ^ schoolbook16(h2, 0x2000), h2)
}

pub proof fn square32_is_schoolbook(x: u32)
    ensures square32_twin(x) == schoolbook32(x, x)
{
    let l = lo32(x);
    let h = hi32(x);

    square16_is_schoolbook(l);
    square16_is_schoolbook(h);
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

    pack64(l2 ^ schoolbook32(h2, 0x2000_0000), h2)
}

pub proof fn square64_is_schoolbook(x: u64)
    ensures square64_twin(x) == schoolbook64(x, x)
{
    let l = lo64(x);
    let h = hi64(x);

    square32_is_schoolbook(l);
    square32_is_schoolbook(h);
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

    pack128(l2 ^ schoolbook64(h2, 0x2000_0000_0000_0000), h2)
}

pub proof fn square128_is_schoolbook(x: u128)
    ensures square128_twin(x) == schoolbook128(x, x)
{
    let l = lo128(x);
    let h = hi128(x);

    square64_is_schoolbook(l);
    square64_is_schoolbook(h);
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

// The default frobenius loop, algebra.rs:32-41:
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

// The default trace loop, algebra.rs:45-55:
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

fn main() {}

}
