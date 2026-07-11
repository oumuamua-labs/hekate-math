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

//! Twins of `BinaryFieldExtras` at GF(2^16): the `square`
//! override, the default `frobenius` (with its `k % BITS`
//! reduction) and the default `trace` loop, each tied to the
//! `gf_model` tower semantics. `solve_quadratic` rests on the
//! generated basis matrix, discharged exhaustively at build
//! time (TRUSTED_AXIOMS.md).

use vstd::prelude::*;

#[path = "tower_bridge.rs"]
pub mod bridge;

use bridge::b256::b128::b64::b32::b16::b8::schoolbook8;
use bridge::b256::b128::b64::b32::b16::{hi, lo, pack, schoolbook16};
use bridge::gf_model::{
    deg_lt_conv, frobenius_mod_cycle, gf_mul_tower, pow_2exp, pow2, trace_idempotent, trace_spec,
};
use bridge::{bridge16, xor16};

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

// Block16::square, block16.rs:527-536: no cross term,
// new_lo = lo^2 + tau * hi^2, new_hi = hi^2.
pub open spec fn square16_twin(x: u16) -> u16 {
    let l2 = square8_spread(lo(x));
    let h2 = square8_spread(hi(x));

    pack(l2 ^ schoolbook8(h2, 0x20), h2)
}

pub proof fn square16_twin_correct(x: u16)
    ensures square16_twin(x) as nat == gf_mul_tower(x as nat, x as nat, 16)
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

    bridge16(x, x);
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
