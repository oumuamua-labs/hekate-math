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

#[cfg(verus_keep_ghost)]
use super::bridge::gf_model;
#[cfg(verus_keep_ghost)]
use super::bridge::{fold_step, pmod_below, r_poly};

#[cfg(verus_keep_ghost)]
use gf_model::{
    clmul, clmul_distrib_r, clmul_one_l, clmul_one_r, clmul_pow2, clmul_zero_r, deg, deg_lt_conv,
    deg_modulus, deg_pow2, gf_mul, gf_mul_assoc, lo_plus_hipart_is_xor, modulus, pmod,
    pmod_additive, pow2, xor, xor_assoc, xor_comm, xor_lt_pow2, xor_zero,
};
#[cfg(verus_keep_ghost)]
use vstd::arithmetic::div_mod::{
    lemma_div_denominator, lemma_fundamental_div_mod, lemma_fundamental_div_mod_converse_div,
    lemma_fundamental_div_mod_converse_mod,
};
#[cfg(verus_keep_ghost)]
use vstd::arithmetic::mul::{lemma_mul_inequality, lemma_mul_is_associative};

verus! {

// ============================================================
// Exec twin plumbing: u128 elements model Flat<F>, usize is
// pinned to 64 bits (the aarch64/x86_64 deployment targets)
// ============================================================

pub proof fn pow2_bridge(e: nat)
    ensures pow2(e) == vstd::arithmetic::power2::pow2(e)
    decreases e
{
    if e == 0 {
        vstd::arithmetic::power::lemma_pow0(2);
    } else {
        pow2_bridge((e - 1) as nat);
        vstd::arithmetic::power2::lemma_pow2_unfold(e);
    }
}

pub proof fn xor128_reflect(x: u128, y: u128)
    ensures xor(x as nat, y as nat) == (x ^ y) as nat
    decreases x as nat + y as nat
{
    if x == 0 && y == 0 {
        assert(xor(x as nat, y as nat) == 0) by {
            reveal_with_fuel(xor, 1);
        }
        assert(x ^ y == 0) by (bit_vector) requires x == 0 && y == 0;
    } else {
        xor128_reflect(x / 2, y / 2);

        let xl = (x % 2) ^ (y % 2);
        let xh = (x / 2) ^ (y / 2);

        assert((x as nat) / 2 == (x / 2) as nat);
        assert((y as nat) / 2 == (y / 2) as nat);
        assert(xor((x as nat) / 2, (y as nat) / 2) == xh as nat);

        assert(xor(x as nat, y as nat) == ((x as nat) % 2 + (y as nat) % 2) % 2 + 2
            * xor((x as nat) / 2, (y as nat) / 2)) by {
            reveal_with_fuel(xor, 1);
        }

        assert((x % 2) ^ (y % 2) == ((x % 2) + (y % 2)) % 2) by (bit_vector);
        assert(((x as nat) % 2 + (y as nat) % 2) % 2 == xl as nat);
        assert(x ^ y == ((x % 2) ^ (y % 2)) + 2 * ((x / 2) ^ (y / 2))) by (bit_vector);
        assert((x ^ y) as nat == xl as nat + 2 * (xh as nat));
        assert(xor(x as nat, y as nat) == xl as nat + 2 * (xh as nat));
    }
}

pub fn mul_flat(a: u128, b: u128) -> (r: u128)
    ensures r as nat == gf_mul(a as nat, b as nat, 128)
{
    let mut acc: u128 = 0;
    let mut x: u128 = a;
    let mut bb: u128 = b;
    let mut i: usize = 0;

    let ghost mut done: nat = 0;

    proof {
        deg_modulus(128);
        assert(pow2(0) == 1) by (compute);
        assert(pow2(128) == 0x1_0000_0000_0000_0000_0000_0000_0000_0000) by (compute);
        assert(deg(0) == -1);

        clmul_zero_r(a as nat);
        pmod_below(0, 128);
        clmul_one_r(a as nat);
        deg_lt_conv(a as nat, 128);
        pmod_below(a as nat, 128);
    }

    while i < 128
        invariant
            i <= 128,
            b as nat == (bb as nat) * pow2(i as nat) + done,
            done < pow2(i as nat),
            acc as nat == gf_mul(a as nat, done, 128),
            i < 128 ==> x as nat == gf_mul(a as nat, pow2(i as nat), 128),
        decreases 128 - i,
    {
        let ghost n = i as nat;
        let ghost p = pow2(n);
        let ghost done0 = done;
        let ghost q = (bb / 2) as nat;
        let ghost xi = x as nat;
        let bit = bb % 2;

        proof {
            deg_modulus(128);

            assert(pow2(1) == 2) by (compute);
            assert(pow2(128) == 0x1_0000_0000_0000_0000_0000_0000_0000_0000) by (compute);
            assert(pow2(n + 1) == 2 * p);

            lemma_fundamental_div_mod(bb as int, 2);

            assert(bb as nat == 2 * q + (bit as nat));
            assert((2 * q + (bit as nat)) * p == q * (2 * p) + p * (bit as nat))
                by (nonlinear_arith);

            if bit == 1 {
                assert(p * (bit as nat) == p);

                lo_plus_hipart_is_xor(n, done0, 1);
                clmul_distrib_r(a as nat, done0, p);
                pmod_additive(clmul(a as nat, done0), clmul(a as nat, p), modulus(128));
                xor128_reflect(acc, x);
            } else {
                assert(p * (bit as nat) == 0);
            }
        }

        if bit == 1 {
            acc ^= x;
        }

        proof {
            done = done0 + p * (bit as nat);
            clmul_pow2(xi, 1);
            deg_lt_conv(xi, 128);
        }

        if x < 0x8000_0000_0000_0000_0000_0000_0000_0000u128 {
            proof {
                deg_lt_conv(2 * xi, 128);
                pmod_below(2 * xi, 128);
            }

            x *= 2;

            proof {
                assert(clmul(xi, 2) == 2 * xi);
                assert(x as nat == gf_mul(xi, 2, 128));
            }
        } else {
            let rr = (x - 0x8000_0000_0000_0000_0000_0000_0000_0000u128) * 2;

            proof {
                assert(2 * xi == (rr as nat) + pow2(128) * 1);

                lo_plus_hipart_is_xor(128, rr as nat, 1);
                fold_step(rr as nat, 1, 128);
                clmul_one_l(0x87);
                assert(r_poly(128) == 0x87);
                xor_lt_pow2(rr as nat, 0x87, 128);
                deg_lt_conv(xor(rr as nat, 0x87), 128);
                pmod_below(xor(rr as nat, 0x87), 128);
                xor128_reflect(rr, 0x87);
            }

            x = rr ^ 0x87;

            proof {
                assert(clmul(xi, 2) == 2 * xi);
                assert(pmod(2 * xi, modulus(128)) == xor(rr as nat, 0x87));
                assert(x as nat == gf_mul(xi, 2, 128));
            }
        }

        proof {
            if n + 1 < 128 {
                gf_mul_assoc(a as nat, p, 2, 128);
                clmul_pow2(p, 1);
                deg_pow2(n + 1);
                pmod_below(pow2(n + 1), 128);

                assert(gf_mul(p, 2, 128) == pow2(n + 1));
                assert(x as nat == gf_mul(a as nat, pow2(n + 1), 128));
            }
        }

        bb /= 2;
        i += 1;
    }

    proof {
        assert(pow2(128) == 0x1_0000_0000_0000_0000_0000_0000_0000_0000) by (compute);

        if bb >= 1 {
            lemma_mul_inequality(1, bb as int, pow2(128) as int);
            assert(false);
        }
    }

    acc
}

pub fn add_flat(a: u128, b: u128) -> (r: u128)
    ensures r as nat == xor(a as nat, b as nat)
{
    proof {
        xor128_reflect(a, b);
    }

    a ^ b
}

pub open spec fn nats(s: Seq<u128>) -> Seq<nat> {
    s.map_values(|x: u128| x as nat)
}

// ============================================================
// Twiddle schedule: tw_sum(lift, t, 0) = sum of lift[j]
// over the set bits j of t
// ============================================================

pub open spec fn tw_sum(lift: Seq<nat>, bits: nat, base: nat) -> nat
    decreases bits
{
    if bits == 0 {
        0
    } else {
        xor(
            if bits % 2 == 1 { lift[base as int] } else { 0 },
            tw_sum(lift, bits / 2, base + 1),
        )
    }
}

// Any set bit j of the index peels its lift term out of
// the sum; lower bits need not be clear.
pub proof fn tw_sum_clear_bit(lift: Seq<nat>, bits: nat, j: nat, base: nat)
    requires (bits / pow2(j)) % 2 == 1,
    ensures
        bits >= pow2(j),
        tw_sum(lift, bits, base)
            == xor(lift[(base + j) as int], tw_sum(lift, (bits - pow2(j)) as nat, base)),
    decreases j
{
    gf_model::pow2_pos(j);
    lemma_fundamental_div_mod(bits as int, pow2(j) as int);

    let m = bits / pow2(j);

    lemma_mul_inequality(1, m as int, pow2(j) as int);

    assert(bits >= pow2(j));

    if j == 0 {
        assert(pow2(0) == 1);
        vstd::arithmetic::div_mod::lemma_div_basics(bits as int);

        assert(bits % 2 == 1);

        let rest = (bits - 1) as nat;

        lemma_fundamental_div_mod(bits as int, 2);
        lemma_fundamental_div_mod_converse_mod(rest as int, 2, (bits / 2) as int, 0);
        lemma_fundamental_div_mod_converse_div(rest as int, 2, (bits / 2) as int, 0);

        assert(rest % 2 == 0 && rest / 2 == bits / 2);
        assert(tw_sum(lift, bits, base)
            == xor(lift[base as int], tw_sum(lift, bits / 2, base + 1)));

        if rest == 0 {
            assert(tw_sum(lift, 0, base) == 0);
            assert(bits / 2 == 0);
            assert(tw_sum(lift, 0, base + 1) == 0);
        } else {
            assert(tw_sum(lift, rest, base) == xor(0, tw_sum(lift, rest / 2, base + 1)));
            xor_zero(tw_sum(lift, rest / 2, base + 1));
        }
    } else {
        let h = pow2((j - 1) as nat);

        assert(pow2(j) == 2 * h);
        gf_model::pow2_pos((j - 1) as nat);
        lemma_div_denominator(bits as int, 2, h as int);

        assert((bits / 2) / h == bits / pow2(j));

        tw_sum_clear_bit(lift, bits / 2, (j - 1) as nat, base + 1);

        assert(base + 1 + (j - 1) == base + j);

        let s = bits % 2;

        lemma_fundamental_div_mod(bits as int, 2);

        assert(bits == 2 * (bits / 2) + s);
        assert(bits / 2 >= h);

        let rest = (bits - pow2(j)) as nat;
        let t2 = bits / 2 - h;

        assert(rest as int == 2 * t2 + s);
        lemma_fundamental_div_mod_converse_mod(rest as int, 2, t2 as int, s as int);
        lemma_fundamental_div_mod_converse_div(rest as int, 2, t2 as int, s as int);

        assert(rest % 2 == s && rest as int / 2 == t2);

        let selv: nat = if s == 1 { lift[base as int] } else { 0 };
        let el = lift[(base + j) as int];
        let tt = tw_sum(lift, (t2) as nat, base + 1);

        assert(bits != 0);
        assert(tw_sum(lift, bits, base) == xor(selv, tw_sum(lift, bits / 2, base + 1)));
        assert(tw_sum(lift, bits / 2, base + 1) == xor(el, tt));

        if rest == 0 {
            assert(t2 == 0 && s == 0);
            assert(tw_sum(lift, 0, base + 1) == 0);
            assert(tw_sum(lift, 0, base) == 0);
            xor_zero(el);
        } else {
            assert(tw_sum(lift, rest, base) == xor(selv, tt));
        }

        xor_assoc(selv, el, tt);
        xor_comm(selv, el);
        xor_assoc(el, selv, tt);
    }
}

pub proof fn tw_sum_double(lift: Seq<nat>, j: nat, t: nat)
    requires t < pow2(j),
    ensures tw_sum(lift, pow2(j) + t, 0) == xor(lift[j as int], tw_sum(lift, t, 0)),
{
    gf_model::pow2_pos(j);

    let bits = pow2(j) + t;

    lemma_fundamental_div_mod_converse_div(bits as int, pow2(j) as int, 1, t as int);

    assert(bits / pow2(j) == 1);

    tw_sum_clear_bit(lift, bits, j, 0);

    assert((bits - pow2(j)) as nat == t);
}

pub proof fn tw_sum_split(lift: Seq<nat>, c: nat, u: nat, m: nat, base: nat)
    requires u < pow2(m),
    ensures
        tw_sum(lift, c * pow2(m) + u, base)
            == xor(tw_sum(lift, u, base), tw_sum(lift, c, base + m)),
    decreases m
{
    if m == 0 {
        assert(pow2(0) == 1);
        assert(u == 0);
        assert(c * pow2(m) + u == c) by (nonlinear_arith)
            requires pow2(m) == 1, u == 0;
        assert(tw_sum(lift, 0, base) == 0);

        xor_zero(tw_sum(lift, c, base));
    } else {
        let h = pow2((m - 1) as nat);
        let bits = c * pow2(m) + u;
        let half = c * h + u / 2;

        gf_model::pow2_pos((m - 1) as nat);
        lemma_fundamental_div_mod(u as int, 2);

        assert(pow2(m) == 2 * h);
        assert(u / 2 < h);
        assert(bits == 2 * half + u % 2) by (nonlinear_arith)
            requires
                bits == c * pow2(m) + u,
                pow2(m) == 2 * h,
                half == c * h + u / 2,
                u == 2 * (u / 2) + u % 2;

        lemma_fundamental_div_mod_converse_div(bits as int, 2, half as int, (u % 2) as int);
        lemma_fundamental_div_mod_converse_mod(bits as int, 2, half as int, (u % 2) as int);

        assert(bits / 2 == half && bits % 2 == u % 2);

        tw_sum_split(lift, c, u / 2, (m - 1) as nat, base + 1);

        assert(base + 1 + (m - 1) == base + m);

        let sel: nat = if u % 2 == 1 { lift[base as int] } else { 0 };
        let a = tw_sum(lift, u / 2, base + 1);
        let hc = tw_sum(lift, c, base + m);

        assert(tw_sum(lift, half, base + 1) == xor(a, hc));

        if bits == 0 {
            assert(u == 0);
            assert(c == 0) by (nonlinear_arith)
                requires c * pow2(m) + u == 0, pow2(m) >= 1;
            assert(tw_sum(lift, 0, base + m) == 0);

            xor_zero(0);
        } else {
            assert(tw_sum(lift, bits, base) == xor(sel, tw_sum(lift, half, base + 1)));

            if u == 0 {
                assert(a == 0 && sel == 0);
                assert(tw_sum(lift, u, base) == 0);

                xor_zero(0);
            } else {
                assert(tw_sum(lift, u, base) == xor(sel, a));
            }

            xor_assoc(sel, a, hc);
        }
    }
}

pub proof fn tw_sum_lt(lift: Seq<nat>, bits: nat, base: nat)
    requires
        base <= lift.len(),
        bits < pow2((lift.len() - base) as nat),
        forall|i: int| 0 <= i < lift.len() ==> #[trigger] lift[i] < pow2(128),
    ensures tw_sum(lift, bits, base) < pow2(128),
    decreases bits
{
    gf_model::pow2_pos(128);

    if bits != 0 {
        assert(base < lift.len()) by {
            if base == lift.len() {
                assert(pow2(0) == 1);
            }
        }

        assert(pow2((lift.len() - base) as nat)
            == 2 * pow2((lift.len() - base - 1) as nat));

        tw_sum_lt(lift, bits / 2, base + 1);

        let sel: nat = if bits % 2 == 1 { lift[base as int] } else { 0 };

        xor_lt_pow2(sel, tw_sum(lift, bits / 2, base + 1), 128);
    }
}

// The trailing_zeros characterization, arithmetic side:
// all bits below j clear means divisible by 2^j.
pub proof fn low_bits_zero_mod(x: u64, j: u64)
    requires
        j < 64,
        forall|jj: u64| jj < j ==> #[trigger] ((x >> jj) & 1u64) == 0u64,
    ensures x as nat % pow2(j as nat) == 0
    decreases j
{
    if j == 0 {
        assert(pow2(0) == 1);
        lemma_fundamental_div_mod(x as int, 1);
    } else {
        assert(((x >> 0u64) & 1u64) == 0u64);
        assert(x % 2 == 0 && x / 2 == (x >> 1u64)) by (bit_vector)
            requires ((x >> 0u64) & 1u64) == 0u64;

        assert forall|jj: u64| jj < j - 1 implies #[trigger] (((x / 2) >> jj) & 1u64) == 0u64 by {
            assert(((x >> add(jj, 1u64)) & 1u64) == 0u64);
            assert(((x >> 1u64) >> jj) == x >> add(jj, 1u64)) by (bit_vector)
                requires jj < 63;
        }

        low_bits_zero_mod(x / 2, (j - 1) as u64);

        let h = pow2((j - 1) as nat);

        gf_model::pow2_pos((j - 1) as nat);
        lemma_fundamental_div_mod((x / 2) as int, h as int);

        let m = (x / 2) as nat / h;

        assert((x / 2) as nat == h * m);
        assert(x as nat == 2 * (h * m));
        lemma_mul_is_associative(2, h as int, m as int);
        assert(pow2(j as nat) == 2 * h);
        lemma_fundamental_div_mod_converse_mod(x as int, pow2(j as nat) as int, m as int, 0);
    }
}

// bits & (bits - 1) clears exactly the lowest set bit j:
// arithmetically, subtracts 2^j.
pub proof fn and_dec_is_sub(x: u64, j: u64)
    requires
        j < 64,
        (x as nat / pow2(j as nat)) % 2 == 1,
        x as nat % pow2(j as nat) == 0,
    ensures
        x as nat >= pow2(j as nat),
        (x & sub(x, 1u64)) as nat == x as nat - pow2(j as nat),
    decreases j
{
    gf_model::pow2_pos(j as nat);
    lemma_fundamental_div_mod(x as int, pow2(j as nat) as int);

    let m = x as nat / pow2(j as nat);

    lemma_mul_inequality(1, m as int, pow2(j as nat) as int);

    assert(x as nat == pow2(j as nat) * m);
    assert(x as nat >= pow2(j as nat));

    if j == 0 {
        assert(pow2(0) == 1);
        vstd::arithmetic::div_mod::lemma_div_basics(x as int);

        assert(x as nat == m);
        assert(x % 2 == 1);
        assert((x & sub(x, 1u64)) == sub(x, 1u64) && sub(x, 1u64) == x - 1) by (bit_vector)
            requires x % 2 == 1;
    } else {
        let h = pow2((j - 1) as nat);

        gf_model::pow2_pos((j - 1) as nat);

        assert(pow2(j as nat) == 2 * h);
        lemma_mul_is_associative(2, h as int, m as int);

        assert(x as nat == 2 * (h * m));
        lemma_fundamental_div_mod_converse_mod(x as int, 2, (h * m) as int, 0);
        lemma_fundamental_div_mod_converse_div(x as int, 2, (h * m) as int, 0);

        assert(x as nat % 2 == 0 && (x / 2) as nat == h * m);

        lemma_fundamental_div_mod_converse_mod((x / 2) as int, h as int, m as int, 0);
        lemma_fundamental_div_mod_converse_div((x / 2) as int, h as int, m as int, 0);

        assert((x / 2) as nat % h == 0 && (x / 2) as nat / h == m);

        and_dec_is_sub(x / 2, (j - 1) as u64);

        let x2 = x / 2;

        assert((x2 & sub(x2, 1u64)) as nat == x2 as nat - h);
        assert(x2 as nat - h <= x2 as nat);
        assert((x & sub(x, 1u64)) == mul(2u64, x2 & sub(x2, 1u64))) by (bit_vector)
            requires x % 2 == 0, x2 == x / 2;

        assert(x2 < 0x8000_0000_0000_0000u64);
        assert((x & sub(x, 1u64)) as nat == 2 * ((x2 & sub(x2, 1u64)) as nat));
        assert(x as nat == 2 * (x2 as nat));
    }
}

}
