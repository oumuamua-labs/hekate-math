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

use super::twiddles::{add_flat, mul_flat};
use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use super::bridge::gf_model;
#[cfg(verus_keep_ghost)]
use super::spec::{
    bfly_lo, chain_links, eval_novel, gf_mul_one_l, gf_mul_one_r, gf_mul_zero_l, point, sigma,
    sigma_additive, sigma_point, sigma_pow, sigma_pow_step, tw_sum_is_point, xt,
};
#[cfg(verus_keep_ghost)]
use super::twiddles::{
    and_dec_is_sub, low_bits_zero_mod, nats, pow2_bridge, tw_sum, tw_sum_clear_bit, xor128_reflect,
};

#[cfg(verus_keep_ghost)]
use gf_model::{
    deg_xor_lt, gf_distrib, gf_mul, gf_mul_assoc, gf_mul_closed, gf_mul_comm, in_field, pow2,
    pow2_mono, xor, xor_assoc, xor_comm, xor_rearrange4, xor_zero,
};
#[cfg(verus_keep_ghost)]
use vstd::arithmetic::div_mod::{
    lemma_div_denominator, lemma_div_is_ordered, lemma_div_is_ordered_by_denominator,
    lemma_fundamental_div_mod, lemma_fundamental_div_mod_converse_div,
    lemma_fundamental_div_mod_converse_mod,
};
#[cfg(verus_keep_ghost)]
use vstd::bits::{lemma_u64_pow2_no_overflow, lemma_u64_shl_is_mul, lemma_u64_shr_is_div};
#[cfg(verus_keep_ghost)]
use vstd::std_specs::bits::axiom_u64_trailing_zeros;

verus! {

// ============================================================
// CantorBasis twin (src/fft/cantor.rs): evaluate_at folds
// the coefficients along each index's path with twiddle
// sigma^l(shift + point(j)); fold_eval is that recursion.
// ============================================================

pub open spec fn halves_fold(v: Seq<nat>, tw: nat, s: nat, k: nat) -> Seq<nat> {
    Seq::new(s, |r: int| bfly_lo(v[r], v[r + s as int], tw, k))
}

pub open spec fn fold_eval(v: Seq<nat>, x: nat, d: nat, k: nat) -> nat
    decreases d
{
    if d == 0 {
        v[0]
    } else {
        let m = (d - 1) as nat;

        fold_eval(halves_fold(v, sigma_pow(x, m, k), pow2(m), k), x, m, k)
    }
}

proof fn sigma_pow_shift(x: nat, l: nat, k: nat)
    ensures sigma_pow(sigma(x, k), l, k) == sigma_pow(x, l + 1, k)
    decreases l
{
    if l == 0 {
        assert(sigma_pow(x, 0, k) == x);
        assert(sigma_pow(x, 1, k) == sigma(sigma_pow(x, 0, k), k));
    } else {
        let lm = (l - 1) as nat;

        sigma_pow_shift(x, lm, k);

        assert(sigma_pow(sigma(x, k), l, k) == sigma(sigma_pow(sigma(x, k), lm, k), k));
        assert(sigma_pow(x, l + 1, k) == sigma(sigma_pow(x, l, k), k));
    }
}

proof fn xt_top(m: nat, r: nat, x: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        r < pow2(m),
    ensures xt(pow2(m) + r, x, k) == gf_mul(sigma_pow(x, m, k), xt(r, x, k), k)
    decreases m
{
    if m == 0 {
        assert(pow2(0) == 1);
        assert(r == 0);
        assert(xt(1, x, k) == gf_mul(x, xt(0, sigma(x, k), k), k));
    } else {
        let h = pow2((m - 1) as nat);
        let t = pow2(m) + r;
        let sx = sigma(x, k);

        assert(pow2(m) == 2 * h);

        lemma_fundamental_div_mod(r as int, 2);
        lemma_fundamental_div_mod_converse_div(t as int, 2, (h + r / 2) as int, (r % 2) as int);
        lemma_fundamental_div_mod_converse_mod(t as int, 2, (h + r / 2) as int, (r % 2) as int);

        assert(t / 2 == h + r / 2 && t % 2 == r % 2);
        assert(r / 2 < h);

        xt_top((m - 1) as nat, r / 2, sx, k);
        sigma_pow_shift(x, (m - 1) as nat, k);

        let sp = sigma_pow(x, m, k);
        let inner = xt(r / 2, sx, k);

        assert(xt(h + r / 2, sx, k) == gf_mul(sp, inner, k));

        if r % 2 == 1 {
            assert(xt(t, x, k) == gf_mul(x, xt(t / 2, sx, k), k));
            assert(xt(r, x, k) == gf_mul(x, inner, k));

            gf_mul_assoc(x, sp, inner, k);
            gf_mul_comm(x, sp, k);
            gf_mul_assoc(sp, x, inner, k);
        } else {
            assert(xt(t, x, k) == xt(t / 2, sx, k));

            if r == 0 {
                assert(xt(r, x, k) == 1 && inner == 1);
            } else {
                assert(xt(r, x, k) == inner);
            }
        }
    }
}

proof fn eval_novel_top_prefix(v: Seq<nat>, x: nat, m: nat, h: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        v.len() == 2 * pow2(m),
        h <= pow2(m),
    ensures
        eval_novel(v.subrange(0, (pow2(m) + h) as int), x, k) == xor(
            eval_novel(v.subrange(0, pow2(m) as int), x, k),
            gf_mul(
                sigma_pow(x, m, k),
                eval_novel(v.subrange(pow2(m) as int, (pow2(m) + h) as int), x, k),
                k,
            ),
        ),
    decreases h
{
    let s = pow2(m);
    let sp = sigma_pow(x, m, k);

    if h == 0 {
        assert(v.subrange(s as int, s as int).len() == 0);
        assert(eval_novel(v.subrange(s as int, s as int), x, k) == 0);

        gf_mul_comm(sp, 0, k);
        gf_mul_zero_l(sp, k);
        xor_zero(eval_novel(v.subrange(0, s as int), x, k));
    } else {
        let hm = (h - 1) as nat;

        eval_novel_top_prefix(v, x, m, hm, k);

        let pre = v.subrange(0, (s + h) as int);
        let hi = v.subrange(s as int, (s + h) as int);
        let a = v[(s + hm) as int];
        let xx = xt(hm, x, k);

        assert(pre.drop_last() =~= v.subrange(0, (s + hm) as int));
        assert(pre.last() == a);
        assert(hi.drop_last() =~= v.subrange(s as int, (s + hm) as int));
        assert(hi.last() == a);
        assert(hi.len() == h);

        xt_top(m, hm, x, k);

        let lo_e = eval_novel(v.subrange(0, s as int), x, k);
        let hi_e = eval_novel(v.subrange(s as int, (s + hm) as int), x, k);
        let t = gf_mul(a, xx, k);

        assert(eval_novel(pre, x, k) == xor(
            xor(lo_e, gf_mul(sp, hi_e, k)),
            gf_mul(a, gf_mul(sp, xx, k), k),
        ));
        assert(eval_novel(hi, x, k) == xor(hi_e, t));

        gf_mul_assoc(a, sp, xx, k);
        gf_mul_comm(a, sp, k);
        gf_mul_assoc(sp, a, xx, k);
        gf_distrib(sp, hi_e, t, k);
        xor_assoc(lo_e, gf_mul(sp, hi_e, k), gf_mul(sp, t, k));
    }
}

proof fn eval_novel_top_split(v: Seq<nat>, x: nat, m: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        v.len() == 2 * pow2(m),
    ensures
        eval_novel(v, x, k) == xor(
            eval_novel(v.subrange(0, pow2(m) as int), x, k),
            gf_mul(
                sigma_pow(x, m, k),
                eval_novel(v.subrange(pow2(m) as int, 2 * pow2(m) as int), x, k),
                k,
            ),
        ),
{
    eval_novel_top_prefix(v, x, m, pow2(m), k);

    assert(v.subrange(0, 2 * pow2(m) as int) =~= v);
}

proof fn eval_novel_halves_prefix(v: Seq<nat>, tw: nat, s: nat, h: nat, x: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        v.len() == 2 * s,
        h <= s,
    ensures
        eval_novel(halves_fold(v, tw, s, k).subrange(0, h as int), x, k) == xor(
            eval_novel(v.subrange(0, h as int), x, k),
            gf_mul(tw, eval_novel(v.subrange(s as int, (s + h) as int), x, k), k),
        ),
    decreases h
{
    let g = halves_fold(v, tw, s, k);

    if h == 0 {
        assert(g.subrange(0, 0).len() == 0);
        assert(v.subrange(0, 0).len() == 0);
        assert(v.subrange(s as int, s as int).len() == 0);

        gf_mul_comm(tw, 0, k);
        gf_mul_zero_l(tw, k);
        xor_zero(0);
    } else {
        let hm = (h - 1) as nat;

        eval_novel_halves_prefix(v, tw, s, hm, x, k);

        let gh = g.subrange(0, h as int);
        let lo = v.subrange(0, h as int);
        let hi = v.subrange(s as int, (s + h) as int);

        let a = v[hm as int];
        let b = v[(s + hm) as int];
        let xx = xt(hm, x, k);
        let tb = gf_mul(tw, b, k);

        assert(gh.drop_last() =~= g.subrange(0, hm as int));
        assert(gh.last() == xor(a, tb));
        assert(lo.drop_last() =~= v.subrange(0, hm as int));
        assert(lo.last() == a);
        assert(hi.drop_last() =~= v.subrange(s as int, (s + hm) as int));
        assert(hi.last() == b);
        assert(gh.len() == h && lo.len() == h && hi.len() == h);

        let lo_e = eval_novel(v.subrange(0, hm as int), x, k);
        let hi_e = eval_novel(v.subrange(s as int, (s + hm) as int), x, k);

        assert(eval_novel(gh, x, k) == xor(
            xor(lo_e, gf_mul(tw, hi_e, k)),
            gf_mul(xor(a, tb), xx, k),
        ));

        gf_mul_comm(xor(a, tb), xx, k);
        gf_distrib(xx, a, tb, k);
        gf_mul_comm(xx, a, k);
        gf_mul_comm(xx, tb, k);
        gf_mul_assoc(tw, b, xx, k);
        gf_distrib(tw, hi_e, gf_mul(b, xx, k), k);

        xor_rearrange4(
            lo_e,
            gf_mul(tw, hi_e, k),
            gf_mul(a, xx, k),
            gf_mul(tw, gf_mul(b, xx, k), k),
        );
    }
}

proof fn eval_novel_halves_fold(v: Seq<nat>, tw: nat, s: nat, x: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        v.len() == 2 * s,
    ensures
        eval_novel(halves_fold(v, tw, s, k), x, k) == xor(
            eval_novel(v.subrange(0, s as int), x, k),
            gf_mul(tw, eval_novel(v.subrange(s as int, 2 * s as int), x, k), k),
        ),
{
    eval_novel_halves_prefix(v, tw, s, s, x, k);

    assert(halves_fold(v, tw, s, k).subrange(0, s as int) =~= halves_fold(v, tw, s, k));
}

pub proof fn fold_eval_is_eval_novel(v: Seq<nat>, x: nat, d: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        v.len() == pow2(d),
        forall|i: int| 0 <= i < v.len() ==> in_field(#[trigger] v[i], k),
    ensures fold_eval(v, x, d, k) == eval_novel(v, x, k)
    decreases d
{
    if d == 0 {
        assert(pow2(0) == 1);
        assert(v.drop_last().len() == 0);
        assert(eval_novel(v.drop_last(), x, k) == 0);
        assert(xt(0, x, k) == 1);
        assert(eval_novel(v, x, k) == xor(0, gf_mul(v[0], 1, k)));

        gf_mul_one_r(v[0], k);
        xor_zero(v[0]);
    } else {
        let m = (d - 1) as nat;
        let s = pow2(m);
        let tw = sigma_pow(x, m, k);
        let g = halves_fold(v, tw, s, k);

        assert(pow2(d) == 2 * s);

        assert forall|r: int| 0 <= r < g.len() implies in_field(#[trigger] g[r], k) by {
            gf_mul_closed(tw, v[r + s as int], k);
            deg_xor_lt(v[r], gf_mul(tw, v[r + s as int], k), k);
        }

        fold_eval_is_eval_novel(g, x, m, k);
        eval_novel_halves_fold(v, tw, s, x, k);
        eval_novel_top_split(v, x, m, k);
    }
}

proof fn sigma_pow_additive(a: nat, b: nat, l: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures sigma_pow(xor(a, b), l, k) == xor(sigma_pow(a, l, k), sigma_pow(b, l, k))
    decreases l
{
    if l > 0 {
        let lm = (l - 1) as nat;

        sigma_pow_additive(a, b, lm, k);
        sigma_additive(sigma_pow(a, lm, k), sigma_pow(b, lm, k), k);
    }
}

proof fn sigma_pow_point(beta: Seq<nat>, j: nat, l: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        chain_links(beta, k),
        beta.len() >= 1,
        beta[0] == 1,
        j < pow2(beta.len() as nat),
    ensures sigma_pow(point(beta, j), l, k) == point(beta, j / pow2(l))
    decreases l
{
    if l == 0 {
        assert(pow2(0) == 1);
        assert(j / 1 == j);
    } else {
        let lm = (l - 1) as nat;

        sigma_pow_point(beta, j, lm, k);
        gf_model::pow2_pos(lm);

        let q = j / pow2(lm);

        lemma_div_is_ordered_by_denominator(j as int, 1, pow2(lm) as int);

        assert(j / 1 == j);
        assert(q <= j);

        sigma_point(beta, q, k);
        lemma_div_denominator(j as int, pow2(lm) as int, 2);

        assert(pow2(l) == pow2(lm) * 2);
    }
}

proof fn fold_twiddle(beta: Seq<nat>, shift: nat, j: nat, l: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        chain_links(beta, k),
        beta.len() >= 1,
        beta[0] == 1,
        j < pow2(beta.len() as nat),
    ensures
        sigma_pow(xor(shift, point(beta, j)), l, k) == xor(
            xor(sigma_pow(shift, l, k), point(beta.skip(1), j / pow2(l + 1))),
            if (j / pow2(l)) % 2 == 1 { 1nat } else { 0nat },
        ),
{
    sigma_pow_additive(shift, point(beta, j), l, k);
    sigma_pow_point(beta, j, l, k);

    gf_model::pow2_pos(l);

    let q = j / pow2(l);
    let bit: nat = if q % 2 == 1 { 1nat } else { 0nat };
    let sp = sigma_pow(shift, l, k);
    let pt = point(beta.skip(1), q / 2);

    lemma_div_denominator(j as int, pow2(l) as int, 2);

    assert(pow2(l + 1) == pow2(l) * 2);
    assert(q / 2 == j / pow2(l + 1));

    if q == 0 {
        assert(point(beta, q) == 0);
        assert(point(beta.skip(1), 0) == 0);

        xor_zero(0);
        xor_zero(sp);
    } else {
        assert(point(beta, q) == xor(if q % 2 == 1 { beta[0] } else { 0 }, pt));
    }

    assert(point(beta, q) == xor(bit, pt));

    xor_comm(bit, pt);
    xor_assoc(sp, pt, bit);
}

proof fn bit_monotone(a: nat, b: nat, l: nat)
    requires
        a <= b,
        a / pow2(l + 1) == b / pow2(l + 1),
        (a / pow2(l)) % 2 == 1,
    ensures (b / pow2(l)) % 2 == 1,
{
    gf_model::pow2_pos(l);

    let qa = a / pow2(l);
    let qb = b / pow2(l);

    lemma_div_is_ordered(a as int, b as int, pow2(l) as int);
    lemma_div_denominator(a as int, pow2(l) as int, 2);
    lemma_div_denominator(b as int, pow2(l) as int, 2);

    assert(pow2(l + 1) == pow2(l) * 2);
    assert(qa / 2 == qb / 2);

    lemma_fundamental_div_mod(qa as int, 2);
    lemma_fundamental_div_mod(qb as int, 2);
}

proof fn div_split(j: nat, l: nat)
    ensures j / pow2(l) == 2 * (j / pow2(l + 1)) + (j / pow2(l)) % 2,
{
    gf_model::pow2_pos(l);

    lemma_div_denominator(j as int, pow2(l) as int, 2);
    lemma_fundamental_div_mod((j / pow2(l)) as int, 2);

    assert(pow2(l + 1) == pow2(l) * 2);
}

proof fn block_below_chain(j: nat, l: nat, n: nat)
    requires
        n >= 1,
        j < pow2(n),
    ensures j / pow2(l + 1) < pow2((n - 1) as nat),
{
    gf_model::pow2_pos(l + 1);
    gf_model::pow2_pos(l);

    assert(pow2(l + 1) == 2 * pow2(l));
    assert(pow2(n) == 2 * pow2((n - 1) as nat));

    lemma_div_is_ordered_by_denominator(j as int, 2, pow2(l + 1) as int);
    lemma_fundamental_div_mod(j as int, 2);
}

proof fn bfly_lo_plus_one(p: nat, q: nat, tw: nat)
    requires in_field(q, 128),
    ensures bfly_lo(p, q, xor(tw, 1), 128) == xor(bfly_lo(p, q, tw, 128), q),
{
    gf_mul_comm(xor(tw, 1), q, 128);
    gf_distrib(q, tw, 1, 128);
    gf_mul_comm(q, tw, 128);
    gf_mul_comm(q, 1, 128);
    gf_mul_one_l(q, 128);
    xor_assoc(p, gf_mul(tw, q, 128), q);
}

proof fn u128_in_field(v: u128)
    ensures in_field(v as nat, 128),
{
    assert(pow2(128) == 0x1_0000_0000_0000_0000_0000_0000_0000_0000) by (compute);
    gf_model::deg_lt_conv(v as nat, 128);
}

pub open spec fn src_at(top: bool, coeffs: Seq<u128>, scratch: Seq<u128>, base: int, u: int) -> nat {
    if top {
        coeffs[u] as nat
    } else {
        scratch[base + u] as nat
    }
}

pub open spec fn fold_src(top: bool, coeffs: Seq<u128>, scratch: Seq<u128>, level: nat) -> Seq<nat> {
    Seq::new(pow2(level + 1), |u: int| src_at(top, coeffs, scratch, pow2(level + 1) - 1, u))
}

proof fn level_bounds(level: nat)
    requires level < 63,
    ensures
        pow2(level + 1) == 2 * pow2(level),
        pow2(level + 2) == 4 * pow2(level),
        1 <= pow2(level) <= 0x4000_0000_0000_0000,
{
    gf_model::pow2_pos(level);
    pow2_mono(level, 62);

    assert(pow2(62) == 0x4000_0000_0000_0000) by (compute);
    assert(pow2(level + 2) == 2 * pow2(level + 1));
}

proof fn shr_bit(x: u64, l: u64)
    requires l < 64,
    ensures
        (x >> l) as nat == (x as nat) / pow2(l as nat),
        ((x >> l) & 1u64) as nat == ((x as nat) / pow2(l as nat)) % 2,
{
    lemma_u64_shr_is_div(x, l);
    pow2_bridge(l as nat);

    let q = x >> l;

    assert((q & 1u64) == q % 2) by (bit_vector);
}

fn fill(out: &mut Vec<u128>, lo: usize, hi: usize, v: u128)
    requires lo <= hi <= old(out)@.len(),
    ensures
        final(out)@.len() == old(out)@.len(),
        forall|p: int| lo <= p < hi ==> #[trigger] final(out)@[p] == v,
        forall|p: int| 0 <= p < old(out)@.len() && !(lo <= p < hi) ==> final(out)@[p] == old(out)@[p],
{
    let mut p = lo;
    while p < hi
        invariant
            lo <= p <= hi,
            hi <= out@.len(),
            out@.len() == old(out)@.len(),
            forall|q: int| lo <= q < p ==> #[trigger] out@[q] == v,
            forall|q: int| 0 <= q < out@.len() && !(lo <= q < p) ==> out@[q] == old(out)@[q],
        decreases hi - p,
    {
        out.set(p, v);

        p += 1;
    }
}

fn split_at_bit(indices: &Vec<u64>, ilo: usize, ihi: usize, level: usize) -> (split: usize)
    requires
        ilo < ihi <= indices@.len(),
        level < 63,
        forall|p: int, q: int| ilo <= p <= q < ihi ==> indices@[p] <= indices@[q],
        forall|p: int| ilo <= p < ihi ==> (#[trigger] indices@[p] as nat) / pow2(level as nat + 1)
            == indices@[ilo as int] as nat / pow2(level as nat + 1),
    ensures
        ilo <= split <= ihi,
        forall|p: int| ilo <= p < split
            ==> ((#[trigger] indices@[p] as nat) / pow2(level as nat)) % 2 == 0,
        forall|p: int| split <= p < ihi
            ==> ((#[trigger] indices@[p] as nat) / pow2(level as nat)) % 2 == 1,
{
    let lu = level as u64;

    let mut split = ilo;
    while split < ihi && (indices[split] >> lu) & 1 == 0
        invariant
            ilo <= split <= ihi,
            ihi <= indices@.len(),
            lu == level as u64,
            level < 63,
            forall|p: int| ilo <= p < split
                ==> ((#[trigger] indices@[p] as nat) / pow2(level as nat)) % 2 == 0,
        decreases ihi - split,
    {
        proof {
            shr_bit(indices@[split as int], lu);
        }

        split += 1;
    }

    proof {
        if split < ihi {
            let js = indices@[split as int];
            shr_bit(js, lu);

            assert forall|p: int| split <= p < ihi
                implies ((#[trigger] indices@[p] as nat) / pow2(level as nat)) % 2 == 1 by {
                assert(indices@[p] as nat / pow2(level as nat + 1)
                    == js as nat / pow2(level as nat + 1));

                bit_monotone(js as nat, indices@[p] as nat, level as nat);
            }
        }
    }

    split
}

fn halve(coeffs: &Vec<u128>, top: bool, level: usize, tw: u128, scratch: &mut Vec<u128>)
    requires
        level < 63,
        top ==> coeffs@.len() == pow2(level as nat + 1),
        old(scratch)@.len() <= usize::MAX,
        old(scratch)@.len() >= pow2(level as nat + 1) - 1,
        !top ==> level < 62 && old(scratch)@.len() >= pow2(level as nat + 2) - 1,
    ensures
        final(scratch)@.len() == old(scratch)@.len(),
        forall|u: int| 0 <= u < pow2(level as nat) ==> #[trigger] final(scratch)@[pow2(level as nat) - 1 + u]
            as nat == halves_fold(
            fold_src(top, coeffs@, old(scratch)@, level as nat),
            tw as nat,
            pow2(level as nat),
            128,
        )[u],
        forall|q: int|
            0 <= q < old(scratch)@.len() && !(pow2(level as nat) - 1 <= q < pow2(level as nat + 1) - 1)
                ==> final(scratch)@[q] == old(scratch)@[q],
{
    proof {
        level_bounds(level as nat);
        lemma_u64_pow2_no_overflow(level as nat);
        lemma_u64_shl_is_mul(1u64, level as u64);
        pow2_bridge(level as nat);
    }

    let s = (1u64 << level) as usize;
    let bbase = s - 1;
    let abase = 2 * s - 1;

    let ghost src = fold_src(top, coeffs@, old(scratch)@, level as nat);

    let mut r: usize = 0;
    while r < s
        invariant
            s as nat == pow2(level as nat),
            bbase == s - 1,
            abase == 2 * s - 1,
            level < 63,
            r <= s,
            top ==> coeffs@.len() == 2 * s,
            scratch@.len() == old(scratch)@.len(),
            scratch@.len() <= usize::MAX,
            scratch@.len() >= 2 * s - 1,
            !top ==> scratch@.len() >= 4 * s - 1,
            src == fold_src(top, coeffs@, old(scratch)@, level as nat),
            pow2(level as nat + 1) == 2 * s,
            forall|u: int| 0 <= u < r ==> #[trigger] scratch@[bbase + u] as nat
                == bfly_lo(src[u], src[u + s as int], tw as nat, 128),
            forall|q: int| 0 <= q < scratch@.len() && !(bbase <= q < bbase + r)
                ==> scratch@[q] == old(scratch)@[q],
        decreases s - r,
    {
        let p = if top { coeffs[r] } else { scratch[abase + r] };
        let q = if top { coeffs[s + r] } else { scratch[abase + s + r] };

        proof {
            assert(src[r as int] == p as nat);
            assert(src[r + s as int] == q as nat);

            gf_mul_comm(tw as nat, q as nat, 128);
        }

        scratch.set(bbase + r, add_flat(p, mul_flat(q, tw)));

        r += 1;
    }
}

fn add_hi(coeffs: &Vec<u128>, top: bool, level: usize, scratch: &mut Vec<u128>)
    requires
        level < 63,
        top ==> coeffs@.len() == pow2(level as nat + 1),
        old(scratch)@.len() <= usize::MAX,
        old(scratch)@.len() >= pow2(level as nat + 1) - 1,
        !top ==> level < 62 && old(scratch)@.len() >= pow2(level as nat + 2) - 1,
    ensures
        final(scratch)@.len() == old(scratch)@.len(),
        forall|u: int| 0 <= u < pow2(level as nat) ==> #[trigger] final(scratch)@[pow2(level as nat) - 1 + u]
            as nat == xor(
            old(scratch)@[pow2(level as nat) - 1 + u] as nat,
            fold_src(top, coeffs@, old(scratch)@, level as nat)[u + pow2(level as nat)],
        ),
        forall|q: int|
            0 <= q < old(scratch)@.len() && !(pow2(level as nat) - 1 <= q < pow2(level as nat + 1) - 1)
                ==> final(scratch)@[q] == old(scratch)@[q],
{
    proof {
        level_bounds(level as nat);
        lemma_u64_pow2_no_overflow(level as nat);
        lemma_u64_shl_is_mul(1u64, level as u64);
        pow2_bridge(level as nat);
    }

    let s = (1u64 << level) as usize;
    let bbase = s - 1;
    let abase = 2 * s - 1;

    let ghost src = fold_src(top, coeffs@, old(scratch)@, level as nat);

    let mut r: usize = 0;
    while r < s
        invariant
            s as nat == pow2(level as nat),
            bbase == s - 1,
            abase == 2 * s - 1,
            level < 63,
            r <= s,
            top ==> coeffs@.len() == 2 * s,
            scratch@.len() == old(scratch)@.len(),
            scratch@.len() <= usize::MAX,
            scratch@.len() >= 2 * s - 1,
            !top ==> scratch@.len() >= 4 * s - 1,
            src == fold_src(top, coeffs@, old(scratch)@, level as nat),
            pow2(level as nat + 1) == 2 * s,
            forall|u: int| 0 <= u < r ==> #[trigger] scratch@[bbase + u] as nat
                == xor(old(scratch)@[bbase + u] as nat, src[u + s as int]),
            forall|q: int| 0 <= q < scratch@.len() && !(bbase <= q < bbase + r)
                ==> scratch@[q] == old(scratch)@[q],
        decreases s - r,
    {
        let q = if top { coeffs[s + r] } else { scratch[abase + s + r] };
        let v = scratch[bbase + r];

        proof {
            assert(src[r + s as int] == q as nat);
        }

        scratch.set(bbase + r, add_flat(v, q));

        r += 1;
    }
}

pub struct CantorTwin {
    pub betas: Vec<u128>,
}

impl CantorTwin {
    pub open spec fn wf(self) -> bool {
        &&& 1 <= self.betas@.len() <= 64
        &&& self.betas@[0] == 1
        &&& chain_links(nats(self.betas@), 128)
    }

    pub open spec fn x_of(self, shift: nat, j: nat) -> nat {
        xor(shift, point(nats(self.betas@), j))
    }

    // beta_sum, cantor.rs: `bits` is u64 where
    // production uses usize (the pinned platform).
    fn beta_sum(&self, bits: u64, first: usize) -> (r: u128)
        requires
            self.wf(),
            first <= self.betas@.len(),
            (bits as nat) < pow2((self.betas@.len() - first) as nat),
        ensures r as nat == point(nats(self.betas@).skip(first as int), bits as nat),
    {
        let ghost lift = nats(self.betas@);
        let ghost n = self.betas@.len();

        let mut acc: u128 = 0;
        let mut rest: u64 = bits;

        proof {
            xor_zero(tw_sum(lift, bits as nat, first as nat));
        }

        while rest != 0
            invariant
                lift == nats(self.betas@),
                n == self.betas@.len(),
                n <= 64,
                first <= n,
                (bits as nat) < pow2((n - first) as nat),
                rest as nat <= bits as nat,
                xor(acc as nat, tw_sum(lift, rest as nat, first as nat))
                    == tw_sum(lift, bits as nat, first as nat),
            decreases rest,
        {
            let j32 = rest.trailing_zeros();
            let j = j32 as usize;
            let ghost jn = j as nat;
            let ghost j64: u64 = j32 as u64;

            proof {
                axiom_u64_trailing_zeros(rest);

                assert(j64 < 64);

                lemma_u64_shr_is_div(rest, j64);
                pow2_bridge(jn);

                let q = rest >> j64;

                assert(q as nat == rest as nat / pow2(jn));
                assert((q & 1u64) == 1u64);
                assert(q % 2 == 1) by (bit_vector) requires (q & 1u64) == 1u64;

                low_bits_zero_mod(rest, j64);
                tw_sum_clear_bit(lift, rest as nat, jn, first as nat);

                if jn >= (n - first) as nat {
                    pow2_mono((n - first) as nat, jn);

                    assert(pow2(jn) <= rest as nat);
                    assert(false);
                }
            }

            let l = self.betas[first + j];

            proof {
                xor128_reflect(acc, l);

                assert(lift[(first + j) as int] == l as nat);
            }

            let ghost acc_old = acc as nat;
            let ghost rest_prev: u64 = rest;

            acc ^= l;
            rest = rest & (rest - 1);

            proof {
                and_dec_is_sub(rest_prev, j64);
                gf_model::pow2_pos(jn);

                assert(rest == (rest_prev & sub(rest_prev, 1u64)));
                assert(rest as nat == rest_prev as nat - pow2(jn));
                assert(rest < rest_prev);

                xor_assoc(
                    acc_old,
                    lift[(first + j) as int],
                    tw_sum(lift, rest as nat, first as nat),
                );
            }
        }

        proof {
            assert(tw_sum(lift, 0, first as nat) == 0);

            xor_zero(acc as nat);
            tw_sum_is_point(lift, bits as nat, first as nat);
        }

        acc
    }

    // check_index, cantor.rs: checked_shr has
    // no high part once the shift reaches 64.
    fn index_ok(&self, index: u64) -> (ok: bool)
        requires self.wf(),
        ensures ok == ((index as nat) < pow2(self.betas@.len() as nat)),
    {
        let dim = self.betas.len();

        if dim >= 64 {
            proof {
                assert(pow2(64) == 0x1_0000_0000_0000_0000) by (compute);
            }

            return true;
        }

        let du = dim as u64;

        proof {
            shr_bit(index, du);
            gf_model::pow2_pos(dim as nat);

            if (index as nat) < pow2(dim as nat) {
                vstd::arithmetic::div_mod::lemma_basic_div(index as int, pow2(dim as nat) as int);
            } else {
                lemma_div_is_ordered(pow2(dim as nat) as int, index as int, pow2(dim as nat) as int);
                vstd::arithmetic::div_mod::lemma_div_by_self(pow2(dim as nat) as int);
            }
        }

        (index >> du) == 0
    }

    pub fn point(&self, index: u64) -> (r: Result<u128, ()>)
        requires self.wf(),
        ensures
            (r is Ok) == ((index as nat) < pow2(self.betas@.len() as nat)),
            r is Ok ==> r->Ok_0 as nat == point(nats(self.betas@), index as nat),
    {
        if !self.index_ok(index) {
            return Err(());
        }

        let v = self.beta_sum(index, 0);

        proof {
            assert(nats(self.betas@).skip(0) =~= nats(self.betas@));
        }

        Ok(v)
    }

    // fold, cantor.rs: level l writes scratch
    // [2^l - 1, 2^(l+1) - 1), the region split_at_mut
    // carves; `a` is coeffs at the top, else the parent
    // buffer above it. The loops sit in helpers.
    fn fold(
        &self,
        coeffs: &Vec<u128>,
        top: bool,
        level: usize,
        shift: Ghost<nat>,
        indices: &Vec<u64>,
        ilo: usize,
        ihi: usize,
        cosets: &Vec<u128>,
        scratch: &mut Vec<u128>,
        out: &mut Vec<u128>,
    )
        requires
            self.wf(),
            level < 63,
            ilo < ihi <= indices@.len(),
            old(out)@.len() == indices@.len(),
            top ==> coeffs@.len() == pow2(level as nat + 1),
            old(scratch)@.len() <= usize::MAX,
            old(scratch)@.len() >= pow2(level as nat + 1) - 1,
            !top ==> level < 62 && old(scratch)@.len() >= pow2(level as nat + 2) - 1,
            level < cosets@.len(),
            forall|l: int| 0 <= l <= level
                ==> #[trigger] cosets@[l] as nat == sigma_pow(shift@, l as nat, 128),
            forall|p: int, q: int| ilo <= p <= q < ihi ==> indices@[p] <= indices@[q],
            forall|p: int| ilo <= p < ihi
                ==> (#[trigger] indices@[p] as nat) < pow2(self.betas@.len() as nat),
            forall|p: int| ilo <= p < ihi ==> (#[trigger] indices@[p] as nat) / pow2(level as nat + 1)
                == indices@[ilo as int] as nat / pow2(level as nat + 1),
        ensures
            final(out)@.len() == old(out)@.len(),
            final(scratch)@.len() == old(scratch)@.len(),
            forall|p: int| ilo <= p < ihi ==> #[trigger] final(out)@[p] as nat == fold_eval(
                fold_src(top, coeffs@, old(scratch)@, level as nat),
                self.x_of(shift@, indices@[p] as nat),
                level as nat + 1,
                128,
            ),
            forall|p: int| 0 <= p < old(out)@.len() && !(ilo <= p < ihi)
                ==> final(out)@[p] == old(out)@[p],
            forall|q: int| pow2(level as nat + 1) - 1 <= q < old(scratch)@.len()
                ==> final(scratch)@[q] == old(scratch)@[q],
        decreases level,
    {
        let ghost betas = nats(self.betas@);
        let ghost src = fold_src(top, coeffs@, old(scratch)@, level as nat);
        let ghost s0 = old(scratch)@;

        proof {
            level_bounds(level as nat);
            lemma_u64_pow2_no_overflow(level as nat);
            lemma_u64_shl_is_mul(1u64, level as u64);
            pow2_bridge(level as nat);
        }

        let s = (1u64 << level) as usize;

        let split = split_at_bit(indices, ilo, ihi, level);

        let lu = (level + 1) as u64;
        let blk = indices[ilo] >> lu;

        proof {
            shr_bit(indices@[ilo as int], lu);
            block_below_chain(indices@[ilo as int] as nat, level as nat, self.betas@.len() as nat);
        }

        let tw0 = add_flat(cosets[level], self.beta_sum(blk, 1));

        let mut tw = tw0;
        if split == ilo {
            tw = add_flat(tw0, self.betas[0]);
        }

        proof {
            assert forall|p: int| ilo <= p < split implies sigma_pow(
                #[trigger] self.x_of(shift@, indices@[p] as nat),
                level as nat,
                128,
            ) == tw0 as nat by {
                fold_twiddle(betas, shift@, indices@[p] as nat, level as nat, 128);

                assert(indices@[p] as nat / pow2(level as nat + 1) == blk as nat);
                assert(cosets@[level as int] as nat == sigma_pow(shift@, level as nat, 128));

                xor_zero(tw0 as nat);
            }

            assert forall|p: int| split <= p < ihi implies sigma_pow(
                #[trigger] self.x_of(shift@, indices@[p] as nat),
                level as nat,
                128,
            ) == xor(tw0 as nat, 1) by {
                fold_twiddle(betas, shift@, indices@[p] as nat, level as nat, 128);

                assert(indices@[p] as nat / pow2(level as nat + 1) == blk as nat);
                assert(cosets@[level as int] as nat == sigma_pow(shift@, level as nat, 128));
            }

            assert(self.betas@[0] == 1);
        }

        halve(coeffs, top, level, tw, scratch);

        let ghost s1 = scratch@;

        if level == 0 {
            let abase = 2 * s - 1;
            let v0 = scratch[0];
            let q0 = if top { coeffs[1] } else { scratch[abase + 1] };

            let right_value = if split == ilo { v0 } else { add_flat(v0, q0) };

            proof {
                assert(pow2(level as nat) == 1);
                assert(s1[pow2(level as nat) - 1 + 0] as nat
                    == halves_fold(src, tw as nat, pow2(level as nat), 128)[0]);
                assert(halves_fold(src, tw as nat, pow2(level as nat), 128)[0]
                    == bfly_lo(src[0], src[1], tw as nat, 128));

                assert(src[1] == q0 as nat);
                assert(v0 as nat == bfly_lo(src[0], src[1], tw as nat, 128));

                u128_in_field(q0);
                bfly_lo_plus_one(src[0], src[1], tw0 as nat);
            }

            fill(out, ilo, split, v0);
            fill(out, split, ihi, right_value);

            proof {
                assert forall|p: int| ilo <= p < ihi implies #[trigger] out@[p] as nat == fold_eval(
                    src,
                    self.x_of(shift@, indices@[p] as nat),
                    level as nat + 1,
                    128,
                ) by {
                    let x = self.x_of(shift@, indices@[p] as nat);
                    let g = halves_fold(src, sigma_pow(x, 0, 128), pow2(0), 128);

                    assert(pow2(0) == 1);
                    assert(fold_eval(src, x, 1, 128) == fold_eval(g, x, 0, 128));
                    assert(fold_eval(g, x, 0, 128) == g[0]);
                    assert(g[0] == bfly_lo(src[0], src[1], sigma_pow(x, 0, 128), 128));

                    if p < split {
                        assert(tw == tw0);
                    } else if split == ilo {
                        assert(tw as nat == xor(tw0 as nat, 1));
                    }
                }
            }

            return;
        }

        let lm = level - 1;

        proof {
            assert(pow2(lm as nat + 1) == s as nat);
            assert(pow2(lm as nat + 2) == 2 * s as nat);
        }

        if split > ilo {
            proof {
                assert(tw == tw0);

                assert forall|u: int| 0 <= u < s implies fold_src(false, coeffs@, s1, lm as nat)[u]
                    == halves_fold(src, tw as nat, s as nat, 128)[u] by {
                    assert(s1[pow2(level as nat) - 1 + u] as nat
                        == halves_fold(src, tw as nat, pow2(level as nat), 128)[u]);
                }

                assert(fold_src(false, coeffs@, s1, lm as nat) =~= halves_fold(
                    src,
                    tw as nat,
                    s as nat,
                    128,
                ));

                assert forall|p: int| ilo <= p < split implies (#[trigger] indices@[p] as nat)
                    / pow2(lm as nat + 1) == indices@[ilo as int] as nat / pow2(lm as nat + 1) by {
                    div_split(indices@[p] as nat, level as nat);
                    div_split(indices@[ilo as int] as nat, level as nat);
                }
            }

            self.fold(coeffs, false, lm, shift, indices, ilo, split, cosets, scratch, out);

            proof {
                assert forall|p: int| ilo <= p < split implies #[trigger] out@[p] as nat == fold_eval(
                    src,
                    self.x_of(shift@, indices@[p] as nat),
                    level as nat + 1,
                    128,
                ) by {
                    let x = self.x_of(shift@, indices@[p] as nat);

                    assert(sigma_pow(x, level as nat, 128) == tw as nat);
                    assert(fold_eval(src, x, level as nat + 1, 128) == fold_eval(
                        halves_fold(src, tw as nat, s as nat, 128),
                        x,
                        level as nat,
                        128,
                    ));
                }
            }

            if split == ihi {
                return;
            }

            let ghost s2 = scratch@;

            add_hi(coeffs, top, level, scratch);

            proof {
                assert(fold_src(top, coeffs@, s2, level as nat) =~= src);

                assert forall|u: int| 0 <= u < s implies fold_src(false, coeffs@, scratch@, lm as nat)[u]
                    == halves_fold(src, xor(tw0 as nat, 1), s as nat, 128)[u] by {
                    let qv: u128 = if top {
                        coeffs@[u + s as int]
                    } else {
                        s0[2 * (s as int) - 1 + u + s as int]
                    };

                    assert(scratch@[pow2(level as nat) - 1 + u] as nat == xor(
                        s2[pow2(level as nat) - 1 + u] as nat,
                        fold_src(top, coeffs@, s2, level as nat)[u + pow2(level as nat)],
                    ));
                    assert(s2[pow2(level as nat) - 1 + u] == s1[pow2(level as nat) - 1 + u]);
                    assert(s1[pow2(level as nat) - 1 + u] as nat
                        == halves_fold(src, tw as nat, pow2(level as nat), 128)[u]);
                    assert(src[u + s as int] == qv as nat);

                    u128_in_field(qv);
                    bfly_lo_plus_one(src[u], src[u + s as int], tw0 as nat);
                }
            }
        }

        let ghost s3 = scratch@;

        proof {
            if split == ilo {
                assert(tw as nat == xor(tw0 as nat, 1));
                assert(s3 == s1);

                assert forall|u: int| 0 <= u < s implies fold_src(false, coeffs@, s3, lm as nat)[u]
                    == halves_fold(src, xor(tw0 as nat, 1), s as nat, 128)[u] by {
                    assert(s1[pow2(level as nat) - 1 + u] as nat
                        == halves_fold(src, tw as nat, pow2(level as nat), 128)[u]);
                }
            }

            assert(fold_src(false, coeffs@, s3, lm as nat) =~= halves_fold(
                src,
                xor(tw0 as nat, 1),
                s as nat,
                128,
            ));

            assert forall|p: int| split <= p < ihi implies (#[trigger] indices@[p] as nat)
                / pow2(lm as nat + 1) == indices@[split as int] as nat / pow2(lm as nat + 1) by {
                div_split(indices@[p] as nat, level as nat);
                div_split(indices@[split as int] as nat, level as nat);
            }
        }

        self.fold(coeffs, false, lm, shift, indices, split, ihi, cosets, scratch, out);

        proof {
            assert forall|p: int| split <= p < ihi implies #[trigger] out@[p] as nat == fold_eval(
                src,
                self.x_of(shift@, indices@[p] as nat),
                level as nat + 1,
                128,
            ) by {
                let x = self.x_of(shift@, indices@[p] as nat);

                assert(sigma_pow(x, level as nat, 128) == xor(tw0 as nat, 1));
                assert(fold_eval(src, x, level as nat + 1, 128) == fold_eval(
                    halves_fold(src, xor(tw0 as nat, 1), s as nat, 128),
                    x,
                    level as nat,
                    128,
                ));
            }
        }
    }

    // evaluate_at, cantor.rs: production's checks
    // in order; is_power_of_two as k == 1 << tz(k).
    pub fn evaluate_at(
        &self,
        coeffs: &Vec<u128>,
        shift: u128,
        indices: &Vec<u64>,
        scratch: &mut Vec<u128>,
        out: &mut Vec<u128>,
    ) -> (r: Result<(), ()>)
        requires self.wf(),
        ensures
            final(out)@.len() == old(out)@.len(),
            r is Ok ==> forall|p: int| 0 <= p < indices@.len() ==> #[trigger] final(out)@[p] as nat
                == eval_novel(nats(coeffs@), self.x_of(shift as nat, indices@[p] as nat), 128),
    {
        let k = coeffs.len();

        if k == 0 {
            return Err(());
        }

        let ku = k as u64;
        let tz = ku.trailing_zeros();

        proof {
            axiom_u64_trailing_zeros(ku);

            assert(tz < 64);
        }

        if ku != (1u64 << tz) {
            return Err(());
        }

        if out.len() != indices.len() {
            return Err(());
        }

        if scratch.len() < k - 1 {
            return Err(());
        }

        let n = indices.len();

        let mut i: usize = 1;
        while i < n
            invariant
                1 <= i,
                n == indices@.len(),
                forall|p: int, q: int| 0 <= p <= q < i && q < n ==> indices@[p] <= indices@[q],
            decreases n - i,
        {
            if indices[i] < indices[i - 1] {
                return Err(());
            }

            proof {
                assert forall|p: int| 0 <= p <= i implies indices@[p] <= #[trigger] indices@[i as int] by {
                    if p < i {
                        assert(indices@[p] <= indices@[i - 1]);
                    }
                }
            }

            i += 1;
        }

        if n > 0 && !self.index_ok(indices[n - 1]) {
            return Err(());
        }

        let tzu = tz as u64;
        let log_k = tz as usize;
        let ghost cs = nats(coeffs@);

        proof {
            lemma_u64_pow2_no_overflow(tzu as nat);
            lemma_u64_shl_is_mul(1u64, tzu);
            pow2_bridge(tzu as nat);

            assert(k as nat == pow2(log_k as nat));

            assert forall|p: int| 0 <= p < n implies (#[trigger] indices@[p] as nat)
                < pow2(self.betas@.len() as nat) by {
                assert(indices@[p] <= indices@[n - 1]);
            }

            assert forall|u: int| 0 <= u < cs.len() implies in_field(#[trigger] cs[u], 128) by {
                u128_in_field(coeffs@[u]);
            }
        }

        if log_k == 0 {
            fill(out, 0, n, coeffs[0]);

            proof {
                assert forall|p: int| 0 <= p < n implies #[trigger] out@[p] as nat == eval_novel(
                    cs,
                    self.x_of(shift as nat, indices@[p] as nat),
                    128,
                ) by {
                    fold_eval_is_eval_novel(cs, self.x_of(shift as nat, indices@[p] as nat), 0, 128);
                }
            }

            return Ok(());
        }

        let mut cosets: Vec<u128> = Vec::new();
        let mut c = shift;

        let mut l: usize = 0;
        while l < log_k
            invariant
                l <= log_k,
                log_k < 64,
                cosets@.len() == l,
                c as nat == sigma_pow(shift as nat, l as nat, 128),
                forall|t: int| 0 <= t < l
                    ==> #[trigger] cosets@[t] as nat == sigma_pow(shift as nat, t as nat, 128),
            decreases log_k - l,
        {
            cosets.push(c);

            let sq = mul_flat(c, c);
            c = add_flat(sq, c);

            proof {
                sigma_pow_step(shift as nat, l as nat, 128);
            }

            l += 1;
        }

        let mut start: usize = 0;
        while start < n
            invariant
                self.wf(),
                start <= n,
                n == indices@.len(),
                out@.len() == n,
                k == coeffs@.len(),
                k as nat == pow2(log_k as nat),
                1 <= log_k < 64,
                tzu == log_k as u64,
                scratch@.len() >= k - 1,
                scratch@.len() <= usize::MAX,
                cs == nats(coeffs@),
                cosets@.len() == log_k,
                forall|t: int| 0 <= t < log_k
                    ==> #[trigger] cosets@[t] as nat == sigma_pow(shift as nat, t as nat, 128),
                forall|p: int, q: int| 0 <= p <= q < n ==> indices@[p] <= indices@[q],
                forall|p: int| 0 <= p < n
                    ==> (#[trigger] indices@[p] as nat) < pow2(self.betas@.len() as nat),
                forall|u: int| 0 <= u < cs.len() ==> in_field(#[trigger] cs[u], 128),
                forall|p: int| 0 <= p < start ==> #[trigger] out@[p] as nat == eval_novel(
                    cs,
                    self.x_of(shift as nat, indices@[p] as nat),
                    128,
                ),
            decreases n - start,
        {
            let class = indices[start] >> tzu;

            let mut end = start + 1;
            while end < n && (indices[end] >> tzu) == class
                invariant
                    start < end <= n,
                    n == indices@.len(),
                    tzu < 64,
                    class == indices@[start as int] >> tzu,
                    forall|p: int| start <= p < end ==> (#[trigger] indices@[p] >> tzu) == class,
                decreases n - end,
            {
                end += 1;
            }

            proof {
                assert(pow2((log_k - 1) as nat + 1) == pow2(log_k as nat));

                assert forall|p: int| start <= p < end implies (#[trigger] indices@[p] as nat)
                    / pow2((log_k - 1) as nat + 1)
                    == indices@[start as int] as nat / pow2((log_k - 1) as nat + 1) by {
                    shr_bit(indices@[p], tzu);
                    shr_bit(indices@[start as int], tzu);
                }
            }

            let ghost before = out@;
            let ghost sc = scratch@;

            proof {
                assert(fold_src(true, coeffs@, sc, (log_k - 1) as nat) =~= cs);
            }

            self.fold(
                coeffs,
                true,
                log_k - 1,
                Ghost(shift as nat),
                indices,
                start,
                end,
                &cosets,
                scratch,
                out,
            );

            proof {
                assert forall|p: int| 0 <= p < end implies #[trigger] out@[p] as nat == eval_novel(
                    cs,
                    self.x_of(shift as nat, indices@[p] as nat),
                    128,
                ) by {
                    if p >= start {
                        let x = self.x_of(shift as nat, indices@[p] as nat);

                        fold_eval_is_eval_novel(cs, x, log_k as nat, 128);
                    } else {
                        assert(out@[p] == before[p]);
                    }
                }
            }

            start = end;
        }

        Ok(())
    }
}

}
