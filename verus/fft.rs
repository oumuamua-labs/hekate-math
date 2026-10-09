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

//! Twin and semantics of the additive FFT (src/fft/additive.rs).
//! The level-loop transforms refine the recursive fwd_spec/inv_spec
//! through a strided-gather invariant; the round-trip theorem uses
//! only the xor group; it holds for any twiddle and any multiply.

use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
#[path = "flat/bridge.rs"]
pub mod bridge;

#[cfg(verus_keep_ghost)]
use bridge::gf_model;
#[cfg(verus_keep_ghost)]
use bridge::{fold_step, pmod_below, r_poly};
#[cfg(verus_keep_ghost)]
use gf_model::{
    clmul, clmul_distrib_r, clmul_one_l, clmul_one_r, clmul_pow2, clmul_zero_r, deg, deg_lt_conv,
    deg_modulus, deg_pow2, deg_xor_lt, gf_distrib, gf_mul, gf_mul_assoc, gf_mul_closed,
    gf_mul_comm, gf_sq_additive, in_field, lo_plus_hipart_is_xor, modulus, pmod, pmod_additive,
    pow2, pow2_mono, xor, xor_assoc, xor_comm, xor_lt_pow2, xor_rearrange4, xor_self, xor_zero,
};
#[cfg(verus_keep_ghost)]
use vstd::arithmetic::div_mod::{
    lemma_div_denominator, lemma_div_is_ordered, lemma_div_is_ordered_by_denominator,
    lemma_fundamental_div_mod, lemma_fundamental_div_mod_converse_div,
    lemma_fundamental_div_mod_converse_mod,
};
#[cfg(verus_keep_ghost)]
use vstd::arithmetic::mul::{
    lemma_mul_inequality, lemma_mul_is_associative, lemma_mul_is_commutative,
    lemma_mul_is_distributive_add, lemma_mul_strict_inequality,
};
#[cfg(verus_keep_ghost)]
use vstd::bits::{lemma_u64_pow2_no_overflow, lemma_u64_shl_is_mul, lemma_u64_shr_is_div};
#[cfg(verus_keep_ghost)]
use vstd::std_specs::bits::axiom_u64_trailing_zeros;

verus! {

global size_of usize == 8;

// ============================================================
// Spec layer: the transform recursions, contiguous form
// ============================================================

pub open spec fn sigma(x: nat, k: nat) -> nat {
    xor(gf_mul(x, x, k), x)
}

// sigma iterated l times:
// the coset chain sigma^l(offset) the level loop walks.
pub open spec fn sigma_pow(x: nat, l: nat, k: nat) -> nat
    decreases l
{
    if l == 0 {
        x
    } else {
        sigma(sigma_pow(x, (l - 1) as nat, k), k)
    }
}

proof fn sigma_pow_step(x: nat, l: nat, k: nat)
    ensures sigma_pow(x, l + 1, k) == sigma(sigma_pow(x, l, k), k)
{
}

pub open spec fn evens(v: Seq<nat>) -> Seq<nat> {
    Seq::new(v.len() / 2, |t: int| v[2 * t])
}

pub open spec fn odds(v: Seq<nat>) -> Seq<nat> {
    Seq::new(v.len() / 2, |t: int| v[2 * t + 1])
}

pub open spec fn interleave(e: Seq<nat>, o: Seq<nat>) -> Seq<nat> {
    Seq::new(2 * e.len(), |i: int| if i % 2 == 0 { e[i / 2] } else { o[i / 2] })
}

pub open spec fn bfly_lo(p: nat, q: nat, tw: nat, k: nat) -> nat {
    xor(p, gf_mul(tw, q, k))
}

// Recursive reference form, no production twin: recurse
// on the even/odd sub-arrays with coset sigma(coset), then
// butterfly pair t with twiddle coset + tws[t];
// fwd_levels_exec refines it level by level.
pub open spec fn fwd_spec(v: Seq<nat>, tws: Seq<nat>, d: nat, coset: nat, k: nat) -> Seq<nat>
    decreases d
{
    if d == 0 {
        v
    } else {
        let child = sigma(coset, k);
        let e = fwd_spec(evens(v), tws, (d - 1) as nat, child, k);
        let o = fwd_spec(odds(v), tws, (d - 1) as nat, child, k);

        Seq::new(v.len(), |i: int| {
            let t = i / 2;
            let lo = bfly_lo(e[t], o[t], xor(coset, tws[t]), k);

            if i % 2 == 0 { lo } else { xor(lo, o[t]) }
        })
    }
}

// Recursive reference form, no production twin: butterfly
// first (q = o0 + o1, p = o0 + tw*q), then recurse;
// inv_levels_exec refines it level by level.
pub open spec fn inv_spec(w: Seq<nat>, tws: Seq<nat>, d: nat, coset: nat, k: nat) -> Seq<nat>
    decreases d
{
    if d == 0 {
        w
    } else {
        let child = sigma(coset, k);
        let q = Seq::new(w.len() / 2, |t: int| xor(w[2 * t], w[2 * t + 1]));
        let p = Seq::new(
            w.len() / 2,
            |t: int| bfly_lo(w[2 * t], xor(w[2 * t], w[2 * t + 1]), xor(coset, tws[t]), k),
        );

        interleave(
            inv_spec(p, tws, (d - 1) as nat, child, k),
            inv_spec(q, tws, (d - 1) as nat, child, k),
        )
    }
}

// ============================================================
// Round-trip: inverse . forward == id
// The twiddle product is never unfolded: a wrong twiddle
// (or a wrong multiply) still round-trips, which is why
// this theorem alone cannot certify the evaluation semantics.
// ============================================================

proof fn xor_cancel(x: nat, y: nat)
    ensures xor(xor(x, y), y) == x
{
    xor_assoc(x, y, y);
    xor_self(y);
    xor_zero(x);
}

proof fn fwd_spec_len(v: Seq<nat>, tws: Seq<nat>, d: nat, coset: nat, k: nat)
    ensures fwd_spec(v, tws, d, coset, k).len() == v.len()
{
    if d == 0 {
    } else {
    }
}

proof fn inv_spec_len(w: Seq<nat>, tws: Seq<nat>, d: nat, coset: nat, k: nat)
    requires w.len() == pow2(d),
    ensures inv_spec(w, tws, d, coset, k).len() == pow2(d),
    decreases d,
{
    if d == 0 {
        assert(pow2(0) == 1);
    } else {
        let child = sigma(coset, k);

        assert(pow2(d) == 2 * pow2((d - 1) as nat));

        let p = Seq::new(
            w.len() / 2,
            |t: int| bfly_lo(w[2 * t], xor(w[2 * t], w[2 * t + 1]), xor(coset, tws[t]), k),
        );
        let q = Seq::new(w.len() / 2, |t: int| xor(w[2 * t], w[2 * t + 1]));

        inv_spec_len(p, tws, (d - 1) as nat, child, k);
        inv_spec_len(q, tws, (d - 1) as nat, child, k);
    }
}

pub proof fn roundtrip(v: Seq<nat>, tws: Seq<nat>, d: nat, coset: nat, k: nat)
    requires v.len() == pow2(d)
    ensures inv_spec(fwd_spec(v, tws, d, coset, k), tws, d, coset, k) == v
    decreases d
{
    if d == 0 {
    } else {
        let child = sigma(coset, k);
        let n = v.len();
        let half = (n / 2) as int;

        assert(pow2(d) == 2 * pow2((d - 1) as nat));

        let ev = evens(v);
        let od = odds(v);

        assert(ev.len() == pow2((d - 1) as nat));
        assert(od.len() == pow2((d - 1) as nat));

        let e = fwd_spec(ev, tws, (d - 1) as nat, child, k);
        let o = fwd_spec(od, tws, (d - 1) as nat, child, k);

        fwd_spec_len(ev, tws, (d - 1) as nat, child, k);
        fwd_spec_len(od, tws, (d - 1) as nat, child, k);

        let w = fwd_spec(v, tws, d, coset, k);

        assert(w.len() == n);

        let q = Seq::new(w.len() / 2, |t: int| xor(w[2 * t], w[2 * t + 1]));
        let p = Seq::new(
            w.len() / 2,
            |t: int| bfly_lo(w[2 * t], xor(w[2 * t], w[2 * t + 1]), xor(coset, tws[t]), k),
        );

        assert forall|t: int| 0 <= t < half implies q[t] == o[t] && p[t] == e[t] by {
            let tw = xor(coset, tws[t]);
            let lo = bfly_lo(e[t], o[t], tw, k);

            assert(w[2 * t] == lo);
            assert(w[2 * t + 1] == xor(lo, o[t]));

            xor_assoc(lo, lo, o[t]);
            xor_self(lo);
            xor_zero(o[t]);

            assert(q[t] == o[t]);

            xor_cancel(e[t], gf_mul(tw, o[t], k));

            assert(p[t] == xor(xor(e[t], gf_mul(tw, o[t], k)), gf_mul(tw, o[t], k)));
        }

        assert(q =~= o);
        assert(p =~= e);

        roundtrip(ev, tws, (d - 1) as nat, child, k);
        roundtrip(od, tws, (d - 1) as nat, child, k);

        let r = interleave(ev, od);

        assert forall|i: int| 0 <= i < n implies r[i] == v[i] by {
            if i % 2 == 0 {
                assert(2 * (i / 2) == i);
            } else {
                assert(2 * (i / 2) + 1 == i);
            }
        }

        assert(r =~= v);
        assert(inv_spec(w, tws, d, coset, k) == interleave(
            inv_spec(p, tws, (d - 1) as nat, child, k),
            inv_spec(q, tws, (d - 1) as nat, child, k),
        ));
    }
}

// ============================================================
// Evaluation semantics: the novel polynomial basis
// X_t(x) = prod_{bit j of t} sigma^j(x) over the Cantor
// subspace chain beta[0] = 1, sigma(beta[j]) = beta[j-1]
// ============================================================

pub open spec fn xt(t: nat, x: nat, k: nat) -> nat
    decreases t
{
    if t == 0 {
        1
    } else if t % 2 == 1 {
        gf_mul(x, xt(t / 2, sigma(x, k), k), k)
    } else {
        xt(t / 2, sigma(x, k), k)
    }
}

pub open spec fn eval_novel(v: Seq<nat>, x: nat, k: nat) -> nat
    decreases v.len()
{
    if v.len() == 0 {
        0
    } else {
        xor(
            eval_novel(v.drop_last(), x, k),
            gf_mul(v.last(), xt((v.len() - 1) as nat, x, k), k),
        )
    }
}

// point(beta, i) = sum of beta[j] over the set bits j of i.
pub open spec fn point(beta: Seq<nat>, i: nat) -> nat
    decreases i
{
    if i == 0 {
        0
    } else {
        xor(if i % 2 == 1 { beta[0] } else { 0 }, point(beta.skip(1), i / 2))
    }
}

// The descent links sigma(beta[j]) == beta[j-1];
// beta[0] == 1 is stated separately where needed.
pub open spec fn chain_links(beta: Seq<nat>, k: nat) -> bool {
    forall|j: int| 1 <= j < beta.len() ==> #[trigger] sigma(beta[j] as nat, k) == beta[j - 1]
}

proof fn gf_mul_one_l(y: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        in_field(y, k),
    ensures gf_mul(1, y, k) == y
{
    gf_model::clmul_one_l(y);
    gf_model::deg_modulus(k);
}

proof fn gf_mul_one_r(y: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        in_field(y, k),
    ensures gf_mul(y, 1, k) == y
{
    gf_mul_comm(y, 1, k);
    gf_mul_one_l(y, k);
}

proof fn gf_mul_zero_l(y: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures gf_mul(0, y, k) == 0
{
    gf_model::deg_modulus(k);

    assert(gf_model::clmul(0, y) == 0);
    assert(gf_model::deg(0) == -1);
}

proof fn sigma_additive(a: nat, b: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures sigma(xor(a, b), k) == xor(sigma(a, k), sigma(b, k))
{
    gf_sq_additive(a, b, k);

    let aa = gf_mul(a, a, k);
    let bb = gf_mul(b, b, k);

    xor_rearrange4(aa, bb, a, b);
}

proof fn sigma_zero(k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures sigma(0, k) == 0
{
    gf_mul_zero_l(0, k);
    xor_zero(0);
}

proof fn sigma_one(k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures sigma(1, k) == 0
{
    assert(gf_model::deg(0) == -1);
    assert(gf_model::deg(1nat) == 0);
    assert(in_field(1, k));

    gf_mul_one_l(1, k);
    xor_self(1);
}

proof fn eval_novel_in_field(v: Seq<nat>, x: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures in_field(eval_novel(v, x, k), k)
    decreases v.len()
{
    if v.len() == 0 {
        assert(gf_model::deg(0) == -1);
    } else {
        eval_novel_in_field(v.drop_last(), x, k);
        gf_mul_closed(v.last(), xt((v.len() - 1) as nat, x, k), k);
        deg_xor_lt(
            eval_novel(v.drop_last(), x, k),
            gf_mul(v.last(), xt((v.len() - 1) as nat, x, k), k),
            k,
        );
    }
}

// sigma maps the shifted chain onto the unshifted one:
// the recursion's coset descent walks the subspace tower.
proof fn sigma_point_shift(beta: Seq<nat>, q: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        chain_links(beta, k),
        q < pow2((beta.len() - 1) as nat),
        beta.len() >= 1,
    ensures sigma(point(beta.skip(1), q), k) == point(beta, q)
    decreases q
{
    if q == 0 {
        sigma_zero(k);
    } else {
        assert(beta.len() >= 2) by {
            if beta.len() < 2 {
                assert(pow2(0) == 1);
            }
        }

        let b1 = beta.skip(1);

        assert(b1.len() == beta.len() - 1);
        assert(chain_links(b1, k)) by {
            assert forall|j: int| 1 <= j < b1.len() implies
                #[trigger] sigma(b1[j] as nat, k) == b1[j - 1] by {
                assert(b1[j] == beta[j + 1]);
                assert(b1[j - 1] == beta[j]);
                assert(sigma(beta[j + 1] as nat, k) == beta[j]);
            }
        }

        assert(pow2((beta.len() - 1) as nat) == 2 * pow2((beta.len() - 2) as nat));

        sigma_point_shift(b1, q / 2, k);

        assert(b1.skip(1) =~= beta.skip(2));
        assert(beta.skip(1).skip(1) =~= beta.skip(2));

        let s1: nat = if q % 2 == 1 { b1[0] as nat } else { 0 };

        assert(point(b1, q) == xor(s1, point(b1.skip(1), q / 2)));

        sigma_additive(s1, point(b1.skip(1), q / 2), k);

        assert(sigma(s1, k) == if q % 2 == 1 { beta[0] as nat } else { 0nat }) by {
            if q % 2 == 1 {
                assert(b1[0] == beta[1]);
                assert(sigma(beta[1] as nat, k) == beta[0]);
            } else {
                sigma_zero(k);
            }
        }

        assert(point(beta, q) == xor(
            if q % 2 == 1 { beta[0] as nat } else { 0nat },
            point(beta.skip(1), q / 2),
        ));
    }
}

// sigma(point(beta, i)) == point(beta, i/2):
// the pair (2t, 2t+1) collapses onto the child point t.
proof fn sigma_point(beta: Seq<nat>, i: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        chain_links(beta, k),
        beta.len() >= 1,
        beta[0] == 1,
        i < pow2(beta.len() as nat),
    ensures sigma(point(beta, i), k) == point(beta, i / 2)
{
    if i == 0 {
        sigma_zero(k);
    } else {
        let s: nat = if i % 2 == 1 { beta[0] as nat } else { 0 };

        assert(point(beta, i) == xor(s, point(beta.skip(1), i / 2)));

        sigma_additive(s, point(beta.skip(1), i / 2), k);

        assert(sigma(s, k) == 0) by {
            if i % 2 == 1 {
                sigma_one(k);
            } else {
                sigma_zero(k);
            }
        }

        assert(i / 2 < pow2((beta.len() - 1) as nat)) by {
            assert(pow2(beta.len() as nat) == 2 * pow2((beta.len() - 1) as nat));
        }

        sigma_point_shift(beta, i / 2, k);
        xor_zero(point(beta, i / 2));
    }
}

// The twiddle schedule is the point map of the shifted chain:
// point(beta, 2t) == point(beta.skip(1), t)
// and the odd point adds beta[0] == 1.
proof fn point_pair(beta: Seq<nat>, t: nat)
    requires beta.len() >= 1,
    ensures
        point(beta, 2 * t) == point(beta.skip(1), t),
        point(beta, 2 * t + 1) == xor(beta[0] as nat, point(beta.skip(1), t)),
{
    if t == 0 {
        assert(point(beta, 0) == 0);
        assert(point(beta, 1) == xor(beta[0] as nat, point(beta.skip(1), 0)));
    } else {
        assert((2 * t) % 2 == 0 && (2 * t) / 2 == t);
        assert((2 * t + 1) % 2 == 1 && (2 * t + 1) / 2 == t);
        assert(point(beta, 2 * t) == xor(0, point(beta.skip(1), t)));
        xor_zero(point(beta.skip(1), t));
    }
}

// The constructor's bit loop computes the point map.
proof fn tw_sum_is_point(lift: Seq<nat>, t: nat, base: nat)
    requires
        base <= lift.len(),
        t < pow2((lift.len() - base) as nat),
    ensures tw_sum(lift, t, base) == point(lift.skip(base as int), t)
    decreases t
{
    if t == 0 {
    } else {
        assert(base < lift.len()) by {
            if base == lift.len() {
                assert(pow2(0) == 1);
            }
        }

        assert(pow2((lift.len() - base) as nat)
            == 2 * pow2((lift.len() - base - 1) as nat));

        tw_sum_is_point(lift, t / 2, base + 1);

        assert(lift.skip(base as int).skip(1) =~= lift.skip(base as int + 1));
        assert(lift.skip(base as int)[0] == lift[base as int]);
    }
}

proof fn evens_odds_push(v: Seq<nat>)
    requires
        v.len() >= 2,
        v.len() % 2 == 0,
    ensures ({
        let w = v.drop_last().drop_last();
        evens(v) == evens(w).push(v[v.len() - 2])
            && odds(v) == odds(w).push(v[v.len() - 1])
    })
{
    let w = v.drop_last().drop_last();
    let n = v.len() as int;
    let h = n / 2;

    assert(w.len() == n - 2);
    assert(evens(w).len() == (n - 2) / 2 && odds(w).len() == (n - 2) / 2);
    assert((n - 2) / 2 == h - 1);

    assert forall|t: int| 0 <= t < h implies
        #[trigger] evens(v)[t] == evens(w).push(v[n - 2])[t] by {
        if t < h - 1 {
            assert(evens(w)[t] == w[2 * t]);
            assert(w[2 * t] == v[2 * t]);
        } else {
            assert(2 * t == n - 2);
        }
    }

    assert forall|t: int| 0 <= t < h implies
        #[trigger] odds(v)[t] == odds(w).push(v[n - 1])[t] by {
        if t < h - 1 {
            assert(odds(w)[t] == w[2 * t + 1]);
            assert(w[2 * t + 1] == v[2 * t + 1]);
        } else {
            assert(2 * t + 1 == n - 1);
        }
    }

    assert(evens(v) =~= evens(w).push(v[n - 2]));
    assert(odds(v) =~= odds(w).push(v[n - 1]));
}

proof fn eval_novel_push(s: Seq<nat>, a: nat, x: nat, k: nat)
    ensures eval_novel(s.push(a), x, k)
        == xor(eval_novel(s, x, k), gf_mul(a, xt(s.len(), x, k), k))
{
    assert(s.push(a).drop_last() =~= s);
    assert(s.push(a).last() == a);
}

// Decimation in time: peeling one sigma level splits the
// evaluation into even and odd novel-basis halves.
proof fn eval_novel_split(v: Seq<nat>, x: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        v.len() % 2 == 0,
    ensures eval_novel(v, x, k) == xor(
        eval_novel(evens(v), sigma(x, k), k),
        gf_mul(x, eval_novel(odds(v), sigma(x, k), k), k),
    )
    decreases v.len()
{
    let sx = sigma(x, k);

    if v.len() == 0 {
        assert(evens(v).len() == 0 && odds(v).len() == 0);
        gf_mul_comm(x, 0, k);
        gf_mul_zero_l(x, k);
        xor_zero(0);
    } else {
        let n = v.len() as int;
        let w = v.drop_last().drop_last();
        let h = ((n - 2) / 2) as nat;

        assert(w.len() == n - 2 && w.len() % 2 == 0);

        eval_novel_split(w, x, k);
        evens_odds_push(v);

        let xth = xt(h, sx, k);
        let a = v[n - 2];
        let b = v[n - 1];

        assert(v.drop_last().len() == n - 1);
        assert(v.drop_last().last() == a);
        assert(eval_novel(v, x, k) == xor(
            eval_novel(v.drop_last(), x, k),
            gf_mul(b, xt((n - 1) as nat, x, k), k),
        ));
        assert(eval_novel(v.drop_last(), x, k) == xor(
            eval_novel(w, x, k),
            gf_mul(a, xt((n - 2) as nat, x, k), k),
        ));

        assert((n - 2) as nat % 2 == 0 && (n - 2) as nat / 2 == h);
        assert((n - 1) as nat % 2 == 1 && (n - 1) as nat / 2 == h);

        assert(xt((n - 2) as nat, x, k) == xth) by {
            if n == 2 {
                assert(xt(0, x, k) == 1 && xt(0, sx, k) == 1);
            }
        }

        assert(xt((n - 1) as nat, x, k) == gf_mul(x, xth, k));

        eval_novel_push(evens(w), a, sx, k);
        eval_novel_push(odds(w), b, sx, k);

        assert(evens(w).len() == h && odds(w).len() == h);

        let e_w = eval_novel(evens(w), sx, k);
        let o_w = eval_novel(odds(w), sx, k);
        let ea = gf_mul(a, xth, k);
        let ob = gf_mul(b, xth, k);

        assert(eval_novel(evens(v), sx, k) == xor(e_w, ea));
        assert(eval_novel(odds(v), sx, k) == xor(o_w, ob));

        gf_distrib(x, o_w, ob, k);
        gf_mul_assoc(x, b, xth, k);
        gf_mul_comm(x, b, k);
        gf_mul_assoc(b, x, xth, k);

        assert(gf_mul(b, xt((n - 1) as nat, x, k), k) == gf_mul(x, ob, k));

        let xo_w = gf_mul(x, o_w, k);
        let xob = gf_mul(x, ob, k);

        assert(eval_novel(v, x, k) == xor(xor(xor(e_w, xo_w), ea), xob));

        xor_assoc(xor(e_w, xo_w), ea, xob);
        xor_rearrange4(e_w, xo_w, ea, xob);

        assert(eval_novel(v, x, k) == xor(xor(e_w, ea), xor(xo_w, xob)));
    }
}

// Top theorem: the forward transform evaluates the
// novel-basis polynomial on coset + W_d, by induction
// on the recursion depth over the Cantor chain.
pub proof fn fwd_semantics(v: Seq<nat>, tws: Seq<nat>, beta: Seq<nat>, d: nat, coset: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        v.len() == pow2(d),
        beta.len() >= d,
        beta.len() >= 1,
        beta[0] == 1,
        chain_links(beta, k),
        forall|i: int| 0 <= i < v.len() ==> in_field(#[trigger] v[i], k),
        forall|t: int| 0 <= t < pow2(d) / 2
            ==> #[trigger] tws[t] == point(beta.skip(1), t as nat),
    ensures forall|i: int| 0 <= i < pow2(d)
        ==> #[trigger] fwd_spec(v, tws, d, coset, k)[i]
            == eval_novel(v, xor(coset, point(beta, i as nat)), k)
    decreases d
{
    if d == 0 {
        assert(pow2(0) == 1);

        assert forall|i: int| 0 <= i < 1 implies
            #[trigger] fwd_spec(v, tws, d, coset, k)[i]
                == eval_novel(v, xor(coset, point(beta, i as nat)), k) by {
            let x = xor(coset, point(beta, 0));

            assert(point(beta, 0) == 0);
            assert(v.drop_last().len() == 0);
            assert(eval_novel(v.drop_last(), x, k) == 0);
            assert(xt(0, x, k) == 1);
            assert(eval_novel(v, x, k) == xor(0, gf_mul(v[0], 1, k)));

            gf_mul_one_r(v[0], k);
            xor_zero(v[0]);
        }
    } else {
        let child = sigma(coset, k);
        let dm1 = (d - 1) as nat;
        let ev = evens(v);
        let od = odds(v);

        assert(pow2(d) == 2 * pow2(dm1));
        assert(ev.len() == pow2(dm1) && od.len() == pow2(dm1));

        assert forall|i: int| 0 <= i < ev.len() implies in_field(#[trigger] ev[i], k) by {
            assert(ev[i] == v[2 * i]);
        }

        assert forall|i: int| 0 <= i < od.len() implies in_field(#[trigger] od[i], k) by {
            assert(od[i] == v[2 * i + 1]);
        }

        fwd_semantics(ev, tws, beta, dm1, child, k);
        fwd_semantics(od, tws, beta, dm1, child, k);

        let e = fwd_spec(ev, tws, dm1, child, k);
        let o = fwd_spec(od, tws, dm1, child, k);

        fwd_spec_len(ev, tws, dm1, child, k);
        fwd_spec_len(od, tws, dm1, child, k);

        let w = fwd_spec(v, tws, d, coset, k);

        assert(w.len() == v.len());

        assert forall|i: int| 0 <= i < pow2(d) implies
            #[trigger] w[i] == eval_novel(v, xor(coset, point(beta, i as nat)), k) by {
            lemma_fundamental_div_mod(i, 2);

            let t = i / 2;

            assert(0 <= t < pow2(dm1));

            let x = xor(coset, point(beta, i as nat));
            let tw_full = xor(coset, tws[t]);
            let lo = bfly_lo(e[t], o[t], tw_full, k);
            let pt = point(beta, t as nat);

            assert(w[i] == if i % 2 == 0 { lo } else { xor(lo, o[t]) });

            pow2_mono(d, beta.len() as nat);
            sigma_point(beta, i as nat, k);
            sigma_additive(coset, point(beta, i as nat), k);

            assert((i as nat) / 2 == t as nat);
            assert(sigma(x, k) == xor(child, pt));

            assert(e[t] == eval_novel(ev, xor(child, pt), k));
            assert(o[t] == eval_novel(od, xor(child, pt), k));

            eval_novel_split(v, x, k);

            assert(eval_novel(v, x, k)
                == xor(e[t], gf_mul(x, o[t], k)));

            point_pair(beta, t as nat);

            assert(tws[t] == point(beta.skip(1), t as nat));

            if i % 2 == 0 {
                assert(i as nat == 2 * (t as nat));
                assert(point(beta, i as nat) == tws[t]);
                assert(x == tw_full);
            } else {
                assert(i as nat == 2 * (t as nat) + 1);
                assert(point(beta, i as nat) == xor(1, tws[t]));

                xor_comm(1, tws[t]);
                xor_assoc(coset, tws[t], 1);

                assert(x == xor(tw_full, 1));

                gf_mul_comm(xor(tw_full, 1), o[t], k);
                gf_distrib(o[t], tw_full, 1, k);
                gf_mul_comm(o[t], tw_full, k);
                gf_mul_comm(o[t], 1, k);
                eval_novel_in_field(od, xor(child, pt), k);
                gf_mul_one_l(o[t], k);

                assert(gf_mul(x, o[t], k) == xor(gf_mul(tw_full, o[t], k), o[t]));

                xor_assoc(e[t], gf_mul(tw_full, o[t], k), o[t]);
            }
        }
    }
}

// The exec twin's element domain discharges the membership
// hypothesis: every u128 is a reduced GF(2^128) element.
pub proof fn fwd_semantics_u128(
    v: Seq<u128>, tws: Seq<nat>, beta: Seq<nat>, d: nat, coset: u128,
)
    requires
        v.len() == pow2(d),
        beta.len() >= d,
        beta.len() >= 1,
        beta[0] == 1,
        chain_links(beta, 128),
        forall|t: int| 0 <= t < pow2(d) / 2
            ==> #[trigger] tws[t] == point(beta.skip(1), t as nat),
    ensures forall|i: int| 0 <= i < pow2(d)
        ==> #[trigger] fwd_spec(nats(v), tws, d, coset as nat, 128)[i]
            == eval_novel(nats(v), xor(coset as nat, point(beta, i as nat)), 128),
{
    assert forall|i: int| 0 <= i < nats(v).len()
        implies in_field(#[trigger] nats(v)[i], 128) by {
        assert(pow2(128) == 0x1_0000_0000_0000_0000_0000_0000_0000_0000) by (compute);
        gf_model::deg_lt_conv(v[i] as nat, 128);
    }

    fwd_semantics(nats(v), tws, beta, d, coset as nat, 128);
}

// ============================================================
// Exec twin plumbing: u128 elements model Flat<F>, usize is
// pinned to 64 bits (the aarch64/x86_64 deployment targets)
// ============================================================

proof fn pow2_bridge(e: nat)
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

proof fn xor128_reflect(x: u128, y: u128)
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

fn mul_flat(a: u128, b: u128) -> (r: u128)
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
        }

        proof {
            if n + 1 < 128 {
                gf_mul_assoc(a as nat, p, 2, 128);
                clmul_pow2(p, 1);
                deg_pow2(n + 1);
                pmod_below(pow2(n + 1), 128);
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

fn add_flat(a: u128, b: u128) -> (r: u128)
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
proof fn tw_sum_clear_bit(lift: Seq<nat>, bits: nat, j: nat, base: nat)
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

proof fn tw_sum_double(lift: Seq<nat>, j: nat, t: nat)
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

// The trailing_zeros characterization, arithmetic side:
// all bits below j clear means divisible by 2^j.
proof fn low_bits_zero_mod(x: u64, j: u64)
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
proof fn and_dec_is_sub(x: u64, j: u64)
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

// ============================================================
// Constructor twin: new(), additive.rs, from the lift chain on.
// The solve_quadratic loop producing `lift` is checked at build time.
// ============================================================

pub struct FftTwin {
    pub log_n: u32,
    pub twiddles: Vec<u128>,
}

impl FftTwin {
    pub open spec fn wf(self) -> bool {
        &&& 1 <= self.log_n < 64
        &&& self.log_n as nat <= 128
        &&& self.twiddles@.len() == pow2((self.log_n - 1) as nat)
    }

    pub fn new(log_n: u32, lift: Vec<u128>) -> (r: FftTwin)
        requires
            1 <= log_n < 64,
            log_n as nat <= 128,
            lift@.len() == log_n - 1,
        ensures
            r.wf(),
            r.log_n == log_n,
            forall|t: int| 0 <= t < r.twiddles@.len()
                ==> #[trigger] r.twiddles@[t] as nat == tw_sum(nats(lift@), t as nat, 0),
    {
        proof {
            lemma_u64_pow2_no_overflow((log_n - 1) as nat);
            lemma_u64_shl_is_mul(1u64, (log_n - 1) as u64);
            pow2_bridge((log_n - 1) as nat);
        }

        let half = (1u64 << (log_n - 1)) as usize;

        assert(half as nat == pow2((log_n - 1) as nat));

        let mut twiddles: Vec<u128> = Vec::with_capacity(half);
        twiddles.push(0);

        proof {
            assert(pow2(0) == 1);
            assert(tw_sum(nats(lift@), 0, 0) == 0);
        }

        let mut j: usize = 0;
        while j < lift.len()
            invariant
                j <= lift@.len(),
                lift@.len() == log_n - 1,
                1 <= log_n < 64,
                half as nat == pow2((log_n - 1) as nat),
                twiddles@.len() == pow2(j as nat),
                forall|u: int| 0 <= u < twiddles@.len()
                    ==> #[trigger] twiddles@[u] as nat == tw_sum(nats(lift@), u as nat, 0),
            decreases lift@.len() - j,
        {
            let filled = twiddles.len();
            let l = lift[j];

            let mut t: usize = 0;
            while t < filled
                invariant
                    t <= filled,
                    filled as nat == pow2(j as nat),
                    j < lift@.len(),
                    lift@.len() == log_n - 1,
                    1 <= log_n < 64,
                    half as nat == pow2((log_n - 1) as nat),
                    l == lift@[j as int],
                    twiddles@.len() == filled + t,
                    forall|u: int| 0 <= u < twiddles@.len()
                        ==> #[trigger] twiddles@[u] as nat == tw_sum(nats(lift@), u as nat, 0),
                decreases filled - t,
            {
                let tw = twiddles[t];

                proof {
                    xor128_reflect(tw, l);
                    tw_sum_double(nats(lift@), j as nat, t as nat);
                    xor_comm(l as nat, tw as nat);

                    assert(nats(lift@)[j as int] == l as nat);
                }

                twiddles.push(tw ^ l);

                t += 1;
            }

            proof {
                assert(pow2((j + 1) as nat) == 2 * pow2(j as nat));
            }

            j += 1;
        }

        FftTwin { log_n, twiddles }
    }
}

// ============================================================
// Strided gather: the loop invariant's class (off, stride) of a
// size-2^d transform reads exactly { off + i*stride : i < 2^d }.
// ============================================================

pub open spec fn gather(s: Seq<nat>, off: int, stride: int, n: nat) -> Seq<nat> {
    Seq::new(n, |i: int| s[off + i * stride])
}

// The strided even/odd sub-views are the two child classes.
proof fn gather_split(s: Seq<nat>, off: int, stride: int, d: nat)
    requires d >= 1,
    ensures
        evens(gather(s, off, stride, pow2(d)))
            == gather(s, off, 2 * stride, pow2((d - 1) as nat)),
        odds(gather(s, off, stride, pow2(d)))
            == gather(s, off + stride, 2 * stride, pow2((d - 1) as nat)),
{
    let h = pow2((d - 1) as nat);
    let g = gather(s, off, stride, pow2(d));

    assert(pow2(d) == 2 * h);

    assert forall|t: int| 0 <= t < h implies
        evens(g)[t] == gather(s, off, 2 * stride, h)[t] by {
        assert(2 * t * stride == t * (2 * stride)) by (nonlinear_arith);
        assert(g[2 * t] == s[off + 2 * t * stride]);
    }

    assert forall|t: int| 0 <= t < h implies
        odds(g)[t] == gather(s, off + stride, 2 * stride, h)[t] by {
        assert(2 * t * stride == t * (2 * stride)) by (nonlinear_arith);
        assert(g[2 * t + 1] == s[off + (2 * t + 1) * stride]);
        assert((2 * t + 1) * stride == 2 * t * stride + stride) by (nonlinear_arith);
    }

    assert(evens(g) =~= gather(s, off, 2 * stride, h));
    assert(odds(g) =~= gather(s, off + stride, 2 * stride, h));
}

proof fn gather_ident(s: Seq<nat>, n: nat)
    requires s.len() == n,
    ensures gather(s, 0, 1, n) == s,
{
    assert forall|i: int| 0 <= i < n implies gather(s, 0, 1, n)[i] == s[i] by {
        assert(0 + i * 1 == i) by (nonlinear_arith);
    }

    assert(gather(s, 0, 1, n) =~= s);
}

proof fn interleave_evens(a: Seq<nat>, b: Seq<nat>)
    requires a.len() == b.len(),
    ensures
        evens(interleave(a, b)) == a,
        odds(interleave(a, b)) == b,
{
    let g = interleave(a, b);

    assert forall|t: int| 0 <= t < a.len() implies evens(g)[t] == a[t] && odds(g)[t] == b[t] by {}

    assert(evens(g) =~= a);
    assert(odds(g) =~= b);
}

proof fn interleave_evens_odds(g: Seq<nat>)
    requires g.len() % 2 == 0,
    ensures interleave(evens(g), odds(g)) == g,
{
    assert forall|i: int| 0 <= i < g.len() implies interleave(evens(g), odds(g))[i] == g[i] by {
        if i % 2 == 0 {
            assert(2 * (i / 2) == i);
        } else {
            assert(2 * (i / 2) + 1 == i);
        }
    }

    assert(interleave(evens(g), odds(g)) =~= g);
}

// The level loop's inductive step: once a node's even/odd
// children hold their fwd_spec and one butterfly pass has run
// over the pair (g_pre[2t], g_pre[2t+1]) with twiddle
// xor(coset, tws[t]), the node holds fwd_spec at depth d.
proof fn fwd_combine(
    g_pre: Seq<nat>,
    g_post: Seq<nat>,
    old_g: Seq<nat>,
    tws: Seq<nat>,
    d: nat,
    coset: nat,
    k: nat,
)
    requires
        d >= 1,
        g_pre.len() == pow2(d),
        g_post.len() == pow2(d),
        old_g.len() == pow2(d),
        evens(g_pre) == fwd_spec(evens(old_g), tws, (d - 1) as nat, sigma(coset, k), k),
        odds(g_pre) == fwd_spec(odds(old_g), tws, (d - 1) as nat, sigma(coset, k), k),
        forall|t: int| 0 <= t < pow2((d - 1) as nat) ==> {
            &&& #[trigger] g_post[2 * t] == bfly_lo(
                g_pre[2 * t],
                g_pre[2 * t + 1],
                xor(coset, tws[t]),
                k,
            )
            &&& g_post[2 * t + 1] == xor(g_post[2 * t], g_pre[2 * t + 1])
        },
    ensures
        g_post == fwd_spec(old_g, tws, d, coset, k),
{
    let child = sigma(coset, k);
    let e = fwd_spec(evens(old_g), tws, (d - 1) as nat, child, k);
    let o = fwd_spec(odds(old_g), tws, (d - 1) as nat, child, k);
    let w = fwd_spec(old_g, tws, d, coset, k);

    fwd_spec_len(evens(old_g), tws, (d - 1) as nat, child, k);
    fwd_spec_len(odds(old_g), tws, (d - 1) as nat, child, k);

    assert(pow2(d) == 2 * pow2((d - 1) as nat));

    assert forall|i: int| 0 <= i < pow2(d) implies g_post[i] == w[i] by {
        let t = i / 2;

        assert(0 <= t < pow2((d - 1) as nat)) by (nonlinear_arith)
            requires 0 <= i < 2 * pow2((d - 1) as nat), t == i / 2;

        assert(evens(g_pre)[t] == g_pre[2 * t]);
        assert(odds(g_pre)[t] == g_pre[2 * t + 1]);
        assert(g_pre[2 * t] == e[t]);
        assert(g_pre[2 * t + 1] == o[t]);

        assert(g_post[2 * t] == bfly_lo(g_pre[2 * t], g_pre[2 * t + 1], xor(coset, tws[t]), k));
        assert(g_post[2 * t + 1] == xor(g_post[2 * t], g_pre[2 * t + 1]));

        let lo = bfly_lo(e[t], o[t], xor(coset, tws[t]), k);

        if i % 2 == 0 {
            assert(i == 2 * t);
            assert(w[i] == lo);
        } else {
            assert(i == 2 * t + 1);
            assert(w[i] == xor(lo, o[t]));
        }
    }

    assert(g_post =~= w);
}

pub open spec fn fwd_rows(
    pre: Seq<u128>,
    post: Seq<u128>,
    tws: Seq<u128>,
    s: int,
    nblocks: int,
    coset: nat,
) -> bool {
    forall|b: int, r: int|
        0 <= b < nblocks && 0 <= r < s ==> {
            &&& #[trigger] post[b * (2 * s) + r] as nat == bfly_lo(
                pre[b * (2 * s) + r] as nat,
                pre[b * (2 * s) + s + r] as nat,
                xor(coset, tws[b] as nat),
                128,
            )
            &&& post[b * (2 * s) + s + r] as nat == xor(
                post[b * (2 * s) + r] as nat,
                pre[b * (2 * s) + s + r] as nat,
            )
        }
}

pub open spec fn inv_rows(
    pre: Seq<u128>,
    post: Seq<u128>,
    tws: Seq<u128>,
    s: int,
    nblocks: int,
    coset: nat,
) -> bool {
    forall|b: int, r: int|
        0 <= b < nblocks && 0 <= r < s ==> {
            &&& #[trigger] post[b * (2 * s) + r] as nat == bfly_lo(
                pre[b * (2 * s) + r] as nat,
                xor(pre[b * (2 * s) + r] as nat, pre[b * (2 * s) + s + r] as nat),
                xor(coset, tws[b] as nat),
                128,
            )
            &&& post[b * (2 * s) + s + r] as nat == xor(
                pre[b * (2 * s) + r] as nat,
                pre[b * (2 * s) + s + r] as nat,
            )
        }
}

pub open spec fn fwd_rows_nat(
    pre: Seq<nat>,
    post: Seq<nat>,
    tws: Seq<nat>,
    n: nat,
    lev: nat,
    coset: nat,
    k: nat,
) -> bool {
    forall|b: int, r: int|
        0 <= b < pow2((n - lev) as nat) && 0 <= r < pow2((lev - 1) as nat) ==> {
            &&& #[trigger] post[b * pow2(lev) + r] == bfly_lo(
                pre[b * pow2(lev) + r],
                pre[b * pow2(lev) + pow2((lev - 1) as nat) + r],
                xor(coset, tws[b]),
                k,
            )
            &&& post[b * pow2(lev) + pow2((lev - 1) as nat) + r] == xor(
                post[b * pow2(lev) + r],
                pre[b * pow2(lev) + pow2((lev - 1) as nat) + r],
            )
        }
}

pub open spec fn inv_rows_nat(
    pre: Seq<nat>,
    post: Seq<nat>,
    tws: Seq<nat>,
    n: nat,
    lev: nat,
    coset: nat,
    k: nat,
) -> bool {
    forall|b: int, r: int|
        0 <= b < pow2((n - lev - 1) as nat) && 0 <= r < pow2(lev) ==> {
            &&& #[trigger] post[b * pow2((lev + 1) as nat) + r] == bfly_lo(
                pre[b * pow2((lev + 1) as nat) + r],
                xor(
                    pre[b * pow2((lev + 1) as nat) + r],
                    pre[b * pow2((lev + 1) as nat) + pow2(lev) + r],
                ),
                xor(coset, tws[b]),
                k,
            )
            &&& post[b * pow2((lev + 1) as nat) + pow2(lev) + r] == xor(
                pre[b * pow2((lev + 1) as nat) + r],
                pre[b * pow2((lev + 1) as nat) + pow2(lev) + r],
            )
        }
}

proof fn fwd_rows_bridge(
    pre: Seq<u128>,
    post: Seq<u128>,
    tws: Seq<u128>,
    n: nat,
    lev: nat,
    s: int,
    nblocks: int,
    coset: nat,
)
    requires
        1 <= lev <= n,
        s == pow2((lev - 1) as nat),
        nblocks == pow2((n - lev) as nat),
        nblocks * (2 * s) == pre.len(),
        post.len() == pre.len(),
        nblocks <= tws.len(),
        fwd_rows(pre, post, tws, s, nblocks, coset),
    ensures fwd_rows_nat(nats(pre), nats(post), nats(tws), n, lev, coset, 128),
{
    gf_model::pow2_pos((lev - 1) as nat);

    assert(pow2(lev) == 2 * s);

    assert forall|b: int, r: int|
        0 <= b < pow2((n - lev) as nat) && 0 <= r < pow2((lev - 1) as nat) implies {
        &&& #[trigger] nats(post)[b * pow2(lev) + r] == bfly_lo(
            nats(pre)[b * pow2(lev) + r],
            nats(pre)[b * pow2(lev) + pow2((lev - 1) as nat) + r],
            xor(coset, nats(tws)[b]),
            128,
        )
        &&& nats(post)[b * pow2(lev) + pow2((lev - 1) as nat) + r] == xor(
            nats(post)[b * pow2(lev) + r],
            nats(pre)[b * pow2(lev) + pow2((lev - 1) as nat) + r],
        )
    } by {
        lemma_mul_inequality((b + 1) as int, nblocks, 2 * s);

        assert(b * pow2(lev) == b * (2 * s)) by (nonlinear_arith)
            requires pow2(lev) == 2 * s;
        assert((b + 1) * (2 * s) == b * (2 * s) + 2 * s) by (nonlinear_arith);
        assert(0 <= b * (2 * s)) by (nonlinear_arith)
            requires b >= 0, s >= 1;

        assert(post[b * (2 * s) + r] as nat == bfly_lo(
            pre[b * (2 * s) + r] as nat,
            pre[b * (2 * s) + s + r] as nat,
            xor(coset, tws[b] as nat),
            128,
        ));
        assert(post[b * (2 * s) + s + r] as nat == xor(
            post[b * (2 * s) + r] as nat,
            pre[b * (2 * s) + s + r] as nat,
        ));
    }
}

proof fn inv_rows_bridge(
    pre: Seq<u128>,
    post: Seq<u128>,
    tws: Seq<u128>,
    n: nat,
    lev: nat,
    s: int,
    nblocks: int,
    coset: nat,
)
    requires
        lev < n,
        s == pow2(lev),
        nblocks == pow2((n - lev - 1) as nat),
        nblocks * (2 * s) == pre.len(),
        post.len() == pre.len(),
        nblocks <= tws.len(),
        inv_rows(pre, post, tws, s, nblocks, coset),
    ensures inv_rows_nat(nats(pre), nats(post), nats(tws), n, lev, coset, 128),
{
    gf_model::pow2_pos(lev);

    assert(pow2((lev + 1) as nat) == 2 * s);

    assert forall|b: int, r: int|
        0 <= b < pow2((n - lev - 1) as nat) && 0 <= r < pow2(lev) implies {
        &&& #[trigger] nats(post)[b * pow2((lev + 1) as nat) + r] == bfly_lo(
            nats(pre)[b * pow2((lev + 1) as nat) + r],
            xor(
                nats(pre)[b * pow2((lev + 1) as nat) + r],
                nats(pre)[b * pow2((lev + 1) as nat) + pow2(lev) + r],
            ),
            xor(coset, nats(tws)[b]),
            128,
        )
        &&& nats(post)[b * pow2((lev + 1) as nat) + pow2(lev) + r] == xor(
            nats(pre)[b * pow2((lev + 1) as nat) + r],
            nats(pre)[b * pow2((lev + 1) as nat) + pow2(lev) + r],
        )
    } by {
        lemma_mul_inequality((b + 1) as int, nblocks, 2 * s);

        assert(b * pow2((lev + 1) as nat) == b * (2 * s)) by (nonlinear_arith)
            requires pow2((lev + 1) as nat) == 2 * s;
        assert((b + 1) * (2 * s) == b * (2 * s) + 2 * s) by (nonlinear_arith);
        assert(0 <= b * (2 * s)) by (nonlinear_arith)
            requires b >= 0, s >= 1;

        assert(post[b * (2 * s) + r] as nat == bfly_lo(
            pre[b * (2 * s) + r] as nat,
            xor(pre[b * (2 * s) + r] as nat, pre[b * (2 * s) + s + r] as nat),
            xor(coset, tws[b] as nat),
            128,
        ));
        assert(post[b * (2 * s) + s + r] as nat == xor(
            pre[b * (2 * s) + r] as nat,
            pre[b * (2 * s) + s + r] as nat,
        ));
    }
}

// One level pass advances the invariant:
// Inv(lev) plus the stride-2^(lev-1) butterfly pass
// gives Inv(lev-1). Pure re-indexing over gather_split,
// node-wise via fwd_combine.
proof fn fwd_pass_step(
    pre: Seq<nat>,
    post: Seq<nat>,
    orig: Seq<nat>,
    tws: Seq<nat>,
    n: nat,
    lev: nat,
    coset: nat,
    k: nat,
)
    requires
        1 <= lev <= n,
        pre.len() == pow2(n),
        post.len() == pow2(n),
        orig.len() == pow2(n),
        forall|off: int| 0 <= off < pow2(lev) ==>
            #[trigger] gather(pre, off, pow2(lev) as int, pow2((n - lev) as nat))
                == fwd_spec(
                    gather(orig, off, pow2(lev) as int, pow2((n - lev) as nat)),
                    tws,
                    (n - lev) as nat,
                    sigma(coset, k),
                    k,
                ),
        fwd_rows_nat(pre, post, tws, n, lev, coset, k),
    ensures
        forall|off: int| 0 <= off < pow2((lev - 1) as nat) ==>
            #[trigger] gather(post, off, pow2((lev - 1) as nat) as int, pow2((n - lev + 1) as nat))
                == fwd_spec(
                    gather(orig, off, pow2((lev - 1) as nat) as int, pow2((n - lev + 1) as nat)),
                    tws,
                    (n - lev + 1) as nat,
                    coset,
                    k,
                ),
{
    let snew = pow2((lev - 1) as nat);
    let slev = pow2(lev);
    let mlow = pow2((n - lev) as nat);
    let m = pow2((n - lev + 1) as nat);
    let dd = (n - lev + 1) as nat;

    assert(slev == 2 * snew);
    assert(m == 2 * mlow);
    assert((dd - 1) as nat == (n - lev) as nat);

    assert forall|off: int| 0 <= off < snew implies gather(post, off, snew as int, m) == fwd_spec(
        gather(orig, off, snew as int, m),
        tws,
        dd,
        coset,
        k,
    ) by {
        let g_pre = gather(pre, off, snew as int, m);
        let g_post = gather(post, off, snew as int, m);
        let old_g = gather(orig, off, snew as int, m);

        gather_split(pre, off, snew as int, dd);
        gather_split(orig, off, snew as int, dd);

        assert(off < slev);
        assert(off + snew < slev);

        assert(evens(g_pre) == fwd_spec(evens(old_g), tws, (dd - 1) as nat, sigma(coset, k), k));
        assert(odds(g_pre) == fwd_spec(odds(old_g), tws, (dd - 1) as nat, sigma(coset, k), k));

        assert forall|t: int| 0 <= t < pow2((dd - 1) as nat) implies {
            &&& #[trigger] g_post[2 * t] == bfly_lo(g_pre[2 * t], g_pre[2 * t + 1], xor(coset, tws[t]), k)
            &&& g_post[2 * t + 1] == xor(g_post[2 * t], g_pre[2 * t + 1])
        } by {
            assert(2 * t * snew == t * slev) by (nonlinear_arith) requires slev == 2 * snew;
            assert((2 * t + 1) * snew == t * slev + snew) by (nonlinear_arith) requires slev == 2
                * snew;

            assert(g_pre[2 * t] == pre[t * slev + off]);
            assert(g_pre[2 * t + 1] == pre[t * slev + snew + off]);
            assert(g_post[2 * t] == post[t * slev + off]);
            assert(g_post[2 * t + 1] == post[t * slev + snew + off]);
        }

        fwd_combine(g_pre, g_post, old_g, tws, dd, coset, k);
    }
}

// Inverse level step: Inv(lev) (each class still owes its
// depth-(n-lev) inv_spec to reach fin) plus the inverse pass
// gives Inv(lev+1). interleave splits a node's remaining work
// onto its even/odd children.
proof fn inv_pass_step(
    pre: Seq<nat>,
    post: Seq<nat>,
    fin: Seq<nat>,
    tws: Seq<nat>,
    n: nat,
    lev: nat,
    coset: nat,
    k: nat,
)
    requires
        lev < n,
        pre.len() == pow2(n),
        post.len() == pow2(n),
        fin.len() == pow2(n),
        forall|off: int| 0 <= off < pow2(lev) ==> #[trigger] inv_spec(
            gather(pre, off, pow2(lev) as int, pow2((n - lev) as nat)),
            tws,
            (n - lev) as nat,
            coset,
            k,
        ) == gather(fin, off, pow2(lev) as int, pow2((n - lev) as nat)),
        inv_rows_nat(pre, post, tws, n, lev, coset, k),
    ensures
        forall|off: int| 0 <= off < pow2((lev + 1) as nat) ==> #[trigger] inv_spec(
            gather(post, off, pow2((lev + 1) as nat) as int, pow2((n - lev - 1) as nat)),
            tws,
            (n - lev - 1) as nat,
            sigma(coset, k),
            k,
        ) == gather(fin, off, pow2((lev + 1) as nat) as int, pow2((n - lev - 1) as nat)),
{
    let sL = pow2(lev);
    let sL1 = pow2((lev + 1) as nat);
    let mlow = pow2((n - lev - 1) as nat);
    let mhi = pow2((n - lev) as nat);
    let d = (n - lev) as nat;
    let child = sigma(coset, k);

    assert(sL1 == 2 * sL);
    assert(mhi == 2 * mlow);
    assert((d - 1) as nat == (n - lev - 1) as nat);

    assert forall|off: int|
        #![trigger inv_spec(gather(post, off, sL1 as int, mlow), tws, (n - lev - 1) as nat, child, k)]
        #![trigger inv_spec(gather(post, off + sL, sL1 as int, mlow), tws, (n - lev - 1) as nat, child, k)]
        0 <= off < sL implies {
        &&& inv_spec(gather(post, off, sL1 as int, mlow), tws, (n - lev - 1) as nat, child, k)
            == gather(fin, off, sL1 as int, mlow)
        &&& inv_spec(gather(post, off + sL, sL1 as int, mlow), tws, (n - lev - 1) as nat, child, k)
            == gather(fin, off + sL, sL1 as int, mlow)
    } by {
        let g_pre = gather(pre, off, sL as int, mhi);
        let g_post = gather(post, off, sL as int, mhi);
        let g_fin = gather(fin, off, sL as int, mhi);

        gather_split(pre, off, sL as int, d);
        gather_split(post, off, sL as int, d);
        gather_split(fin, off, sL as int, d);

        assert forall|t: int|
            #![trigger g_post[2 * t]]
            #![trigger g_post[2 * t + 1]]
            0 <= t < mlow implies {
            &&& g_post[2 * t] == bfly_lo(
                g_pre[2 * t],
                xor(g_pre[2 * t], g_pre[2 * t + 1]),
                xor(coset, tws[t]),
                k,
            )
            &&& g_post[2 * t + 1] == xor(g_pre[2 * t], g_pre[2 * t + 1])
        } by {
            assert(2 * t * sL == t * sL1) by (nonlinear_arith) requires sL1 == 2 * sL;
            assert((2 * t + 1) * sL == t * sL1 + sL) by (nonlinear_arith) requires sL1 == 2 * sL;

            assert(g_pre[2 * t] == pre[t * sL1 + off]);
            assert(g_pre[2 * t + 1] == pre[t * sL1 + sL + off]);
            assert(g_post[2 * t] == post[t * sL1 + off]);
            assert(g_post[2 * t + 1] == post[t * sL1 + sL + off]);
        }

        let p = Seq::new(
            mlow,
            |t: int| bfly_lo(g_pre[2 * t], xor(g_pre[2 * t], g_pre[2 * t + 1]), xor(coset, tws[t]), k),
        );
        let q = Seq::new(mlow, |t: int| xor(g_pre[2 * t], g_pre[2 * t + 1]));

        assert(evens(g_post) =~= p);
        assert(odds(g_post) =~= q);

        assert(inv_spec(p, tws, (d - 1) as nat, child, k) == inv_spec(
            p,
            tws,
            (n - lev - 1) as nat,
            child,
            k,
        ));
        assert(inv_spec(q, tws, (d - 1) as nat, child, k) == inv_spec(
            q,
            tws,
            (n - lev - 1) as nat,
            child,
            k,
        ));

        assert(inv_spec(g_pre, tws, d, coset, k) == interleave(
            inv_spec(p, tws, (n - lev - 1) as nat, child, k),
            inv_spec(q, tws, (n - lev - 1) as nat, child, k),
        ));

        inv_spec_len(p, tws, (n - lev - 1) as nat, child, k);
        inv_spec_len(q, tws, (n - lev - 1) as nat, child, k);

        interleave_evens_odds(g_fin);
        interleave_evens(
            inv_spec(p, tws, (n - lev - 1) as nat, child, k),
            inv_spec(q, tws, (n - lev - 1) as nat, child, k),
        );
    }

    assert forall|off_p: int| 0 <= off_p < sL1 implies #[trigger] inv_spec(
        gather(post, off_p, sL1 as int, mlow),
        tws,
        (n - lev - 1) as nat,
        child,
        k,
    ) == gather(fin, off_p, sL1 as int, mlow) by {
        if off_p < sL {
            assert(inv_spec(gather(post, off_p, sL1 as int, mlow), tws, (n - lev - 1) as nat, child, k)
                == gather(fin, off_p, sL1 as int, mlow));
        } else {
            let off = off_p - sL;

            assert(0 <= off < sL);
            assert(off + sL == off_p);
            assert(inv_spec(gather(post, off, sL1 as int, mlow), tws, (n - lev - 1) as nat, child, k)
                == gather(fin, off, sL1 as int, mlow));
            assert(inv_spec(
                gather(post, off + sL, sL1 as int, mlow),
                tws,
                (n - lev - 1) as nat,
                child,
                k,
            ) == gather(fin, off + sL, sL1 as int, mlow));
        }
    }
}

impl FftTwin {
    // fwd_butterflies, additive.rs:
    // pair r in [0,s) as (base+r, base+s+r);
    // writes stay inside [base, base+2s).
    fn fwd_bfly_block(&self, data: &mut Vec<u128>, base: usize, s: usize, tw: u128)
        requires
            s >= 1,
            base + 2 * s <= old(data)@.len(),
            old(data)@.len() <= usize::MAX,
        ensures
            final(data)@.len() == old(data)@.len(),
            forall|r: int| 0 <= r < s ==> {
                &&& #[trigger] final(data)@[base + r] as nat == bfly_lo(
                    old(data)@[base + r] as nat,
                    old(data)@[base + s + r] as nat,
                    tw as nat,
                    128,
                )
                &&& final(data)@[base + s + r] as nat == xor(
                    final(data)@[base + r] as nat,
                    old(data)@[base + s + r] as nat,
                )
            },
            forall|j: int|
                0 <= j < final(data)@.len() && (j < base || base + 2 * s <= j)
                    ==> final(data)@[j] == old(data)@[j],
    {
        let mut r: usize = 0;

        while r < s
            invariant
                s >= 1,
                base + 2 * s <= data@.len(),
                data@.len() == old(data)@.len(),
                data@.len() <= usize::MAX,
                r <= s,
                forall|u: int| 0 <= u < r ==> {
                    &&& #[trigger] data@[base + u] as nat == bfly_lo(
                        old(data)@[base + u] as nat,
                        old(data)@[base + s + u] as nat,
                        tw as nat,
                        128,
                    )
                    &&& data@[base + s + u] as nat == xor(
                        data@[base + u] as nat,
                        old(data)@[base + s + u] as nat,
                    )
                },
                forall|j: int|
                    0 <= j < data@.len() && !(base <= j < base + r) && !(base + s <= j < base + s
                        + r) ==> data@[j] == old(data)@[j],
            decreases s - r,
        {
            let lo_i = base + r;
            let hi_i = base + s + r;

            let p = data[lo_i];
            let q = data[hi_i];
            let v = add_flat(p, mul_flat(q, tw));

            proof {
                gf_mul_comm(tw as nat, q as nat, 128);
            }

            data.set(lo_i, v);
            data.set(hi_i, add_flat(v, q));

            r += 1;
        }
    }

    // blocks_serial, additive.rs:
    // whole-array pass at stride s;
    // block b (width 2s) twiddled by xor(coset, tws[b]).
    fn pass_fwd_exec(&self, data: &mut Vec<u128>, coset: u128, s: usize, nblocks: usize)
        requires
            self.wf(),
            s >= 1,
            s <= usize::MAX / 2,
            nblocks * (2 * s) == old(data)@.len(),
            nblocks <= self.twiddles@.len(),
            old(data)@.len() <= usize::MAX,
        ensures
            final(data)@.len() == old(data)@.len(),
            fwd_rows(
                old(data)@,
                final(data)@,
                self.twiddles@,
                s as int,
                nblocks as int,
                coset as nat,
            ),
    {
        let mut b: usize = 0;
        let mut base: usize = 0;

        while b < nblocks
            invariant
                self.wf(),
                s >= 1,
                s <= usize::MAX / 2,
                data@.len() == old(data)@.len(),
                nblocks * (2 * s) == data@.len(),
                nblocks <= self.twiddles@.len(),
                b <= nblocks,
                base == b * (2 * s),
                data@.len() <= usize::MAX,
                forall|bb: int, r: int|
                    0 <= bb < b && 0 <= r < s ==> {
                        &&& #[trigger] data@[bb * (2 * s) + r] as nat == bfly_lo(
                            old(data)@[bb * (2 * s) + r] as nat,
                            old(data)@[bb * (2 * s) + s + r] as nat,
                            xor(coset as nat, self.twiddles@[bb] as nat),
                            128,
                        )
                        &&& data@[bb * (2 * s) + s + r] as nat == xor(
                            data@[bb * (2 * s) + r] as nat,
                            old(data)@[bb * (2 * s) + s + r] as nat,
                        )
                    },
                forall|j: int| base <= j < data@.len() ==> data@[j] == old(data)@[j],
            decreases nblocks - b,
        {
            proof {
                lemma_mul_inequality((b + 1) as int, nblocks as int, (2 * s) as int);

                assert((b + 1) * (2 * s) == base + 2 * s) by (nonlinear_arith)
                    requires base == b * (2 * s);
            }

            let tw = add_flat(coset, self.twiddles[b]);
            let ghost pre = data@;

            self.fwd_bfly_block(data, base, s, tw);

            proof {
                assert forall|bb: int, r: int| 0 <= bb < b + 1 && 0 <= r < s implies {
                    &&& #[trigger] data@[bb * (2 * s) + r] as nat == bfly_lo(
                        old(data)@[bb * (2 * s) + r] as nat,
                        old(data)@[bb * (2 * s) + s + r] as nat,
                        xor(coset as nat, self.twiddles@[bb] as nat),
                        128,
                    )
                    &&& data@[bb * (2 * s) + s + r] as nat == xor(
                        data@[bb * (2 * s) + r] as nat,
                        old(data)@[bb * (2 * s) + s + r] as nat,
                    )
                } by {
                    if bb < b {
                        assert(0 <= bb * (2 * s)) by (nonlinear_arith)
                            requires bb >= 0, s >= 1;
                        assert(bb * (2 * s) + 2 * s == (bb + 1) * (2 * s)) by (nonlinear_arith);
                        assert((bb + 1) * (2 * s) <= b * (2 * s)) by (nonlinear_arith)
                            requires bb + 1 <= b, s >= 1;
                        assert(bb * (2 * s) + r < base);
                        assert(bb * (2 * s) + s + r < base);
                        assert(data@[bb * (2 * s) + r] == pre[bb * (2 * s) + r]);
                        assert(data@[bb * (2 * s) + s + r] == pre[bb * (2 * s) + s + r]);
                    } else {
                        assert(bb == b);
                        assert(bb * (2 * s) == base) by (nonlinear_arith)
                            requires bb == b, base == b * (2 * s);
                        assert(bb * (2 * s) + r == base + r);
                        assert(bb * (2 * s) + s + r == base + s + r);
                        assert(base + 2 * s == (b + 1) * (2 * s)) by (nonlinear_arith)
                            requires base == b * (2 * s);
                        assert(base <= bb * (2 * s) + r < data@.len());
                        assert(base <= bb * (2 * s) + s + r < data@.len());
                        assert(pre[base + r] == old(data)@[base + r]);
                        assert(pre[base + s + r] == old(data)@[base + s + r]);
                        assert(tw as nat == xor(coset as nat, self.twiddles@[bb] as nat));
                        assert(data@[base + r] as nat == bfly_lo(
                            old(data)@[base + r] as nat,
                            old(data)@[base + s + r] as nat,
                            xor(coset as nat, self.twiddles@[bb] as nat),
                            128,
                        ));
                        assert(data@[base + s + r] as nat == xor(
                            data@[base + r] as nat,
                            old(data)@[base + s + r] as nat,
                        ));
                    }
                }

                assert forall|j: int| base + 2 * s <= j < data@.len() implies data@[j] == old(data)@[j] by {}
            }

            b += 1;
            base += 2 * s;
        }
    }

    // fwd_levels, additive.rs:
    // passes at stride 2^L for L = log_n-1 down to 0, coset sigma^L(offset).
    // Loop invariant: each stride-2^L class holds fwd_spec at depth log_n-L.
    fn fwd_levels_exec(&self, data: &mut Vec<u128>, offset: u128)
        requires
            self.wf(),
            old(data)@.len() == pow2(self.log_n as nat),
        ensures
            nats(final(data)@) == fwd_spec(
                nats(old(data)@),
                nats(self.twiddles@),
                self.log_n as nat,
                offset as nat,
                128,
            ),
    {
        let n = self.log_n;
        let dlen = data.len();

        let mut chain: Vec<u128> = Vec::new();
        let mut c = offset;
        let mut l: u32 = 0;

        while l < n
            invariant
                chain@.len() == l,
                l <= n,
                c as nat == sigma_pow(offset as nat, l as nat, 128),
                forall|j: int| 0 <= j < l ==> #[trigger] chain@[j] as nat == sigma_pow(
                    offset as nat,
                    j as nat,
                    128,
                ),
            decreases n - l,
        {
            chain.push(c);

            let sq = mul_flat(c, c);

            proof {
                sigma_pow_step(offset as nat, l as nat, 128);
            }

            c = add_flat(sq, c);
            l += 1;
        }

        proof {
            assert(dlen == data@.len());
            assert(data@.len() == pow2(n as nat));
            assert(data@.len() <= usize::MAX);

            assert forall|off: int| 0 <= off < pow2(n as nat) implies #[trigger] gather(
                nats(data@),
                off,
                pow2(n as nat) as int,
                pow2((n - n) as nat),
            ) == fwd_spec(
                gather(nats(old(data)@), off, pow2(n as nat) as int, pow2((n - n) as nat)),
                nats(self.twiddles@),
                (n - n) as nat,
                sigma_pow(offset as nat, n as nat, 128),
                128,
            ) by {
                assert((n - n) as nat == 0);
                assert(pow2(0) == 1);
            }
        }

        let mut lev: u32 = n;

        while lev > 0
            invariant
                self.wf(),
                n == self.log_n,
                data@.len() == pow2(n as nat),
                data@.len() <= usize::MAX,
                old(data)@.len() == pow2(n as nat),
                chain@.len() == n,
                forall|j: int| 0 <= j < n ==> #[trigger] chain@[j] as nat == sigma_pow(
                    offset as nat,
                    j as nat,
                    128,
                ),
                lev <= n,
                forall|off: int| 0 <= off < pow2(lev as nat) ==> #[trigger] gather(
                    nats(data@),
                    off,
                    pow2(lev as nat) as int,
                    pow2((n - lev) as nat),
                ) == fwd_spec(
                    gather(nats(old(data)@), off, pow2(lev as nat) as int, pow2((n - lev) as nat)),
                    nats(self.twiddles@),
                    (n - lev) as nat,
                    sigma_pow(offset as nat, lev as nat, 128),
                    128,
                ),
            decreases lev,
        {
            let new_l = lev - 1;

            proof {
                lemma_u64_pow2_no_overflow(new_l as nat);
                lemma_u64_shl_is_mul(1u64, new_l as u64);
                pow2_bridge(new_l as nat);

                lemma_u64_pow2_no_overflow((n - lev) as nat);
                lemma_u64_shl_is_mul(1u64, (n - lev) as u64);
                pow2_bridge((n - lev) as nat);

                assert(pow2(lev as nat) == 2 * pow2(new_l as nat));
                gf_model::pow2_add((n - lev) as nat, lev as nat);
                assert((n - lev) + lev == n);
                pow2_mono(lev as nat, n as nat);
                pow2_mono((n - lev) as nat, (n - 1) as nat);
                gf_model::pow2_pos(new_l as nat);
            }

            let s = (1u64 << new_l) as usize;
            let nblocks = (1u64 << (n - lev)) as usize;

            proof {
                assert(nblocks * (2 * s) == pow2((n - lev) as nat) * pow2(lev as nat));
                assert(2 * s <= usize::MAX);
                assert(s <= usize::MAX / 2);
            }

            let ghost pre = data@;

            assert(forall|off: int| 0 <= off < pow2(lev as nat) ==> #[trigger] gather(
                nats(pre),
                off,
                pow2(lev as nat) as int,
                pow2((n - lev) as nat),
            ) == fwd_spec(
                gather(nats(old(data)@), off, pow2(lev as nat) as int, pow2((n - lev) as nat)),
                nats(self.twiddles@),
                (n - lev) as nat,
                sigma_pow(offset as nat, lev as nat, 128),
                128,
            ));

            self.pass_fwd_exec(data, chain[new_l as usize], s, nblocks);

            proof {
                assert(nblocks * (2 * s) == pow2(n as nat));
                assert(chain@[new_l as int] as nat == sigma_pow(offset as nat, new_l as nat, 128));

                fwd_rows_bridge(
                    pre,
                    data@,
                    self.twiddles@,
                    n as nat,
                    lev as nat,
                    s as int,
                    nblocks as int,
                    chain@[new_l as int] as nat,
                );

                sigma_pow_step(offset as nat, new_l as nat, 128);

                assert(nats(pre).len() == pow2(n as nat));
                assert(nats(data@).len() == pow2(n as nat));
                assert(old(data)@.len() == pow2(self.log_n as nat));
                assert(self.log_n as nat == n as nat);
                assert(pow2(self.log_n as nat) == pow2(n as nat));
                assert(nats(old(data)@).len() == pow2(n as nat));
                assert((new_l as nat) + 1 == lev as nat);

                fwd_pass_step(
                    nats(pre),
                    nats(data@),
                    nats(old(data)@),
                    nats(self.twiddles@),
                    n as nat,
                    lev as nat,
                    sigma_pow(offset as nat, new_l as nat, 128),
                    128,
                );

                assert(forall|off: int| 0 <= off < pow2(new_l as nat) ==> #[trigger] gather(
                    nats(data@),
                    off,
                    pow2(new_l as nat) as int,
                    pow2((n - new_l) as nat),
                ) == fwd_spec(
                    gather(nats(old(data)@), off, pow2(new_l as nat) as int, pow2((n - new_l) as nat)),
                    nats(self.twiddles@),
                    (n - new_l) as nat,
                    sigma_pow(offset as nat, new_l as nat, 128),
                    128,
                )) by {
                    assert(new_l as nat == (lev - 1) as nat);
                    assert((n - new_l) as nat == (n - lev + 1) as nat);
                };
            }

            lev = new_l;
        }

        proof {
            assert(lev == 0);

            assert(gather(nats(data@), 0, pow2(lev as nat) as int, pow2((n - lev) as nat))
                == fwd_spec(
                gather(nats(old(data)@), 0, pow2(lev as nat) as int, pow2((n - lev) as nat)),
                nats(self.twiddles@),
                (n - lev) as nat,
                sigma_pow(offset as nat, lev as nat, 128),
                128,
            ));

            assert(pow2(lev as nat) == 1);
            assert((n - lev) as nat == n as nat);
            assert(sigma_pow(offset as nat, lev as nat, 128) == offset as nat);
            assert(self.log_n as nat == n as nat);
            assert(old(data)@.len() == pow2(n as nat));

            gather_ident(nats(old(data)@), pow2(n as nat));
            gather_ident(nats(data@), pow2(n as nat));

            assert(gather(nats(data@), 0, pow2(lev as nat) as int, pow2((n - lev) as nat))
                == nats(data@));
            assert(gather(nats(old(data)@), 0, pow2(lev as nat) as int, pow2((n - lev) as nat))
                == nats(old(data)@));
        }
    }

    // inv_butterflies, additive.rs:
    // qv = lo+hi, lo = bfly_lo(lo, qv, tw), hi = qv;
    // writes stay in [base,base+2s).
    fn inv_bfly_block(&self, data: &mut Vec<u128>, base: usize, s: usize, tw: u128)
        requires
            s >= 1,
            base + 2 * s <= old(data)@.len(),
            old(data)@.len() <= usize::MAX,
        ensures
            final(data)@.len() == old(data)@.len(),
            forall|r: int| 0 <= r < s ==> {
                &&& #[trigger] final(data)@[base + r] as nat == bfly_lo(
                    old(data)@[base + r] as nat,
                    xor(old(data)@[base + r] as nat, old(data)@[base + s + r] as nat),
                    tw as nat,
                    128,
                )
                &&& final(data)@[base + s + r] as nat == xor(
                    old(data)@[base + r] as nat,
                    old(data)@[base + s + r] as nat,
                )
            },
            forall|j: int|
                0 <= j < final(data)@.len() && (j < base || base + 2 * s <= j)
                    ==> final(data)@[j] == old(data)@[j],
    {
        let mut r: usize = 0;

        while r < s
            invariant
                s >= 1,
                base + 2 * s <= data@.len(),
                data@.len() == old(data)@.len(),
                data@.len() <= usize::MAX,
                r <= s,
                forall|u: int| 0 <= u < r ==> {
                    &&& #[trigger] data@[base + u] as nat == bfly_lo(
                        old(data)@[base + u] as nat,
                        xor(old(data)@[base + u] as nat, old(data)@[base + s + u] as nat),
                        tw as nat,
                        128,
                    )
                    &&& data@[base + s + u] as nat == xor(
                        old(data)@[base + u] as nat,
                        old(data)@[base + s + u] as nat,
                    )
                },
                forall|j: int|
                    0 <= j < data@.len() && !(base <= j < base + r) && !(base + s <= j < base + s
                        + r) ==> data@[j] == old(data)@[j],
            decreases s - r,
        {
            let lo_i = base + r;
            let hi_i = base + s + r;
            let ghost pre = data@;

            let a = data[lo_i];
            let b = data[hi_i];
            let qv = add_flat(a, b);

            proof {
                gf_mul_comm(tw as nat, qv as nat, 128);
            }

            data.set(lo_i, add_flat(a, mul_flat(qv, tw)));
            data.set(hi_i, qv);

            proof {
                let lo = old(data)@[base + r] as nat;
                let hi = old(data)@[base + s + r] as nat;

                assert(pre[base + r] == old(data)@[base + r]);
                assert(pre[base + s + r] == old(data)@[base + s + r]);
                assert(data@[base + r] as nat == bfly_lo(lo, xor(lo, hi), tw as nat, 128));
                assert(data@[base + s + r] as nat == xor(lo, hi));

                assert forall|u: int| 0 <= u < r implies #[trigger] data@[base + u] == pre[base + u]
                    && data@[base + s + u] == pre[base + s + u] by {
                    assert(base + u < base + r);
                    assert(base + r < base + s + u);
                    assert(base + s + u < base + s + r);
                }

                assert forall|u: int| 0 <= u < r + 1 implies {
                    &&& #[trigger] data@[base + u] as nat == bfly_lo(
                        old(data)@[base + u] as nat,
                        xor(old(data)@[base + u] as nat, old(data)@[base + s + u] as nat),
                        tw as nat,
                        128,
                    )
                    &&& data@[base + s + u] as nat == xor(
                        old(data)@[base + u] as nat,
                        old(data)@[base + s + u] as nat,
                    )
                } by {
                    if u < r {
                        assert(data@[base + u] == pre[base + u]);
                        assert(data@[base + s + u] == pre[base + s + u]);
                    }
                }
            }

            r += 1;
        }
    }

    // blocks_serial, additive.rs: inverse whole-array
    // pass at stride s; block b twiddled by xor(coset, tws[b]).
    fn pass_inv_exec(&self, data: &mut Vec<u128>, coset: u128, s: usize, nblocks: usize)
        requires
            self.wf(),
            s >= 1,
            s <= usize::MAX / 2,
            nblocks * (2 * s) == old(data)@.len(),
            nblocks <= self.twiddles@.len(),
            old(data)@.len() <= usize::MAX,
        ensures
            final(data)@.len() == old(data)@.len(),
            inv_rows(
                old(data)@,
                final(data)@,
                self.twiddles@,
                s as int,
                nblocks as int,
                coset as nat,
            ),
    {
        let mut b: usize = 0;
        let mut base: usize = 0;

        while b < nblocks
            invariant
                self.wf(),
                s >= 1,
                s <= usize::MAX / 2,
                data@.len() == old(data)@.len(),
                nblocks * (2 * s) == data@.len(),
                nblocks <= self.twiddles@.len(),
                b <= nblocks,
                base == b * (2 * s),
                data@.len() <= usize::MAX,
                forall|bb: int, r: int|
                    0 <= bb < b && 0 <= r < s ==> {
                        &&& #[trigger] data@[bb * (2 * s) + r] as nat == bfly_lo(
                            old(data)@[bb * (2 * s) + r] as nat,
                            xor(
                                old(data)@[bb * (2 * s) + r] as nat,
                                old(data)@[bb * (2 * s) + s + r] as nat,
                            ),
                            xor(coset as nat, self.twiddles@[bb] as nat),
                            128,
                        )
                        &&& data@[bb * (2 * s) + s + r] as nat == xor(
                            old(data)@[bb * (2 * s) + r] as nat,
                            old(data)@[bb * (2 * s) + s + r] as nat,
                        )
                    },
                forall|j: int| base <= j < data@.len() ==> data@[j] == old(data)@[j],
            decreases nblocks - b,
        {
            proof {
                lemma_mul_inequality((b + 1) as int, nblocks as int, (2 * s) as int);

                assert((b + 1) * (2 * s) == base + 2 * s) by (nonlinear_arith)
                    requires base == b * (2 * s);
            }

            let tw = add_flat(coset, self.twiddles[b]);
            let ghost pre = data@;

            self.inv_bfly_block(data, base, s, tw);

            proof {
                assert forall|bb: int, r: int| 0 <= bb < b + 1 && 0 <= r < s implies {
                    &&& #[trigger] data@[bb * (2 * s) + r] as nat == bfly_lo(
                        old(data)@[bb * (2 * s) + r] as nat,
                        xor(
                            old(data)@[bb * (2 * s) + r] as nat,
                            old(data)@[bb * (2 * s) + s + r] as nat,
                        ),
                        xor(coset as nat, self.twiddles@[bb] as nat),
                        128,
                    )
                    &&& data@[bb * (2 * s) + s + r] as nat == xor(
                        old(data)@[bb * (2 * s) + r] as nat,
                        old(data)@[bb * (2 * s) + s + r] as nat,
                    )
                } by {
                    if bb < b {
                        assert(0 <= bb * (2 * s)) by (nonlinear_arith)
                            requires bb >= 0, s >= 1;
                        assert(bb * (2 * s) + 2 * s == (bb + 1) * (2 * s)) by (nonlinear_arith);
                        assert((bb + 1) * (2 * s) <= b * (2 * s)) by (nonlinear_arith)
                            requires bb + 1 <= b, s >= 1;
                        assert(bb * (2 * s) + r < base);
                        assert(bb * (2 * s) + s + r < base);
                        assert(data@[bb * (2 * s) + r] == pre[bb * (2 * s) + r]);
                        assert(data@[bb * (2 * s) + s + r] == pre[bb * (2 * s) + s + r]);
                    } else {
                        assert(bb == b);
                        assert(bb * (2 * s) == base) by (nonlinear_arith)
                            requires bb == b, base == b * (2 * s);
                        assert(bb * (2 * s) + r == base + r);
                        assert(bb * (2 * s) + s + r == base + s + r);
                        assert(base + 2 * s == (b + 1) * (2 * s)) by (nonlinear_arith)
                            requires base == b * (2 * s);
                        assert(base <= bb * (2 * s) + r < data@.len());
                        assert(base <= bb * (2 * s) + s + r < data@.len());
                        assert(pre[base + r] == old(data)@[base + r]);
                        assert(pre[base + s + r] == old(data)@[base + s + r]);
                        assert(tw as nat == xor(coset as nat, self.twiddles@[bb] as nat));
                        assert(data@[base + r] as nat == bfly_lo(
                            old(data)@[base + r] as nat,
                            xor(old(data)@[base + r] as nat, old(data)@[base + s + r] as nat),
                            xor(coset as nat, self.twiddles@[bb] as nat),
                            128,
                        ));
                        assert(data@[base + s + r] as nat == xor(
                            old(data)@[base + r] as nat,
                            old(data)@[base + s + r] as nat,
                        ));
                    }
                }

                assert forall|j: int| base + 2 * s <= j < data@.len() implies data@[j] == old(data)@[j] by {}
            }

            b += 1;
            base += 2 * s;
        }
    }

    // inv_levels, additive.rs:
    // passes at stride 2^L for L = 0 up to log_n-1, coset sigma^L(offset).
    // Loop invariant: each stride-2^L class still owes its depth-(log_n-L)
    // inv_spec to reach fin = inv_spec(input).
    fn inv_levels_exec(&self, data: &mut Vec<u128>, offset: u128)
        requires
            self.wf(),
            old(data)@.len() == pow2(self.log_n as nat),
        ensures
            nats(final(data)@) == inv_spec(
                nats(old(data)@),
                nats(self.twiddles@),
                self.log_n as nat,
                offset as nat,
                128,
            ),
    {
        let n = self.log_n;
        let dlen = data.len();

        let ghost fin = inv_spec(
            nats(old(data)@),
            nats(self.twiddles@),
            n as nat,
            offset as nat,
            128,
        );

        proof {
            assert(dlen == data@.len());
            assert(data@.len() == pow2(n as nat));
            assert(data@.len() <= usize::MAX);
            inv_spec_len(nats(old(data)@), nats(self.twiddles@), n as nat, offset as nat, 128);
            gather_ident(nats(data@), pow2(n as nat));
            gather_ident(fin, pow2(n as nat));

            assert forall|off: int| 0 <= off < pow2(0) implies #[trigger] inv_spec(
                gather(nats(data@), off, pow2(0) as int, pow2((n - 0) as nat)),
                nats(self.twiddles@),
                (n - 0) as nat,
                sigma_pow(offset as nat, 0, 128),
                128,
            ) == gather(fin, off, pow2(0) as int, pow2((n - 0) as nat)) by {
                assert(pow2(0) == 1);
                assert(off == 0);
                assert(sigma_pow(offset as nat, 0, 128) == offset as nat);
            }
        }

        let mut c = offset;
        let mut lev: u32 = 0;

        while lev < n
            invariant
                self.wf(),
                n == self.log_n,
                data@.len() == pow2(n as nat),
                data@.len() <= usize::MAX,
                old(data)@.len() == pow2(n as nat),
                fin.len() == pow2(n as nat),
                fin == inv_spec(
                    nats(old(data)@),
                    nats(self.twiddles@),
                    n as nat,
                    offset as nat,
                    128,
                ),
                lev <= n,
                c as nat == sigma_pow(offset as nat, lev as nat, 128),
                forall|off: int| 0 <= off < pow2(lev as nat) ==> #[trigger] inv_spec(
                    gather(nats(data@), off, pow2(lev as nat) as int, pow2((n - lev) as nat)),
                    nats(self.twiddles@),
                    (n - lev) as nat,
                    sigma_pow(offset as nat, lev as nat, 128),
                    128,
                ) == gather(fin, off, pow2(lev as nat) as int, pow2((n - lev) as nat)),
            decreases n - lev,
        {
            proof {
                lemma_u64_pow2_no_overflow(lev as nat);
                lemma_u64_shl_is_mul(1u64, lev as u64);
                pow2_bridge(lev as nat);

                lemma_u64_pow2_no_overflow((n - lev - 1) as nat);
                lemma_u64_shl_is_mul(1u64, (n - lev - 1) as u64);
                pow2_bridge((n - lev - 1) as nat);

                assert(pow2((lev + 1) as nat) == 2 * pow2(lev as nat));
                gf_model::pow2_add((n - lev - 1) as nat, (lev + 1) as nat);
                assert((n - lev - 1) + (lev + 1) == n);
                pow2_mono((lev + 1) as nat, n as nat);
                pow2_mono((n - lev - 1) as nat, (n - 1) as nat);
                gf_model::pow2_pos(lev as nat);
            }

            let s = (1u64 << lev) as usize;
            let nblocks = (1u64 << (n - lev - 1)) as usize;

            proof {
                assert(nblocks * (2 * s) == pow2((n - lev - 1) as nat) * pow2((lev + 1) as nat));
                assert(2 * s <= usize::MAX);
                assert(s <= usize::MAX / 2);
            }

            let ghost pre = data@;

            assert(forall|off: int| 0 <= off < pow2(lev as nat) ==> #[trigger] inv_spec(
                gather(nats(pre), off, pow2(lev as nat) as int, pow2((n - lev) as nat)),
                nats(self.twiddles@),
                (n - lev) as nat,
                sigma_pow(offset as nat, lev as nat, 128),
                128,
            ) == gather(fin, off, pow2(lev as nat) as int, pow2((n - lev) as nat)));

            self.pass_inv_exec(data, c, s, nblocks);

            proof {
                assert(nblocks * (2 * s) == pow2(n as nat));

                inv_rows_bridge(
                    pre,
                    data@,
                    self.twiddles@,
                    n as nat,
                    lev as nat,
                    s as int,
                    nblocks as int,
                    c as nat,
                );

                sigma_pow_step(offset as nat, lev as nat, 128);

                assert(nats(pre).len() == pow2(n as nat));
                assert(nats(data@).len() == pow2(n as nat));

                inv_pass_step(
                    nats(pre),
                    nats(data@),
                    fin,
                    nats(self.twiddles@),
                    n as nat,
                    lev as nat,
                    sigma_pow(offset as nat, lev as nat, 128),
                    128,
                );

                assert(forall|off: int| 0 <= off < pow2((lev + 1) as nat) ==> #[trigger] inv_spec(
                    gather(
                        nats(data@),
                        off,
                        pow2((lev + 1) as nat) as int,
                        pow2((n - lev - 1) as nat),
                    ),
                    nats(self.twiddles@),
                    (n - lev - 1) as nat,
                    sigma_pow(offset as nat, (lev + 1) as nat, 128),
                    128,
                ) == gather(fin, off, pow2((lev + 1) as nat) as int, pow2((n - lev - 1) as nat)));
            }

            c = add_flat(mul_flat(c, c), c);
            lev += 1;
        }

        proof {
            assert(lev == n);

            assert forall|off: int| 0 <= off < pow2(n as nat) implies nats(data@)[off] == fin[off] by {
                assert(inv_spec(
                    gather(nats(data@), off, pow2(lev as nat) as int, pow2((n - lev) as nat)),
                    nats(self.twiddles@),
                    (n - lev) as nat,
                    sigma_pow(offset as nat, lev as nat, 128),
                    128,
                ) == gather(fin, off, pow2(lev as nat) as int, pow2((n - lev) as nat)));

                assert((n - lev) as nat == 0);
                assert(pow2((n - lev) as nat) == 1);
                assert(gather(nats(data@), off, pow2(lev as nat) as int, 1)[0] == nats(data@)[off]);
                assert(gather(fin, off, pow2(lev as nat) as int, 1)[0] == fin[off]);
            }

            assert(nats(data@) =~= fin);
        }
    }

    pub fn forward_coset(&self, data: &mut Vec<u128>, offset: u128) -> (r: Result<(), ()>)
        requires self.wf(),
        ensures
            old(data)@.len() != pow2(self.log_n as nat)
                ==> r is Err && final(data)@ == old(data)@,
            old(data)@.len() == pow2(self.log_n as nat)
                ==> r is Ok && nats(final(data)@) == fwd_spec(
                    nats(old(data)@),
                    nats(self.twiddles@),
                    self.log_n as nat,
                    offset as nat,
                    128,
                ),
    {
        proof {
            lemma_u64_pow2_no_overflow(self.log_n as nat);
            lemma_u64_shl_is_mul(1u64, self.log_n as u64);
            pow2_bridge(self.log_n as nat);
        }

        let expected = (1u64 << self.log_n) as usize;

        if data.len() != expected {
            return Err(());
        }

        self.fwd_levels_exec(data, offset);

        Ok(())
    }

    pub fn inverse_coset(&self, data: &mut Vec<u128>, offset: u128) -> (r: Result<(), ()>)
        requires self.wf(),
        ensures
            old(data)@.len() != pow2(self.log_n as nat)
                ==> r is Err && final(data)@ == old(data)@,
            old(data)@.len() == pow2(self.log_n as nat)
                ==> r is Ok && nats(final(data)@) == inv_spec(
                    nats(old(data)@),
                    nats(self.twiddles@),
                    self.log_n as nat,
                    offset as nat,
                    128,
                ),
    {
        proof {
            lemma_u64_pow2_no_overflow(self.log_n as nat);
            lemma_u64_shl_is_mul(1u64, self.log_n as u64);
            pow2_bridge(self.log_n as nat);
        }

        let expected = (1u64 << self.log_n) as usize;

        if data.len() != expected {
            return Err(());
        }

        self.inv_levels_exec(data, offset);

        Ok(())
    }
}

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

fn main() {}

}
