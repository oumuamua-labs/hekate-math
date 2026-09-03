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
//! only the xor group, so it holds for any twiddle and any multiply.

use vstd::prelude::*;

#[path = "gf_model.rs"]
pub mod gf_model;

use gf_model::{
    deg_xor_lt, gf_distrib, gf_mul, gf_mul_assoc, gf_mul_closed, gf_mul_comm, gf_sq_additive,
    in_field, pow2, pow2_mono, xor, xor_assoc, xor_comm, xor_rearrange4, xor_self, xor_zero,
};
use vstd::arithmetic::div_mod::{
    lemma_div_denominator, lemma_fundamental_div_mod, lemma_fundamental_div_mod_converse_div,
    lemma_fundamental_div_mod_converse_mod,
};
use vstd::arithmetic::mul::{
    lemma_mul_inequality, lemma_mul_is_associative, lemma_mul_is_commutative,
    lemma_mul_is_distributive_add, lemma_mul_strict_inequality,
};
use vstd::bits::{lemma_u64_pow2_no_overflow, lemma_u64_shl_is_mul, lemma_u64_shr_is_div};
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

// Trusted seam, never executed: stands for the production
// flat multiply; every transform theorem in this file is
// relative to this ensures (TRUSTED_AXIOMS.md).
#[verifier::external_body]
fn mul_flat(a: u128, b: u128) -> (r: u128)
    ensures r as nat == gf_mul(a as nat, b as nat, 128)
{
    unimplemented!()
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
// Constructor twin: new(), additive.rs, from the lift
// chain on. The solve_quadratic loop producing `lift` is
// checked at build time; `bits` is u64 where production
// uses usize (identical on the pinned platform).
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
        let mut t: usize = 0;

        while t < half
            invariant
                twiddles@.len() == t,
                t <= half,
                half as nat == pow2((log_n - 1) as nat),
                lift@.len() == log_n - 1,
                1 <= log_n < 64,
                forall|u: int| 0 <= u < t
                    ==> #[trigger] twiddles@[u] as nat == tw_sum(nats(lift@), u as nat, 0),
            decreases half - t,
        {
            let mut acc: u128 = 0;
            let mut bits: u64 = t as u64;

            proof {
                xor_zero(tw_sum(nats(lift@), t as nat, 0));
            }

            while bits != 0
                invariant
                    bits as nat <= t as nat,
                    t < half,
                    half as nat == pow2((log_n - 1) as nat),
                    lift@.len() == log_n - 1,
                    1 <= log_n < 64,
                    xor(acc as nat, tw_sum(nats(lift@), bits as nat, 0))
                        == tw_sum(nats(lift@), t as nat, 0),
                decreases bits,
            {
                let j32 = bits.trailing_zeros();
                let j = j32 as usize;
                let ghost jn = j as nat;
                let ghost j64: u64 = j32 as u64;

                proof {
                    axiom_u64_trailing_zeros(bits);

                    assert(j64 < 64);

                    lemma_u64_shr_is_div(bits, j64);
                    pow2_bridge(jn);

                    let q = bits >> j64;

                    assert(q as nat == bits as nat / pow2(jn));
                    assert((q & 1u64) == 1u64);
                    assert(q % 2 == 1) by (bit_vector) requires (q & 1u64) == 1u64;

                    low_bits_zero_mod(bits, j64);
                    tw_sum_clear_bit(nats(lift@), bits as nat, jn, 0);

                    if jn >= (log_n - 1) as nat {
                        pow2_mono((log_n - 1) as nat, jn);

                        assert(pow2(jn) <= bits as nat);
                        assert(false);
                    }
                }

                let l = lift[j];

                proof {
                    xor128_reflect(acc, l);

                    assert(nats(lift@)[j as int] == l as nat);
                }

                let ghost acc_old = acc as nat;
                let ghost bits_prev: u64 = bits;

                acc = acc ^ l;
                bits = bits & (bits - 1);

                proof {
                    and_dec_is_sub(bits_prev, j64);
                    gf_model::pow2_pos(jn);

                    assert(bits == (bits_prev & sub(bits_prev, 1u64)));
                    assert(bits as nat == bits_prev as nat - pow2(jn));
                    assert(bits < bits_prev);

                    xor_assoc(
                        acc_old,
                        nats(lift@)[j as int],
                        tw_sum(nats(lift@), bits as nat, 0),
                    );
                }
            }

            proof {
                assert(tw_sum(nats(lift@), 0, 0) == 0);
                xor_zero(acc as nat);
            }

            twiddles.push(acc);
            t += 1;
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
            },
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
            },
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
            forall|b: int, r: int|
                0 <= b < nblocks && 0 <= r < s ==> {
                    &&& #[trigger] final(data)@[b * (2 * s) + r] as nat == bfly_lo(
                        old(data)@[b * (2 * s) + r] as nat,
                        old(data)@[b * (2 * s) + s + r] as nat,
                        xor(coset as nat, self.twiddles@[b] as nat),
                        128,
                    )
                    &&& final(data)@[b * (2 * s) + s + r] as nat == xor(
                        final(data)@[b * (2 * s) + r] as nat,
                        old(data)@[b * (2 * s) + s + r] as nat,
                    )
                },
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
                        assert(bb * (2 * s) + 2 * s == (bb + 1) * (2 * s)) by (nonlinear_arith);
                        assert((bb + 1) * (2 * s) <= b * (2 * s)) by (nonlinear_arith)
                            requires bb + 1 <= b, s >= 1;
                        assert(bb * (2 * s) + r < base);
                        assert(bb * (2 * s) + s + r < base);
                    } else {
                        assert(bb == b);
                        assert(bb * (2 * s) == base) by (nonlinear_arith)
                            requires bb == b, base == b * (2 * s);
                        assert(base + 2 * s == (b + 1) * (2 * s)) by (nonlinear_arith)
                            requires base == b * (2 * s);
                        assert(base <= bb * (2 * s) + r < data@.len());
                        assert(base <= bb * (2 * s) + s + r < data@.len());
                    }
                }

                assert forall|j: int| base + 2 * s <= j < data@.len() implies data@[j] == old(data)@[j] by {}
            }

            b = b + 1;
            base = base + 2 * s;
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
            l = l + 1;
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
                assert forall|b: int, r: int|
                    0 <= b < pow2((n - lev) as nat) && 0 <= r < pow2((lev - 1) as nat) implies {
                    &&& #[trigger] nats(data@)[b * pow2(lev as nat) + r] == bfly_lo(
                        nats(pre)[b * pow2(lev as nat) + r],
                        nats(pre)[b * pow2(lev as nat) + pow2((lev - 1) as nat) + r],
                        xor(sigma_pow(offset as nat, new_l as nat, 128), nats(self.twiddles@)[b]),
                        128,
                    )
                    &&& nats(data@)[b * pow2(lev as nat) + pow2((lev - 1) as nat) + r] == xor(
                        nats(data@)[b * pow2(lev as nat) + r],
                        nats(pre)[b * pow2(lev as nat) + pow2((lev - 1) as nat) + r],
                    )
                } by {
                    assert(b < nblocks);
                    assert(pow2(lev as nat) == 2 * (s as nat));
                    assert(pow2((lev - 1) as nat) == s as nat);
                    assert(nblocks * (2 * s) == pow2(n as nat));

                    lemma_mul_inequality((b + 1) as int, nblocks as int, (2 * s) as int);

                    assert(b * pow2(lev as nat) == b * (2 * s)) by (nonlinear_arith)
                        requires pow2(lev as nat) == 2 * (s as nat);
                    assert((b + 1) * (2 * s) == b * (2 * s) + 2 * s) by (nonlinear_arith);

                    assert(0 <= b * (2 * s) + r < data@.len());
                    assert(0 <= b * (2 * s) + s + r < data@.len());
                    assert(chain@[new_l as int] as nat == sigma_pow(offset as nat, new_l as nat, 128));
                }

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

            let a = data[lo_i];
            let b = data[hi_i];
            let qv = add_flat(a, b);

            proof {
                gf_mul_comm(tw as nat, qv as nat, 128);
            }

            data.set(lo_i, add_flat(a, mul_flat(qv, tw)));
            data.set(hi_i, qv);

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
            forall|b: int, r: int|
                0 <= b < nblocks && 0 <= r < s ==> {
                    &&& #[trigger] final(data)@[b * (2 * s) + r] as nat == bfly_lo(
                        old(data)@[b * (2 * s) + r] as nat,
                        xor(
                            old(data)@[b * (2 * s) + r] as nat,
                            old(data)@[b * (2 * s) + s + r] as nat,
                        ),
                        xor(coset as nat, self.twiddles@[b] as nat),
                        128,
                    )
                    &&& final(data)@[b * (2 * s) + s + r] as nat == xor(
                        old(data)@[b * (2 * s) + r] as nat,
                        old(data)@[b * (2 * s) + s + r] as nat,
                    )
                },
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
                        assert(bb * (2 * s) + 2 * s == (bb + 1) * (2 * s)) by (nonlinear_arith);
                        assert((bb + 1) * (2 * s) <= b * (2 * s)) by (nonlinear_arith)
                            requires bb + 1 <= b, s >= 1;
                        assert(bb * (2 * s) + r < base);
                        assert(bb * (2 * s) + s + r < base);
                    } else {
                        assert(bb == b);
                        assert(bb * (2 * s) == base) by (nonlinear_arith)
                            requires bb == b, base == b * (2 * s);
                        assert(base + 2 * s == (b + 1) * (2 * s)) by (nonlinear_arith)
                            requires base == b * (2 * s);
                        assert(base <= bb * (2 * s) + r < data@.len());
                        assert(base <= bb * (2 * s) + s + r < data@.len());
                    }
                }

                assert forall|j: int| base + 2 * s <= j < data@.len() implies data@[j] == old(data)@[j] by {}
            }

            b = b + 1;
            base = base + 2 * s;
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
                assert forall|b: int, r: int|
                    0 <= b < pow2((n - lev - 1) as nat) && 0 <= r < pow2(lev as nat) implies {
                    &&& #[trigger] nats(data@)[b * pow2((lev + 1) as nat) + r] == bfly_lo(
                        nats(pre)[b * pow2((lev + 1) as nat) + r],
                        xor(
                            nats(pre)[b * pow2((lev + 1) as nat) + r],
                            nats(pre)[b * pow2((lev + 1) as nat) + pow2(lev as nat) + r],
                        ),
                        xor(sigma_pow(offset as nat, lev as nat, 128), nats(self.twiddles@)[b]),
                        128,
                    )
                    &&& nats(data@)[b * pow2((lev + 1) as nat) + pow2(lev as nat) + r] == xor(
                        nats(pre)[b * pow2((lev + 1) as nat) + r],
                        nats(pre)[b * pow2((lev + 1) as nat) + pow2(lev as nat) + r],
                    )
                } by {
                    assert(b < nblocks);
                    assert(pow2((lev + 1) as nat) == 2 * (s as nat));
                    assert(pow2(lev as nat) == s as nat);
                    assert(nblocks * (2 * s) == pow2(n as nat));

                    lemma_mul_inequality((b + 1) as int, nblocks as int, (2 * s) as int);

                    assert(b * pow2((lev + 1) as nat) == b * (2 * s)) by (nonlinear_arith)
                        requires pow2((lev + 1) as nat) == 2 * (s as nat);
                    assert((b + 1) * (2 * s) == b * (2 * s) + 2 * s) by (nonlinear_arith);

                    assert(0 <= b * (2 * s) + r < data@.len());
                    assert(0 <= b * (2 * s) + s + r < data@.len());
                }

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
            lev = lev + 1;
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

fn main() {}

}
