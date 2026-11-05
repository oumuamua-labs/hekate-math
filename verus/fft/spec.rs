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
use super::twiddles::{nats, tw_sum};

#[cfg(verus_keep_ghost)]
use gf_model::{
    deg_xor_lt, gf_distrib, gf_mul, gf_mul_assoc, gf_mul_closed, gf_mul_comm, gf_sq_additive,
    in_field, pow2, pow2_mono, xor, xor_assoc, xor_comm, xor_rearrange4, xor_self, xor_zero,
};
#[cfg(verus_keep_ghost)]
use vstd::arithmetic::div_mod::lemma_fundamental_div_mod;

verus! {

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

pub proof fn sigma_pow_step(x: nat, l: nat, k: nat)
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

pub proof fn fwd_spec_len(v: Seq<nat>, tws: Seq<nat>, d: nat, coset: nat, k: nat)
    ensures fwd_spec(v, tws, d, coset, k).len() == v.len()
{
    if d == 0 {
    } else {
    }
}

pub proof fn inv_spec_len(w: Seq<nat>, tws: Seq<nat>, d: nat, coset: nat, k: nat)
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

pub proof fn gf_mul_one_l(y: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        in_field(y, k),
    ensures gf_mul(1, y, k) == y
{
    gf_model::clmul_one_l(y);
    gf_model::deg_modulus(k);
}

pub proof fn gf_mul_one_r(y: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        in_field(y, k),
    ensures gf_mul(y, 1, k) == y
{
    gf_mul_comm(y, 1, k);
    gf_mul_one_l(y, k);
}

pub proof fn gf_mul_zero_l(y: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures gf_mul(0, y, k) == 0
{
    gf_model::deg_modulus(k);

    assert(gf_model::clmul(0, y) == 0);
    assert(gf_model::deg(0) == -1);
}

pub proof fn sigma_additive(a: nat, b: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures sigma(xor(a, b), k) == xor(sigma(a, k), sigma(b, k))
{
    gf_sq_additive(a, b, k);

    let aa = gf_mul(a, a, k);
    let bb = gf_mul(b, b, k);

    xor_rearrange4(aa, bb, a, b);
}

pub proof fn sigma_zero(k: nat)
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
pub proof fn sigma_point(beta: Seq<nat>, i: nat, k: nat)
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
pub proof fn tw_sum_is_point(lift: Seq<nat>, t: nat, base: nat)
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

}
