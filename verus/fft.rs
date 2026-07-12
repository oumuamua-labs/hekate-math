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
//! The spec recursions mirror the strided in-place transforms
//! in contiguous form; the round-trip theorem uses only the xor
//! group, it holds for arbitrary twiddle values and any multiply.

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

// fwd_scalar, additive.rs:185-208: recurse on the even
// and odd sub-arrays with coset sigma(coset), then
// butterfly pair t with twiddle coset + tws[t].
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

// inv_scalar, additive.rs:213-236: butterfly first
// (q = o0 + o1, p = o0 + tw*q), then recurse.
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
// Constructor twin: new(), additive.rs:64-100, from the lift
// chain on. The solve_quadratic loop producing `lift` is
// checked at build time; `bits` is u64 where production uses
// usize (identical on the pinned platform).
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
// Strided view: a transform at (off, stride, d) touches
// exactly { off + i*stride : i < 2^d }; with off < stride,
// membership is j % stride == off and j / stride < 2^d
// ============================================================

pub open spec fn gather(s: Seq<nat>, off: int, stride: int, n: nat) -> Seq<nat> {
    Seq::new(n, |i: int| s[off + i * stride])
}

pub open spec fn in_class(j: int, off: int, stride: int, n: nat) -> bool {
    &&& j % stride == off
    &&& j / stride < n
}

pub open spec fn pos0(off: int, stride: int, u: int) -> int {
    off + 2 * u * stride
}

pub open spec fn pos1(off: int, stride: int, u: int) -> int {
    off + 2 * u * stride + stride
}

proof fn class_member(off: int, stride: int, n: nat, i: int)
    requires
        0 <= off < stride,
        0 <= i < n,
    ensures
        in_class(off + i * stride, off, stride, n),
        (off + i * stride) / stride == i,
{
    let x = off + i * stride;

    assert(x == i * stride + off);
    lemma_fundamental_div_mod_converse_mod(x, stride, i, off);
    lemma_fundamental_div_mod_converse_div(x, stride, i, off);
}

proof fn class_elim(j: int, off: int, stride: int, n: nat)
    requires
        0 <= off < stride,
        j >= 0,
        in_class(j, off, stride, n),
    ensures ({
        let i = j / stride;
        0 <= i < n && j == off + i * stride
    })
{
    lemma_fundamental_div_mod(j, stride);
    lemma_mul_is_commutative(stride, j / stride);

    assert(j / stride >= 0) by (nonlinear_arith)
        requires j >= 0, stride > 0;
}

proof fn class_split(j: int, off: int, stride: int, d: nat)
    requires
        0 <= off < stride,
        d >= 1,
        j >= 0,
    ensures
        in_class(j, off, stride, pow2(d)) <==> (
            in_class(j, off, 2 * stride, pow2((d - 1) as nat))
            || in_class(j, off + stride, 2 * stride, pow2((d - 1) as nat))
        ),
{
    let h = pow2((d - 1) as nat);
    let s = stride;

    assert(pow2(d) == 2 * h);

    if in_class(j, off, s, pow2(d)) {
        class_elim(j, off, s, pow2(d));

        let i = j / s;

        lemma_fundamental_div_mod(i, 2);

        let q = i / 2;

        if i % 2 == 0 {
            assert((2 * q) * s == q * (2 * s)) by (nonlinear_arith);
            assert(j == q * (2 * s) + off);
            lemma_fundamental_div_mod_converse_mod(j, 2 * s, q, off);
            lemma_fundamental_div_mod_converse_div(j, 2 * s, q, off);
        } else {
            assert((2 * q + 1) * s == q * (2 * s) + s) by (nonlinear_arith);
            assert(j == q * (2 * s) + (off + s));
            lemma_fundamental_div_mod_converse_mod(j, 2 * s, q, off + s);
            lemma_fundamental_div_mod_converse_div(j, 2 * s, q, off + s);
        }
    }

    if in_class(j, off, 2 * s, h) {
        class_elim(j, off, 2 * s, h);

        let q = j / (2 * s);

        assert(q * (2 * s) == (2 * q) * s) by (nonlinear_arith);
        assert(j == (2 * q) * s + off);
        lemma_fundamental_div_mod_converse_mod(j, s, 2 * q, off);
        lemma_fundamental_div_mod_converse_div(j, s, 2 * q, off);
    }

    if in_class(j, off + s, 2 * s, h) {
        class_elim(j, off + s, 2 * s, h);

        let q = j / (2 * s);

        assert(q * (2 * s) + s == (2 * q + 1) * s) by (nonlinear_arith);
        assert(j == (2 * q + 1) * s + off);
        lemma_fundamental_div_mod_converse_mod(j, s, 2 * q + 1, off);
        lemma_fundamental_div_mod_converse_div(j, s, 2 * q + 1, off);
    }
}

proof fn idx_bound(off: int, stride: int, i: int, n: int)
    requires
        0 <= off < stride,
        0 <= i < n,
    ensures off + i * stride < n * stride,
{
    lemma_mul_inequality(i + 1, n, stride);
    lemma_mul_is_commutative(i + 1, stride);
    lemma_mul_is_distributive_add(stride, i, 1);
    lemma_mul_is_commutative(i, stride);
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

impl FftTwin {
    // fwd_scalar, additive.rs:185-208; also the index shape
    // of fwd_packed (identical strides, packed element ops).
    fn fwd_exec(&self, data: &mut Vec<u128>, off: usize, stride: usize, d: u32, coset: u128)
        requires
            self.wf(),
            d <= self.log_n,
            stride >= 1,
            off < stride,
            (stride as nat) * pow2(d as nat) <= old(data)@.len(),
            old(data)@.len() <= usize::MAX,
        ensures
            final(data)@.len() == old(data)@.len(),
            gather(nats(final(data)@), off as int, stride as int, pow2(d as nat))
                == fwd_spec(
                    gather(nats(old(data)@), off as int, stride as int, pow2(d as nat)),
                    nats(self.twiddles@),
                    d as nat,
                    coset as nat,
                    128,
                ),
            forall|j: int|
                0 <= j < final(data)@.len()
                    && !in_class(j, off as int, stride as int, pow2(d as nat))
                    ==> final(data)@[j] == old(data)@[j],
        decreases d,
    {
        let ghost g0 = gather(nats(old(data)@), off as int, stride as int, pow2(d as nat));
        let ghost tws = nats(self.twiddles@);

        if d == 0 {
            proof {
                assert(pow2(0) == 1);
                assert(gather(nats(data@), off as int, stride as int, 1) =~= g0);
            }

            return;
        }

        let ghost dm1 = (d - 1) as nat;

        proof {
            lemma_u64_pow2_no_overflow(dm1);
            lemma_u64_shl_is_mul(1u64, (d - 1) as u64);
            pow2_bridge(dm1);
        }

        let half = (1u64 << (d - 1)) as usize;
        let child = add_flat(mul_flat(coset, coset), coset);

        let ghost e_seq = fwd_spec(evens(g0), tws, dm1, child as nat, 128);
        let ghost o_seq = fwd_spec(odds(g0), tws, dm1, child as nat, 128);

        proof {
            assert(half as nat == pow2(dm1));
            assert(child as nat == sigma(coset as nat, 128));
            assert(pow2(d as nat) == 2 * pow2(dm1));
            gf_model::pow2_pos(dm1);

            assert((2 * (stride as nat)) * pow2(dm1) == (stride as nat) * pow2(d as nat))
                by (nonlinear_arith)
                requires pow2(d as nat) == 2 * pow2(dm1),
            {}

            assert((stride as nat) * 2 <= (stride as nat) * pow2(d as nat)) by (nonlinear_arith)
                requires pow2(d as nat) == 2 * pow2(dm1), pow2(dm1) >= 1,
            {}

            gather_split(nats(old(data)@), off as int, stride as int, d as nat);
        }

        self.fwd_exec(data, off, stride * 2, d - 1, child);

        let ghost s1 = nats(data@);

        proof {
            assert(gather(s1, off as int, 2 * (stride as int), pow2(dm1)) == e_seq);
        }

        self.fwd_exec(data, off + stride, stride * 2, d - 1, child);

        let ghost s2 = nats(data@);

        proof {
            // Call 1 left the odd child class untouched.
            assert forall|u: int| 0 <= u < pow2(dm1) implies
                #[trigger] gather(s1, off + stride as int, 2 * (stride as int), pow2(dm1))[u]
                    == gather(nats(old(data)@), off + stride as int, 2 * (stride as int),
                        pow2(dm1))[u] by {
                let j = off + stride as int + u * (2 * (stride as int));

                class_member(off + stride as int, 2 * (stride as int), pow2(dm1), u);
                idx_bound(off + stride as int, 2 * (stride as int), u, pow2(dm1) as int);

                assert(pow2(dm1) as int * (2 * (stride as int))
                    == (stride as int) * (pow2(d as nat) as int)) by (nonlinear_arith)
                    requires pow2(d as nat) == 2 * pow2(dm1),
                {}

                assert(!in_class(j, off as int, 2 * (stride as int), pow2(dm1)));
            }

            assert(gather(s1, off + stride as int, 2 * (stride as int), pow2(dm1))
                =~= gather(nats(old(data)@), off + stride as int, 2 * (stride as int),
                    pow2(dm1)));
            assert(gather(s2, off + stride as int, 2 * (stride as int), pow2(dm1)) == o_seq);

            // Call 2 left the even child class untouched.
            assert forall|u: int| 0 <= u < pow2(dm1) implies
                #[trigger] gather(s2, off as int, 2 * (stride as int), pow2(dm1))[u]
                    == gather(s1, off as int, 2 * (stride as int), pow2(dm1))[u] by {
                let j = off as int + u * (2 * (stride as int));

                class_member(off as int, 2 * (stride as int), pow2(dm1), u);
                idx_bound(off as int, 2 * (stride as int), u, pow2(dm1) as int);

                assert(pow2(dm1) as int * (2 * (stride as int))
                    == (stride as int) * (pow2(d as nat) as int)) by (nonlinear_arith)
                    requires pow2(d as nat) == 2 * pow2(dm1),
                {}

                assert(!in_class(j, off + stride as int, 2 * (stride as int), pow2(dm1)));
            }

            assert(gather(s2, off as int, 2 * (stride as int), pow2(dm1))
                =~= gather(s1, off as int, 2 * (stride as int), pow2(dm1)));
            assert(gather(s2, off as int, 2 * (stride as int), pow2(dm1)) == e_seq);

            // Child gathers pointwise at parent pair positions.
            assert forall|u: int| 0 <= u < pow2(dm1) implies
                #[trigger] nats(data@)[pos0(off as int, stride as int, u)] == e_seq[u]
                    && nats(data@)[pos1(off as int, stride as int, u)] == o_seq[u] by {
                assert(2 * u * (stride as int) == u * (2 * (stride as int)))
                    by (nonlinear_arith);

                assert(gather(s2, off as int, 2 * (stride as int), pow2(dm1))[u] == e_seq[u]);
                assert(gather(s2, off + stride as int, 2 * (stride as int), pow2(dm1))[u]
                    == o_seq[u]);
            }

            fwd_spec_len(evens(g0), tws, dm1, child as nat, 128);
            fwd_spec_len(odds(g0), tws, dm1, child as nat, 128);

            assert forall|j: int|
                0 <= j < data@.len()
                    && !in_class(j, off as int, stride as int, pow2(d as nat))
                    implies data@[j] == old(data)@[j] by {
                class_split(j, off as int, stride as int, d as nat);
            }
        }

        let mut t: usize = 0;

        while t < half
            invariant
                self.wf(),
                1 <= d <= self.log_n,
                stride >= 1,
                off < stride,
                dm1 == (d - 1) as nat,
                half as nat == pow2(dm1),
                pow2(d as nat) == 2 * pow2(dm1),
                (stride as nat) * pow2(d as nat) <= data@.len(),
                data@.len() == old(data)@.len(),
                data@.len() <= usize::MAX,
                t <= half,
                tws == nats(self.twiddles@),
                g0 == gather(nats(old(data)@), off as int, stride as int, pow2(d as nat)),
                e_seq.len() == pow2(dm1),
                o_seq.len() == pow2(dm1),
                forall|u: int| 0 <= u < t ==> ({
                    let lo = bfly_lo(e_seq[u], o_seq[u], xor(coset as nat, tws[u]), 128);
                    &&& #[trigger] nats(data@)[pos0(off as int, stride as int, u)] == lo
                    &&& nats(data@)[pos1(off as int, stride as int, u)] == xor(lo, o_seq[u])
                }),
                forall|u: int| t <= u < half ==> ({
                    &&& #[trigger] nats(data@)[pos0(off as int, stride as int, u)] == e_seq[u]
                    &&& nats(data@)[pos1(off as int, stride as int, u)] == o_seq[u]
                }),
                forall|j: int|
                    0 <= j < data@.len()
                        && !in_class(j, off as int, stride as int, pow2(d as nat))
                        ==> data@[j] == old(data)@[j],
            decreases half - t,
        {
            proof {
                idx_bound(off as int, stride as int, 2 * (t as int) + 1,
                    pow2(d as nat) as int);

                assert((pow2(d as nat) as int) * (stride as int)
                    == (stride as nat) * pow2(d as nat)) by (nonlinear_arith);

                assert(2 * (t as int) * (stride as int) + (stride as int)
                    == (2 * (t as int) + 1) * (stride as int)) by (nonlinear_arith);

                lemma_mul_inequality(1, stride as int, 2 * (t as int));
                lemma_mul_is_commutative(2 * (t as int), stride as int);

                assert(2 * (t as int) <= 2 * (t as int) * (stride as int));
                assert(off as int + 2 * (t as int) * (stride as int) + (stride as int)
                    < data@.len());

                pow2_mono(dm1, (self.log_n - 1) as nat);
            }

            let tw = add_flat(coset, self.twiddles[t]);
            let i0 = off + 2 * t * stride;
            let i1 = i0 + stride;

            let p = data[i0];
            let q = data[i1];
            let lo = add_flat(p, mul_flat(tw, q));
            let hi = add_flat(lo, q);

            proof {
                assert(i0 as int == pos0(off as int, stride as int, t as int));
                assert(i1 as int == pos1(off as int, stride as int, t as int));
                assert(nats(data@)[pos0(off as int, stride as int, t as int)]
                    == e_seq[t as int]);
                assert(nats(data@)[pos1(off as int, stride as int, t as int)]
                    == o_seq[t as int]);
                assert(p as nat == e_seq[t as int]);
                assert(q as nat == o_seq[t as int]);

                class_member(off as int, stride as int, pow2(d as nat), 2 * (t as int));
                class_member(off as int, stride as int, pow2(d as nat), 2 * (t as int) + 1);

                assert((2 * (t as int)) * (stride as int) == 2 * (t as int) * (stride as int))
                    by (nonlinear_arith);
                assert((2 * (t as int) + 1) * (stride as int)
                    == 2 * (t as int) * (stride as int) + (stride as int)) by (nonlinear_arith);

                assert forall|a: int, b: int| 0 <= a < b implies
                    off as int + #[trigger] (a * (stride as int))
                        < off as int + #[trigger] (b * (stride as int)) by {
                    lemma_mul_strict_inequality(a, b, stride as int);
                }

                assert(tws[t as int] == self.twiddles@[t as int] as nat);
                assert(lo as nat == bfly_lo(
                    e_seq[t as int], o_seq[t as int], xor(coset as nat, tws[t as int]), 128,
                ));
                assert(hi as nat == xor(lo as nat, o_seq[t as int]));
            }

            let ghost pre_raw = data@;
            let ghost pre = nats(data@);

            data[i0] = lo;
            data[i1] = hi;

            proof {
                assert(data@ == pre_raw.update(i0 as int, lo).update(i1 as int, hi));

                assert forall|u: int| 0 <= u < t + 1 implies ({
                    let lou = bfly_lo(e_seq[u], o_seq[u], xor(coset as nat, tws[u]), 128);
                    #[trigger] nats(data@)[pos0(off as int, stride as int, u)] == lou
                        && nats(data@)[pos1(off as int, stride as int, u)]
                            == xor(lou, o_seq[u])
                }) by {
                    if u < t as int {
                        lemma_mul_strict_inequality(2 * u, 2 * (t as int), stride as int);
                        lemma_mul_strict_inequality(2 * u + 1, 2 * (t as int), stride as int);
                        lemma_mul_strict_inequality(2 * u, 2 * (t as int) + 1, stride as int);
                        lemma_mul_strict_inequality(
                            2 * u + 1, 2 * (t as int) + 1, stride as int,
                        );

                        assert((2 * u + 1) * (stride as int)
                            == 2 * u * (stride as int) + (stride as int)) by (nonlinear_arith);

                        assert(pre[pos0(off as int, stride as int, u)]
                            == bfly_lo(e_seq[u], o_seq[u], xor(coset as nat, tws[u]), 128));
                        assert(nats(data@)[pos0(off as int, stride as int, u)]
                            == pre[pos0(off as int, stride as int, u)]);
                        assert(nats(data@)[pos1(off as int, stride as int, u)]
                            == pre[pos1(off as int, stride as int, u)]);
                    } else {
                        assert(u == t as int);
                        assert(nats(data@)[i1 as int] == hi as nat);
                        assert(nats(data@)[i0 as int] == lo as nat);
                    }
                }

                assert forall|u: int| t + 1 <= u < half implies ({
                    #[trigger] nats(data@)[pos0(off as int, stride as int, u)] == e_seq[u]
                        && nats(data@)[pos1(off as int, stride as int, u)] == o_seq[u]
                }) by {
                    lemma_mul_strict_inequality(2 * (t as int), 2 * u, stride as int);
                    lemma_mul_strict_inequality(2 * (t as int) + 1, 2 * u, stride as int);
                    lemma_mul_strict_inequality(2 * (t as int), 2 * u + 1, stride as int);
                    lemma_mul_strict_inequality(2 * (t as int) + 1, 2 * u + 1, stride as int);

                    assert((2 * u + 1) * (stride as int)
                        == 2 * u * (stride as int) + (stride as int)) by (nonlinear_arith);

                    idx_bound(off as int, stride as int, 2 * u + 1, pow2(d as nat) as int);

                    assert(pre[pos0(off as int, stride as int, u)] == e_seq[u]);
                    assert(nats(data@)[pos0(off as int, stride as int, u)]
                        == pre[pos0(off as int, stride as int, u)]);
                    assert(nats(data@)[pos1(off as int, stride as int, u)]
                        == pre[pos1(off as int, stride as int, u)]);
                }

                assert forall|j: int|
                    0 <= j < data@.len()
                        && !in_class(j, off as int, stride as int, pow2(d as nat))
                        implies data@[j] == old(data)@[j] by {
                    assert(in_class(i0 as int, off as int, stride as int, pow2(d as nat)));
                    assert(in_class(i1 as int, off as int, stride as int, pow2(d as nat)));
                    assert(data@[j] == pre_raw[j]);
                }
            }

            t += 1;
        }

        proof {
            let gf = gather(nats(data@), off as int, stride as int, pow2(d as nat));
            let want = fwd_spec(g0, tws, d as nat, coset as nat, 128);

            assert(g0.len() == pow2(d as nat));
            assert((d as nat - 1) as nat == dm1);
            assert(sigma(coset as nat, 128) == child as nat);
            assert(want == Seq::new(g0.len(), |i: int| {
                let u = i / 2;
                let lo = bfly_lo(e_seq[u], o_seq[u], xor(coset as nat, tws[u]), 128);

                if i % 2 == 0 { lo } else { xor(lo, o_seq[u]) }
            }));

            assert forall|i: int| 0 <= i < pow2(d as nat) implies gf[i] == want[i] by {
                lemma_fundamental_div_mod(i, 2);

                let u = i / 2;
                let lo = bfly_lo(e_seq[u], o_seq[u], xor(coset as nat, tws[u]), 128);

                assert(0 <= u < pow2(dm1));

                if i % 2 == 0 {
                    assert(i * (stride as int) == 2 * u * (stride as int))
                        by (nonlinear_arith)
                        requires i == 2 * u,
                    {}

                    assert(gf[i] == nats(data@)[pos0(off as int, stride as int, u)]);
                    assert(nats(data@)[pos0(off as int, stride as int, u)] == lo);
                } else {
                    assert(i * (stride as int) == 2 * u * (stride as int) + (stride as int))
                        by (nonlinear_arith)
                        requires i == 2 * u + 1,
                    {}

                    assert(gf[i] == nats(data@)[pos1(off as int, stride as int, u)]);
                    assert(nats(data@)[pos0(off as int, stride as int, u)] == lo);
                    assert(nats(data@)[pos1(off as int, stride as int, u)] == xor(lo, o_seq[u]));
                }
            }

            assert(gf =~= want);
        }
    }

    // inv_scalar, additive.rs:213-236; also the index shape
    // of inv_packed.
    fn inv_exec(&self, data: &mut Vec<u128>, off: usize, stride: usize, d: u32, coset: u128)
        requires
            self.wf(),
            d <= self.log_n,
            stride >= 1,
            off < stride,
            (stride as nat) * pow2(d as nat) <= old(data)@.len(),
            old(data)@.len() <= usize::MAX,
        ensures
            final(data)@.len() == old(data)@.len(),
            gather(nats(final(data)@), off as int, stride as int, pow2(d as nat))
                == inv_spec(
                    gather(nats(old(data)@), off as int, stride as int, pow2(d as nat)),
                    nats(self.twiddles@),
                    d as nat,
                    coset as nat,
                    128,
                ),
            forall|j: int|
                0 <= j < final(data)@.len()
                    && !in_class(j, off as int, stride as int, pow2(d as nat))
                    ==> final(data)@[j] == old(data)@[j],
        decreases d,
    {
        let ghost g0 = gather(nats(old(data)@), off as int, stride as int, pow2(d as nat));
        let ghost tws = nats(self.twiddles@);

        if d == 0 {
            proof {
                assert(pow2(0) == 1);
                assert(gather(nats(data@), off as int, stride as int, 1) =~= g0);
            }

            return;
        }

        let ghost dm1 = (d - 1) as nat;

        proof {
            lemma_u64_pow2_no_overflow(dm1);
            lemma_u64_shl_is_mul(1u64, (d - 1) as u64);
            pow2_bridge(dm1);
        }

        let half = (1u64 << (d - 1)) as usize;
        let child = add_flat(mul_flat(coset, coset), coset);

        let ghost q_seq = Seq::new(pow2(dm1), |u: int| xor(g0[2 * u], g0[2 * u + 1]));
        let ghost p_seq = Seq::new(
            pow2(dm1),
            |u: int| bfly_lo(
                g0[2 * u],
                xor(g0[2 * u], g0[2 * u + 1]),
                xor(coset as nat, tws[u]),
                128,
            ),
        );

        proof {
            assert(half as nat == pow2(dm1));
            assert(child as nat == sigma(coset as nat, 128));
            assert(pow2(d as nat) == 2 * pow2(dm1));
            gf_model::pow2_pos(dm1);

            assert((2 * (stride as nat)) * pow2(dm1) == (stride as nat) * pow2(d as nat))
                by (nonlinear_arith)
                requires pow2(d as nat) == 2 * pow2(dm1),
            {}

            assert((stride as nat) * 2 <= (stride as nat) * pow2(d as nat)) by (nonlinear_arith)
                requires pow2(d as nat) == 2 * pow2(dm1), pow2(dm1) >= 1,
            {}

            // Original pair values at parent positions.
            assert forall|u: int| 0 <= u < pow2(dm1) implies
                #[trigger] nats(data@)[pos0(off as int, stride as int, u)] == g0[2 * u]
                    && nats(data@)[pos1(off as int, stride as int, u)] == g0[2 * u + 1] by {
                assert((2 * u) * (stride as int) == 2 * u * (stride as int))
                    by (nonlinear_arith);
                assert((2 * u + 1) * (stride as int)
                    == 2 * u * (stride as int) + (stride as int)) by (nonlinear_arith);

                assert(data@ == old(data)@);
                assert(g0[2 * u]
                    == nats(old(data)@)[off as int + (2 * u) * (stride as int)]);
                assert(g0[2 * u + 1]
                    == nats(old(data)@)[off as int + (2 * u + 1) * (stride as int)]);
            }
        }

        let mut t: usize = 0;

        while t < half
            invariant
                self.wf(),
                1 <= d <= self.log_n,
                stride >= 1,
                off < stride,
                dm1 == (d - 1) as nat,
                half as nat == pow2(dm1),
                pow2(d as nat) == 2 * pow2(dm1),
                (stride as nat) * pow2(d as nat) <= data@.len(),
                data@.len() == old(data)@.len(),
                data@.len() <= usize::MAX,
                t <= half,
                tws == nats(self.twiddles@),
                g0 == gather(nats(old(data)@), off as int, stride as int, pow2(d as nat)),
                q_seq.len() == pow2(dm1),
                p_seq.len() == pow2(dm1),
                q_seq == Seq::new(pow2(dm1), |u: int| xor(g0[2 * u], g0[2 * u + 1])),
                p_seq == Seq::new(
                    pow2(dm1),
                    |u: int| bfly_lo(
                        g0[2 * u],
                        xor(g0[2 * u], g0[2 * u + 1]),
                        xor(coset as nat, tws[u]),
                        128,
                    ),
                ),
                forall|u: int| 0 <= u < t ==> ({
                    &&& #[trigger] nats(data@)[pos0(off as int, stride as int, u)] == p_seq[u]
                    &&& nats(data@)[pos1(off as int, stride as int, u)] == q_seq[u]
                }),
                forall|u: int| t <= u < half ==> ({
                    &&& #[trigger] nats(data@)[pos0(off as int, stride as int, u)] == g0[2 * u]
                    &&& nats(data@)[pos1(off as int, stride as int, u)] == g0[2 * u + 1]
                }),
                forall|j: int|
                    0 <= j < data@.len()
                        && !in_class(j, off as int, stride as int, pow2(d as nat))
                        ==> data@[j] == old(data)@[j],
            decreases half - t,
        {
            proof {
                idx_bound(off as int, stride as int, 2 * (t as int) + 1,
                    pow2(d as nat) as int);

                assert((pow2(d as nat) as int) * (stride as int)
                    == (stride as nat) * pow2(d as nat)) by (nonlinear_arith);

                assert(2 * (t as int) * (stride as int) + (stride as int)
                    == (2 * (t as int) + 1) * (stride as int)) by (nonlinear_arith);

                lemma_mul_inequality(1, stride as int, 2 * (t as int));
                lemma_mul_is_commutative(2 * (t as int), stride as int);

                assert(2 * (t as int) <= 2 * (t as int) * (stride as int));
                assert(off as int + 2 * (t as int) * (stride as int) + (stride as int)
                    < data@.len());

                pow2_mono(dm1, (self.log_n - 1) as nat);
            }

            let tw = add_flat(coset, self.twiddles[t]);
            let i0 = off + 2 * t * stride;
            let i1 = i0 + stride;

            let o0 = data[i0];
            let o1 = data[i1];
            let qv = add_flat(o0, o1);
            let pv = add_flat(o0, mul_flat(tw, qv));

            proof {
                assert(i0 as int == pos0(off as int, stride as int, t as int));
                assert(i1 as int == pos1(off as int, stride as int, t as int));
                assert(nats(data@)[pos0(off as int, stride as int, t as int)]
                    == g0[2 * (t as int)]);
                assert(nats(data@)[pos1(off as int, stride as int, t as int)]
                    == g0[2 * (t as int) + 1]);
                assert(o0 as nat == g0[2 * (t as int)]);
                assert(o1 as nat == g0[2 * (t as int) + 1]);
                assert(pv as nat == p_seq[t as int]);
                assert(qv as nat == q_seq[t as int]);

                class_member(off as int, stride as int, pow2(d as nat), 2 * (t as int));
                class_member(off as int, stride as int, pow2(d as nat), 2 * (t as int) + 1);

                assert((2 * (t as int)) * (stride as int) == 2 * (t as int) * (stride as int))
                    by (nonlinear_arith);
                assert((2 * (t as int) + 1) * (stride as int)
                    == 2 * (t as int) * (stride as int) + (stride as int)) by (nonlinear_arith);

                assert forall|a: int, b: int| 0 <= a < b implies
                    off as int + #[trigger] (a * (stride as int))
                        < off as int + #[trigger] (b * (stride as int)) by {
                    lemma_mul_strict_inequality(a, b, stride as int);
                }

                assert(tws[t as int] == self.twiddles@[t as int] as nat);
            }

            let ghost pre_raw = data@;
            let ghost pre = nats(data@);

            data[i0] = pv;
            data[i1] = qv;

            proof {
                assert(data@ == pre_raw.update(i0 as int, pv).update(i1 as int, qv));

                assert forall|u: int| 0 <= u < t + 1 implies ({
                    #[trigger] nats(data@)[pos0(off as int, stride as int, u)] == p_seq[u]
                        && nats(data@)[pos1(off as int, stride as int, u)] == q_seq[u]
                }) by {
                    if u < t as int {
                        lemma_mul_strict_inequality(2 * u, 2 * (t as int), stride as int);
                        lemma_mul_strict_inequality(2 * u + 1, 2 * (t as int), stride as int);
                        lemma_mul_strict_inequality(2 * u, 2 * (t as int) + 1, stride as int);
                        lemma_mul_strict_inequality(
                            2 * u + 1, 2 * (t as int) + 1, stride as int,
                        );

                        assert((2 * u + 1) * (stride as int)
                            == 2 * u * (stride as int) + (stride as int)) by (nonlinear_arith);

                        assert(pre[pos0(off as int, stride as int, u)] == p_seq[u]);
                        assert(nats(data@)[pos0(off as int, stride as int, u)]
                            == pre[pos0(off as int, stride as int, u)]);
                        assert(nats(data@)[pos1(off as int, stride as int, u)]
                            == pre[pos1(off as int, stride as int, u)]);
                    } else {
                        assert(u == t as int);
                        assert(nats(data@)[i1 as int] == qv as nat);
                        assert(nats(data@)[i0 as int] == pv as nat);
                    }
                }

                // Restate in the invariant's exact shape:
                // the end-of-body check matches it verbatim.
                assert(forall|u: int| 0 <= u < t + 1 ==> ({
                    &&& #[trigger] nats(data@)[pos0(off as int, stride as int, u)] == p_seq[u]
                    &&& nats(data@)[pos1(off as int, stride as int, u)] == q_seq[u]
                }));

                assert forall|u: int| t + 1 <= u < half implies ({
                    #[trigger] nats(data@)[pos0(off as int, stride as int, u)] == g0[2 * u]
                        && nats(data@)[pos1(off as int, stride as int, u)] == g0[2 * u + 1]
                }) by {
                    lemma_mul_strict_inequality(2 * (t as int), 2 * u, stride as int);
                    lemma_mul_strict_inequality(2 * (t as int) + 1, 2 * u, stride as int);
                    lemma_mul_strict_inequality(2 * (t as int), 2 * u + 1, stride as int);
                    lemma_mul_strict_inequality(2 * (t as int) + 1, 2 * u + 1, stride as int);

                    assert((2 * u + 1) * (stride as int)
                        == 2 * u * (stride as int) + (stride as int)) by (nonlinear_arith);

                    idx_bound(off as int, stride as int, 2 * u + 1, pow2(d as nat) as int);

                    assert(pre[pos0(off as int, stride as int, u)] == g0[2 * u]);
                    assert(pre[pos1(off as int, stride as int, u)] == g0[2 * u + 1]);
                    assert(nats(data@)[pos0(off as int, stride as int, u)]
                        == pre[pos0(off as int, stride as int, u)]);
                    assert(nats(data@)[pos1(off as int, stride as int, u)]
                        == pre[pos1(off as int, stride as int, u)]);
                }

                assert forall|j: int|
                    0 <= j < data@.len()
                        && !in_class(j, off as int, stride as int, pow2(d as nat))
                        implies data@[j] == old(data)@[j] by {
                    assert(in_class(i0 as int, off as int, stride as int, pow2(d as nat)));
                    assert(in_class(i1 as int, off as int, stride as int, pow2(d as nat)));
                    assert(data@[j] == pre_raw[j]);
                }
            }

            t += 1;
        }

        let ghost s1 = nats(data@);

        proof {
            gather_split(s1, off as int, stride as int, d as nat);

            // The even child class now holds p_seq, the odd q_seq.
            assert forall|u: int| 0 <= u < pow2(dm1) implies
                #[trigger] gather(s1, off as int, 2 * (stride as int), pow2(dm1))[u]
                    == p_seq[u] by {
                assert(2 * u * (stride as int) == u * (2 * (stride as int)))
                    by (nonlinear_arith);

                assert(nats(data@)[pos0(off as int, stride as int, u)] == p_seq[u]);
            }

            assert forall|u: int| 0 <= u < pow2(dm1) implies
                #[trigger] gather(s1, off + stride as int, 2 * (stride as int), pow2(dm1))[u]
                    == q_seq[u] by {
                assert(2 * u * (stride as int) == u * (2 * (stride as int)))
                    by (nonlinear_arith);

                assert(nats(data@)[pos0(off as int, stride as int, u)] == p_seq[u]);
                assert(nats(data@)[pos1(off as int, stride as int, u)] == q_seq[u]);
            }

            assert(gather(s1, off as int, 2 * (stride as int), pow2(dm1)) =~= p_seq);
            assert(gather(s1, off + stride as int, 2 * (stride as int), pow2(dm1)) =~= q_seq);
        }

        self.inv_exec(data, off, stride * 2, d - 1, child);

        let ghost s2 = nats(data@);

        proof {
            assert(gather(s2, off as int, 2 * (stride as int), pow2(dm1))
                == inv_spec(p_seq, tws, dm1, child as nat, 128));

            // Call 1 left the odd child class untouched.
            assert forall|u: int| 0 <= u < pow2(dm1) implies
                #[trigger] gather(s2, off + stride as int, 2 * (stride as int), pow2(dm1))[u]
                    == gather(s1, off + stride as int, 2 * (stride as int), pow2(dm1))[u] by {
                let j = off + stride as int + u * (2 * (stride as int));

                class_member(off + stride as int, 2 * (stride as int), pow2(dm1), u);
                idx_bound(off + stride as int, 2 * (stride as int), u, pow2(dm1) as int);

                assert(pow2(dm1) as int * (2 * (stride as int))
                    == (stride as nat) * pow2(d as nat)) by (nonlinear_arith)
                    requires pow2(d as nat) == 2 * pow2(dm1),
                {}

                assert(!in_class(j, off as int, 2 * (stride as int), pow2(dm1)));
            }

            assert(gather(s2, off + stride as int, 2 * (stride as int), pow2(dm1)) =~= q_seq);
        }

        self.inv_exec(data, off + stride, stride * 2, d - 1, child);

        let ghost s3 = nats(data@);

        proof {
            assert(gather(s3, off + stride as int, 2 * (stride as int), pow2(dm1))
                == inv_spec(q_seq, tws, dm1, child as nat, 128));

            // Call 2 left the even child class untouched.
            assert forall|u: int| 0 <= u < pow2(dm1) implies
                #[trigger] gather(s3, off as int, 2 * (stride as int), pow2(dm1))[u]
                    == gather(s2, off as int, 2 * (stride as int), pow2(dm1))[u] by {
                let j = off as int + u * (2 * (stride as int));

                class_member(off as int, 2 * (stride as int), pow2(dm1), u);
                idx_bound(off as int, 2 * (stride as int), u, pow2(dm1) as int);

                assert(pow2(dm1) as int * (2 * (stride as int))
                    == (stride as nat) * pow2(d as nat)) by (nonlinear_arith)
                    requires pow2(d as nat) == 2 * pow2(dm1),
                {}

                assert(!in_class(j, off + stride as int, 2 * (stride as int), pow2(dm1)));
            }

            assert(gather(s3, off as int, 2 * (stride as int), pow2(dm1))
                =~= gather(s2, off as int, 2 * (stride as int), pow2(dm1)));

            let ie = inv_spec(p_seq, tws, dm1, child as nat, 128);
            let io = inv_spec(q_seq, tws, dm1, child as nat, 128);
            let gf = gather(s3, off as int, stride as int, pow2(d as nat));
            let want = inv_spec(g0, tws, d as nat, coset as nat, 128);

            // inv_spec's internal pair seqs are p_seq / q_seq.
            assert(Seq::new(g0.len() / 2, |u: int| xor(g0[2 * u], g0[2 * u + 1])) =~= q_seq);
            assert(Seq::new(
                g0.len() / 2,
                |u: int| bfly_lo(
                    g0[2 * u],
                    xor(g0[2 * u], g0[2 * u + 1]),
                    xor(coset as nat, tws[u]),
                    128,
                ),
            ) =~= p_seq);

            assert(want == interleave(ie, io));

            gather_split(s3, off as int, stride as int, d as nat);

            assert forall|i: int| 0 <= i < pow2(d as nat) implies gf[i] == want[i] by {
                lemma_fundamental_div_mod(i, 2);

                let u = i / 2;

                if i % 2 == 0 {
                    assert(i * (stride as int) == u * (2 * (stride as int)))
                        by (nonlinear_arith)
                        requires i == 2 * u,
                    {}

                    assert(gf[i] == gather(s3, off as int, 2 * (stride as int), pow2(dm1))[u]);
                } else {
                    assert(i * (stride as int)
                        == u * (2 * (stride as int)) + (stride as int)) by (nonlinear_arith)
                        requires i == 2 * u + 1,
                    {}

                    assert(gf[i]
                        == gather(s3, off + stride as int, 2 * (stride as int), pow2(dm1))[u]);
                }
            }

            assert(gf =~= want);

            assert forall|j: int|
                0 <= j < data@.len()
                    && !in_class(j, off as int, stride as int, pow2(d as nat))
                    implies data@[j] == old(data)@[j] by {
                class_split(j, off as int, stride as int, d as nat);
            }
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

        proof {
            assert((1 as nat) * pow2(self.log_n as nat) == pow2(self.log_n as nat))
                by (nonlinear_arith);
        }

        self.fwd_exec(data, 0, 1, self.log_n, offset);

        proof {
            gather_ident(nats(old(data)@), pow2(self.log_n as nat));
            gather_ident(nats(data@), pow2(self.log_n as nat));
        }

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

        proof {
            assert((1 as nat) * pow2(self.log_n as nat) == pow2(self.log_n as nat))
                by (nonlinear_arith);
        }

        self.inv_exec(data, 0, 1, self.log_n, offset);

        proof {
            gather_ident(nats(old(data)@), pow2(self.log_n as nat));
            gather_ident(nats(data@), pow2(self.log_n as nat));
        }

        Ok(())
    }
}

fn main() {}

}
