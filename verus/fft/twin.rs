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
    bfly_lo, evens, fwd_spec, fwd_spec_len, interleave, inv_spec, inv_spec_len, odds, sigma,
    sigma_pow, sigma_pow_step,
};
#[cfg(verus_keep_ghost)]
use super::twiddles::{
    and_dec_is_sub, low_bits_zero_mod, nats, pow2_bridge, tw_sum, tw_sum_clear_bit, tw_sum_double,
    tw_sum_lt, tw_sum_split, xor128_reflect,
};

#[cfg(verus_keep_ghost)]
use gf_model::{gf_mul_comm, pow2, pow2_mono, xor, xor_assoc, xor_comm, xor_zero};
#[cfg(verus_keep_ghost)]
use vstd::arithmetic::div_mod::lemma_fundamental_div_mod;
#[cfg(verus_keep_ghost)]
use vstd::arithmetic::mul::lemma_mul_inequality;
#[cfg(verus_keep_ghost)]
use vstd::bits::{lemma_u64_pow2_no_overflow, lemma_u64_shl_is_mul, lemma_u64_shr_is_div};
#[cfg(verus_keep_ghost)]
use vstd::std_specs::bits::axiom_u64_trailing_zeros;

verus! {

// ============================================================
// Constructor twin: new(), additive.rs, from the lift chain on.
// The solve_quadratic loop producing `lift` is checked at build time.
// ============================================================

pub const LOW_LOG: u32 = 10;

pub struct FftTwin {
    pub log_n: u32,
    pub low: Vec<u128>,
    pub lift: Vec<u128>,
    pub twiddles: Ghost<Seq<u128>>,
}

impl FftTwin {
    pub open spec fn low_log(self) -> nat {
        if self.log_n - 1 < LOW_LOG {
            (self.log_n - 1) as nat
        } else {
            LOW_LOG as nat
        }
    }

    pub open spec fn wf(self) -> bool {
        &&& 1 <= self.log_n < 64
        &&& self.log_n as nat <= 128
        &&& self.twiddles@.len() == pow2((self.log_n - 1) as nat)
        &&& self.lift@.len() == self.log_n - 1
        &&& self.low@.len() == pow2(self.low_log())
        &&& forall|t: int| 0 <= t < self.twiddles@.len()
            ==> #[trigger] self.twiddles@[t] as nat == tw_sum(nats(self.lift@), t as nat, 0)
        &&& forall|u: int| 0 <= u < self.low@.len()
            ==> #[trigger] self.low@[u] as nat == tw_sum(nats(self.lift@), u as nat, 0)
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
        let low_log: u32 = if log_n - 1 < LOW_LOG {
            log_n - 1
        } else {
            LOW_LOG
        };

        proof {
            lemma_u64_pow2_no_overflow(low_log as nat);
            lemma_u64_shl_is_mul(1u64, low_log as u64);
            pow2_bridge(low_log as nat);
        }

        let len = (1u64 << low_log) as usize;

        assert(len as nat == pow2(low_log as nat));

        let mut low: Vec<u128> = Vec::with_capacity(len);
        low.push(0);

        proof {
            assert(pow2(0) == 1);
            assert(tw_sum(nats(lift@), 0, 0) == 0);
        }

        let mut j: usize = 0;
        while j < low_log as usize
            invariant
                j <= low_log,
                low_log <= log_n - 1,
                lift@.len() == log_n - 1,
                1 <= log_n < 64,
                low@.len() == pow2(j as nat),
                forall|u: int| 0 <= u < low@.len()
                    ==> #[trigger] low@[u] as nat == tw_sum(nats(lift@), u as nat, 0),
            decreases low_log - j,
        {
            let filled = low.len();
            let l = lift[j];

            let mut t: usize = 0;
            while t < filled
                invariant
                    t <= filled,
                    filled as nat == pow2(j as nat),
                    j < low_log,
                    low_log <= log_n - 1,
                    lift@.len() == log_n - 1,
                    1 <= log_n < 64,
                    l == lift@[j as int],
                    low@.len() == filled + t,
                    forall|u: int| 0 <= u < low@.len()
                        ==> #[trigger] low@[u] as nat == tw_sum(nats(lift@), u as nat, 0),
                decreases filled - t,
            {
                let tw = low[t];

                proof {
                    xor128_reflect(tw, l);
                    tw_sum_double(nats(lift@), j as nat, t as nat);
                    xor_comm(l as nat, tw as nat);

                    assert(nats(lift@)[j as int] == l as nat);
                }

                low.push(tw ^ l);

                t += 1;
            }

            proof {
                assert(pow2((j + 1) as nat) == 2 * pow2(j as nat));
            }

            j += 1;
        }

        let ghost tws = Seq::new(
            pow2((log_n - 1) as nat),
            |t: int| tw_sum(nats(lift@), t as nat, 0) as u128,
        );

        proof {
            assert(pow2(128) == 0x1_0000_0000_0000_0000_0000_0000_0000_0000) by (compute);

            assert forall|i: int| 0 <= i < nats(lift@).len()
                implies #[trigger] nats(lift@)[i] < pow2(128) by {}

            assert forall|t: int| 0 <= t < tws.len()
                implies #[trigger] tws[t] as nat == tw_sum(nats(lift@), t as nat, 0) by {
                tw_sum_lt(nats(lift@), t as nat, 0);
            }
        }

        FftTwin { log_n, low, lift, twiddles: Ghost(tws) }
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

pub proof fn gather_ident(s: Seq<nat>, n: nat)
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

pub proof fn rows_to_inv_rows(
    src: Seq<u128>,
    dst: Seq<u128>,
    tws: Seq<u128>,
    s: int,
    nblocks: int,
    coset: nat,
)
    requires
        s == 1,
        forall|bb: int| 0 <= bb < nblocks ==> {
            &&& #[trigger] dst[2 * bb] as nat == bfly_lo(
                src[2 * bb] as nat,
                xor(src[2 * bb] as nat, src[2 * bb + 1] as nat),
                xor(coset, tws[bb] as nat),
                128,
            )
            &&& dst[2 * bb + 1] as nat == xor(src[2 * bb] as nat, src[2 * bb + 1] as nat)
        },
    ensures
        inv_rows(src, dst, tws, s, nblocks, coset),
{
    assert forall|b: int, r: int| 0 <= b < nblocks && 0 <= r < s implies {
        &&& #[trigger] dst[b * (2 * s) + r] as nat == bfly_lo(
            src[b * (2 * s) + r] as nat,
            xor(src[b * (2 * s) + r] as nat, src[b * (2 * s) + s + r] as nat),
            xor(coset, tws[b] as nat),
            128,
        )
        &&& dst[b * (2 * s) + s + r] as nat == xor(
            src[b * (2 * s) + r] as nat,
            src[b * (2 * s) + s + r] as nat,
        )
    } by {
        assert(r == 0);
        assert(b * (2 * s) + r == 2 * b) by (nonlinear_arith)
            requires r == 0, s == 1;
        assert(b * (2 * s) + s + r == 2 * b + 1) by (nonlinear_arith)
            requires r == 0, s == 1;
        assert(dst[2 * b] as nat == bfly_lo(
            src[2 * b] as nat,
            xor(src[2 * b] as nat, src[2 * b + 1] as nat),
            xor(coset, tws[b] as nat),
            128,
        ));
        assert(dst[2 * b + 1] as nat == xor(src[2 * b] as nat, src[2 * b + 1] as nat));
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

pub proof fn fwd_rows_bridge(
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

pub proof fn inv_rows_bridge(
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
pub proof fn fwd_pass_step(
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
pub proof fn inv_pass_step(
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

    // CantorBasis::beta_sum, cantor.rs, on lift = betas[1..].
    pub fn sum_lift(&self, bits: u64, base: usize) -> (r: u128)
        requires
            self.wf(),
            base <= self.lift@.len(),
            (bits as nat) < pow2((self.lift@.len() - base) as nat),
        ensures r as nat == tw_sum(nats(self.lift@), bits as nat, base as nat),
    {
        let ghost lift = nats(self.lift@);
        let ghost n = self.lift@.len();

        let mut acc: u128 = 0;
        let mut rest: u64 = bits;

        proof {
            xor_zero(tw_sum(lift, bits as nat, base as nat));
        }

        while rest != 0
            invariant
                lift == nats(self.lift@),
                n == self.lift@.len(),
                n <= 64,
                base <= n,
                (bits as nat) < pow2((n - base) as nat),
                rest as nat <= bits as nat,
                xor(acc as nat, tw_sum(lift, rest as nat, base as nat))
                    == tw_sum(lift, bits as nat, base as nat),
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
                tw_sum_clear_bit(lift, rest as nat, jn, base as nat);

                if jn >= (n - base) as nat {
                    pow2_mono((n - base) as nat, jn);

                    assert(pow2(jn) <= rest as nat);
                    assert(false);
                }
            }

            let l = self.lift[base + j];

            proof {
                xor128_reflect(acc, l);

                assert(lift[(base + j) as int] == l as nat);
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

                xor_assoc(acc_old, lift[(base + j) as int], tw_sum(lift, rest as nat, base as nat));
            }
        }

        proof {
            assert(tw_sum(lift, 0, base as nat) == 0);

            xor_zero(acc as nat);
        }

        acc
    }

    // Twiddles::blocks at b0 = 0, additive.rs: whole-array pass
    // at stride s; block b (width 2s) twiddled by xor(coset, tws[b]).
    pub fn pass_fwd_exec(&self, data: &mut Vec<u128>, coset: u128, s: usize, nblocks: usize)
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
        let len = self.low.len();
        let low_log: u32 = if self.log_n - 1 < LOW_LOG {
            self.log_n - 1
        } else {
            LOW_LOG
        };

        let ghost lift = nats(self.lift@);

        proof {
            gf_model::pow2_pos(low_log as nat);

            assert(low_log as nat == self.low_log());
            assert(len as nat == pow2(low_log as nat));
        }

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
                lift == nats(self.lift@),
                len == self.low@.len(),
                len as nat == pow2(low_log as nat),
                low_log as nat == self.low_log(),
                b % len == 0 || b == nblocks,
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
            let start = b;
            let take = if len < nblocks - b {
                len
            } else {
                nblocks - b
            };
            let end = b + take;
            let c: u64 = (b as u64) >> (low_log as u64);

            proof {
                gf_model::pow2_pos(low_log as nat);
                lemma_u64_shr_is_div(b as u64, low_log as u64);
                pow2_bridge(low_log as nat);
                lemma_fundamental_div_mod(b as int, len as int);

                assert(c as nat == b as nat / pow2(low_log as nat));
                assert(b % len == 0);
                assert(b as nat == c as nat * pow2(low_log as nat)) by (nonlinear_arith)
                    requires
                        b == len * (b / len) + b % len,
                        b % len == 0,
                        c as nat == b as nat / pow2(low_log as nat),
                        len as nat == pow2(low_log as nat);

                gf_model::pow2_add(low_log as nat, (self.lift@.len() - low_log) as nat);

                assert(b < pow2((self.log_n - 1) as nat));
                assert(low_log + (self.lift@.len() - low_log) == self.log_n - 1);
                assert((c as nat) < pow2((self.lift@.len() - low_log) as nat)) by (nonlinear_arith)
                    requires
                        b as nat == c as nat * pow2(low_log as nat),
                        b < pow2((self.log_n - 1) as nat),
                        pow2((self.log_n - 1) as nat) == pow2(low_log as nat) * pow2(
                            (self.lift@.len() - low_log) as nat,
                        ),
                        pow2(low_log as nat) >= 1;
            }

            let high = self.sum_lift(c, low_log as usize);
            let ch = add_flat(coset, high);

            while b < end
                invariant
                    self.wf(),
                    s >= 1,
                    s <= usize::MAX / 2,
                    data@.len() == old(data)@.len(),
                    nblocks * (2 * s) == data@.len(),
                    nblocks <= self.twiddles@.len(),
                    start <= b <= end,
                    end == start + take,
                    take <= len,
                    end <= nblocks,
                    base == b * (2 * s),
                    data@.len() <= usize::MAX,
                    lift == nats(self.lift@),
                    len == self.low@.len(),
                    len as nat == pow2(low_log as nat),
                    low_log as nat == self.low_log(),
                    start as nat == c as nat * pow2(low_log as nat),
                    ch as nat == xor(coset as nat, tw_sum(lift, c as nat, low_log as nat)),
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
                decreases end - b,
            {
                proof {
                    lemma_mul_inequality((b + 1) as int, nblocks as int, (2 * s) as int);

                    assert((b + 1) * (2 * s) == base + 2 * s) by (nonlinear_arith)
                        requires base == b * (2 * s);
                }

                let tw = add_flat(ch, self.low[b - start]);

                proof {
                    let i = (b - start) as nat;
                    let hc = tw_sum(lift, c as nat, low_log as nat);
                    let li = tw_sum(lift, i, 0);

                    tw_sum_split(lift, c as nat, i, low_log as nat, 0);

                    assert(b as nat == c as nat * pow2(low_log as nat) + i);
                    assert(self.twiddles@[b as int] as nat == xor(li, hc));
                    assert(self.low@[i as int] as nat == li);

                    xor_assoc(coset as nat, hc, li);
                    xor_comm(hc, li);

                    assert(tw as nat == xor(coset as nat, self.twiddles@[b as int] as nat));
                }

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

            proof {
                assert(b == start + take);

                if take == len {
                    vstd::arithmetic::div_mod::lemma_mod_multiples_basic(c as int + 1, len as int);

                    assert(b as int == (c as int + 1) * len as int) by (nonlinear_arith)
                        requires
                            b == start + take,
                            take == len,
                            start as nat == c as nat * pow2(low_log as nat),
                            len as nat == pow2(low_log as nat);
                }
            }
        }

        proof {
            assert(b == nblocks);
            assert(fwd_rows(
                old(data)@,
                data@,
                self.twiddles@,
                s as int,
                nblocks as int,
                coset as nat,
            ));
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
            lemma_u64_pow2_no_overflow(n as nat);
            pow2_bridge(n as nat);

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

    // Twiddles::blocks at b0 = 0, additive.rs: inverse whole-array
    // pass at stride s; block b twiddled by xor(coset, tws[b]).
    pub fn pass_inv_exec(&self, data: &mut Vec<u128>, coset: u128, s: usize, nblocks: usize)
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
        let len = self.low.len();
        let low_log: u32 = if self.log_n - 1 < LOW_LOG {
            self.log_n - 1
        } else {
            LOW_LOG
        };

        let ghost lift = nats(self.lift@);

        proof {
            gf_model::pow2_pos(low_log as nat);

            assert(low_log as nat == self.low_log());
            assert(len as nat == pow2(low_log as nat));
        }

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
                lift == nats(self.lift@),
                len == self.low@.len(),
                len as nat == pow2(low_log as nat),
                low_log as nat == self.low_log(),
                b % len == 0 || b == nblocks,
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
            let start = b;
            let take = if len < nblocks - b {
                len
            } else {
                nblocks - b
            };
            let end = b + take;
            let c: u64 = (b as u64) >> (low_log as u64);

            proof {
                gf_model::pow2_pos(low_log as nat);
                lemma_u64_shr_is_div(b as u64, low_log as u64);
                pow2_bridge(low_log as nat);
                lemma_fundamental_div_mod(b as int, len as int);

                assert(c as nat == b as nat / pow2(low_log as nat));
                assert(b % len == 0);
                assert(b as nat == c as nat * pow2(low_log as nat)) by (nonlinear_arith)
                    requires
                        b == len * (b / len) + b % len,
                        b % len == 0,
                        c as nat == b as nat / pow2(low_log as nat),
                        len as nat == pow2(low_log as nat);

                gf_model::pow2_add(low_log as nat, (self.lift@.len() - low_log) as nat);

                assert(b < pow2((self.log_n - 1) as nat));
                assert(low_log + (self.lift@.len() - low_log) == self.log_n - 1);
                assert((c as nat) < pow2((self.lift@.len() - low_log) as nat)) by (nonlinear_arith)
                    requires
                        b as nat == c as nat * pow2(low_log as nat),
                        b < pow2((self.log_n - 1) as nat),
                        pow2((self.log_n - 1) as nat) == pow2(low_log as nat) * pow2(
                            (self.lift@.len() - low_log) as nat,
                        ),
                        pow2(low_log as nat) >= 1;
            }

            let high = self.sum_lift(c, low_log as usize);
            let ch = add_flat(coset, high);

            while b < end
                invariant
                    self.wf(),
                    s >= 1,
                    s <= usize::MAX / 2,
                    data@.len() == old(data)@.len(),
                    nblocks * (2 * s) == data@.len(),
                    nblocks <= self.twiddles@.len(),
                    start <= b <= end,
                    end == start + take,
                    take <= len,
                    end <= nblocks,
                    base == b * (2 * s),
                    data@.len() <= usize::MAX,
                    lift == nats(self.lift@),
                    len == self.low@.len(),
                    len as nat == pow2(low_log as nat),
                    low_log as nat == self.low_log(),
                    start as nat == c as nat * pow2(low_log as nat),
                    ch as nat == xor(coset as nat, tw_sum(lift, c as nat, low_log as nat)),
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
                decreases end - b,
            {
                proof {
                    lemma_mul_inequality((b + 1) as int, nblocks as int, (2 * s) as int);

                    assert((b + 1) * (2 * s) == base + 2 * s) by (nonlinear_arith)
                        requires base == b * (2 * s);
                }

                let tw = add_flat(ch, self.low[b - start]);

                proof {
                    let i = (b - start) as nat;
                    let hc = tw_sum(lift, c as nat, low_log as nat);
                    let li = tw_sum(lift, i, 0);

                    tw_sum_split(lift, c as nat, i, low_log as nat, 0);

                    assert(b as nat == c as nat * pow2(low_log as nat) + i);
                    assert(self.twiddles@[b as int] as nat == xor(li, hc));
                    assert(self.low@[i as int] as nat == li);

                    xor_assoc(coset as nat, hc, li);
                    xor_comm(hc, li);

                    assert(tw as nat == xor(coset as nat, self.twiddles@[b as int] as nat));
                }

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

            proof {
                assert(b == start + take);

                if take == len {
                    vstd::arithmetic::div_mod::lemma_mod_multiples_basic(c as int + 1, len as int);

                    assert(b as int == (c as int + 1) * len as int) by (nonlinear_arith)
                        requires
                            b == start + take,
                            take == len,
                            start as nat == c as nat * pow2(low_log as nat),
                            len as nat == pow2(low_log as nat);
                }
            }
        }

        proof {
            assert(b == nblocks);
            assert(inv_rows(
                old(data)@,
                data@,
                self.twiddles@,
                s as int,
                nblocks as int,
                coset as nat,
            ));
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

        let ghost fin = inv_spec(
            nats(old(data)@),
            nats(self.twiddles@),
            n as nat,
            offset as nat,
            128,
        );

        proof {
            lemma_u64_pow2_no_overflow(n as nat);
            pow2_bridge(n as nat);

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

}
