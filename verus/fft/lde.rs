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
use super::twin::{FftTwin, LOW_LOG};

use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
use super::bridge::gf_model;
#[cfg(verus_keep_ghost)]
use super::spec::{
    bfly_lo, fwd_spec, inv_spec, inv_spec_len, sigma, sigma_pow, sigma_pow_step, sigma_zero,
};
#[cfg(verus_keep_ghost)]
use super::twiddles::{nats, pow2_bridge, tw_sum, tw_sum_split};
#[cfg(verus_keep_ghost)]
use super::twin::{
    fwd_pass_step, fwd_rows, fwd_rows_bridge, gather, gather_ident, inv_pass_step, inv_rows,
    inv_rows_bridge, rows_to_inv_rows,
};

#[cfg(verus_keep_ghost)]
use gf_model::{gf_mul_comm, pow2, pow2_mono, xor, xor_assoc, xor_comm, xor_zero};
#[cfg(verus_keep_ghost)]
use vstd::arithmetic::div_mod::{
    lemma_fundamental_div_mod, lemma_fundamental_div_mod_converse_div,
    lemma_fundamental_div_mod_converse_mod,
};
#[cfg(verus_keep_ghost)]
use vstd::bits::{lemma_u64_pow2_no_overflow, lemma_u64_shl_is_mul, lemma_u64_shr_is_div};

verus! {

// ============================================================
// LdePlan twin (src/fft/additive.rs)
// ============================================================

pub const LANE_TILE: usize = 16;

pub open spec fn slot(i: int, row0: int, stride: int, count: int) -> bool {
    row0 <= i && (i - row0) % stride == 0 && (i - row0) / stride < count
}

pub open spec fn flushed_rows(
    src: Seq<u128>,
    out: Seq<u128>,
    tws: Seq<u128>,
    coset: nat,
    row0: int,
    u0: int,
) -> bool {
    forall|bb: int| 0 <= 2 * bb < u0 ==> {
        &&& #[trigger] out[row0 + 2 * bb] as nat == bfly_lo(
            src[bb * 2] as nat,
            src[bb * 2 + 1] as nat,
            xor(coset, tws[bb] as nat),
            128,
        )
        &&& out[row0 + 2 * bb + 1] as nat == xor(out[row0 + 2 * bb] as nat, src[bb * 2 + 1] as nat)
    }
}

pub open spec fn tile_rows(
    src: Seq<u128>,
    points: Seq<u128>,
    tws: Seq<u128>,
    coset: nat,
    u0: int,
    filled: int,
) -> bool {
    forall|bb: int| u0 <= 2 * bb < u0 + filled ==> {
        &&& #[trigger] points[2 * bb - u0] as nat == bfly_lo(
            src[bb * 2] as nat,
            src[bb * 2 + 1] as nat,
            xor(coset, tws[bb] as nat),
            128,
        )
        &&& points[2 * bb - u0 + 1] as nat == xor(
            points[2 * bb - u0] as nat,
            src[bb * 2 + 1] as nat,
        )
    }
}

proof fn flush_extends(
    src: Seq<u128>,
    pre: Seq<u128>,
    out: Seq<u128>,
    points: Seq<u128>,
    tws: Seq<u128>,
    coset: nat,
    row0: int,
    u0: int,
    filled: int,
)
    requires
        row0 >= 0,
        u0 >= 0,
        u0 % 2 == 0,
        filled >= 0,
        filled % 2 == 0,
        points.len() >= filled,
        out.len() == pre.len(),
        row0 + u0 + filled <= out.len(),
        flushed_rows(src, pre, tws, coset, row0, u0),
        tile_rows(src, points, tws, coset, u0, filled),
        forall|t: int| 0 <= t < filled ==> #[trigger] out[row0 + u0 + t] == points[t],
        forall|i: int|
            0 <= i < out.len() && !(row0 + u0 <= i < row0 + u0 + filled) ==> out[i] == pre[i],
    ensures
        flushed_rows(src, out, tws, coset, row0, u0 + filled),
{
    assert forall|bb: int| 0 <= 2 * bb < u0 + filled implies {
        &&& #[trigger] out[row0 + 2 * bb] as nat == bfly_lo(
            src[bb * 2] as nat,
            src[bb * 2 + 1] as nat,
            xor(coset, tws[bb] as nat),
            128,
        )
        &&& out[row0 + 2 * bb + 1] as nat == xor(out[row0 + 2 * bb] as nat, src[bb * 2 + 1] as nat)
    } by {
        if 2 * bb < u0 {
            assert(2 * bb + 2 <= u0);
            assert(out[row0 + 2 * bb] == pre[row0 + 2 * bb]);
            assert(out[row0 + 2 * bb + 1] == pre[row0 + 2 * bb + 1]);
        } else {
            let t = 2 * bb - u0;

            assert(t + 2 <= filled);
            assert(out[row0 + u0 + t] == points[t]);
            assert(out[row0 + u0 + (t + 1)] == points[t + 1]);
            assert(row0 + u0 + t == row0 + 2 * bb);
            assert(row0 + u0 + (t + 1) == row0 + 2 * bb + 1);
        }
    }
}

proof fn flush_untouched(
    orig: Seq<u128>,
    pre: Seq<u128>,
    out: Seq<u128>,
    row0: int,
    u0: int,
    filled: int,
)
    requires
        row0 >= 0,
        u0 >= 0,
        filled >= 0,
        out.len() == pre.len(),
        pre.len() == orig.len(),
        forall|i: int| 0 <= i < pre.len() && !slot(i, row0, 1, u0) ==> pre[i] == orig[i],
        forall|i: int|
            0 <= i < out.len() && !(row0 + u0 <= i < row0 + u0 + filled) ==> out[i] == pre[i],
    ensures
        forall|i: int| 0 <= i < out.len() && !slot(i, row0, 1, u0 + filled) ==> out[i] == orig[i],
{
    assert forall|i: int| 0 <= i < out.len() && !slot(i, row0, 1, u0 + filled) implies out[i]
        == orig[i] by {
        assert((i - row0) % 1 == 0);
        assert((i - row0) / 1 == i - row0);
        assert(!slot(i, row0, 1, u0));
        assert(!(row0 + u0 <= i < row0 + u0 + filled));
    }
}

proof fn rows_stride_one(
    src: Seq<u128>,
    out: Seq<u128>,
    tws: Seq<u128>,
    coset: nat,
    row0: int,
    stride: int,
    nblocks: int,
)
    requires
        stride == 1,
        flushed_rows(src, out, tws, coset, row0, 2 * nblocks),
    ensures
        forall|bb: int| 0 <= bb < nblocks ==> {
            &&& #[trigger] out[row0 + 2 * bb * stride] as nat == bfly_lo(
                src[bb * 2] as nat,
                src[bb * 2 + 1] as nat,
                xor(coset, tws[bb] as nat),
                128,
            )
            &&& out[row0 + 2 * bb * stride + stride] as nat == xor(
                out[row0 + 2 * bb * stride] as nat,
                src[bb * 2 + 1] as nat,
            )
        },
{
    assert forall|bb: int| 0 <= bb < nblocks implies {
        &&& #[trigger] out[row0 + 2 * bb * stride] as nat == bfly_lo(
            src[bb * 2] as nat,
            src[bb * 2 + 1] as nat,
            xor(coset, tws[bb] as nat),
            128,
        )
        &&& out[row0 + 2 * bb * stride + stride] as nat == xor(
            out[row0 + 2 * bb * stride] as nat,
            src[bb * 2 + 1] as nat,
        )
    } by {
        assert(2 * bb * stride == 2 * bb) by (nonlinear_arith)
            requires stride == 1;
        assert(0 <= 2 * bb < 2 * nblocks);
    }
}

fn flush_tile_exec(points: &Vec<u128>, filled: usize, out: &mut Vec<u128>, at: usize)
    requires
        filled <= points@.len(),
        at + filled <= old(out)@.len(),
        old(out)@.len() <= usize::MAX,
    ensures
        final(out)@.len() == old(out)@.len(),
        forall|t: int| 0 <= t < filled ==> #[trigger] final(out)@[at + t] == points@[t],
        forall|i: int|
            0 <= i < final(out)@.len() && !(at <= i < at + filled) ==> final(out)@[i] == old(out)@[i],
{
    let mut t: usize = 0;

    while t < filled
        invariant
            filled <= points@.len(),
            at + filled <= out@.len(),
            out@.len() == old(out)@.len(),
            out@.len() <= usize::MAX,
            t <= filled,
            forall|tt: int| 0 <= tt < t ==> #[trigger] out@[at + tt] == points@[tt],
            forall|i: int|
                0 <= i < out@.len() && !(at <= i < at + t) ==> out@[i] == old(out)@[i],
        decreases filled - t,
    {
        out.set(at + t, points[t]);
        t += 1;
    }
}

impl FftTwin {
    // fwd_top_into, additive.rs: the one block of the top level, src in, dst out
    fn fwd_top_into_exec(&self, src: &Vec<u128>, dst: &mut Vec<u128>, tw: u128)
        requires
            src@.len() == old(dst)@.len(),
            src@.len() % 2 == 0,
            src@.len() <= usize::MAX,
        ensures
            final(dst)@.len() == old(dst)@.len(),
            forall|r: int| 0 <= r < src@.len() / 2 ==> {
                &&& #[trigger] final(dst)@[r] as nat == bfly_lo(
                    src@[r] as nat,
                    src@[src@.len() / 2 + r] as nat,
                    tw as nat,
                    128,
                )
                &&& final(dst)@[src@.len() / 2 + r] as nat == xor(
                    final(dst)@[r] as nat,
                    src@[src@.len() / 2 + r] as nat,
                )
            },
    {
        let s = src.len() / 2;

        proof {
            lemma_fundamental_div_mod(src@.len() as int, 2);
        }

        let mut r: usize = 0;
        while r < s
            invariant
                s == src@.len() / 2,
                2 * s == src@.len(),
                dst@.len() == src@.len(),
                dst@.len() <= usize::MAX,
                r <= s,
                forall|u: int| 0 <= u < r ==> {
                    &&& #[trigger] dst@[u] as nat == bfly_lo(
                        src@[u] as nat,
                        src@[s + u] as nat,
                        tw as nat,
                        128,
                    )
                    &&& dst@[s + u] as nat == xor(dst@[u] as nat, src@[s + u] as nat)
                },
            decreases s - r,
        {
            let p = src[r];
            let q = src[s + r];
            let v = add_flat(p, mul_flat(q, tw));

            proof {
                gf_mul_comm(tw as nat, q as nat, 128);
            }

            dst.set(r, v);
            dst.set(s + r, add_flat(v, q));

            r += 1;
        }
    }

    // inv_bottom_into, additive.rs: level 0 of the inverse,
    // src pairs into dst pairs, the chunk walk of Twiddles::blocks.
    fn inv_bottom_into_exec(&self, src: &Vec<u128>, dst: &mut Vec<u128>, coset: u128, nblocks: usize)
        requires
            self.wf(),
            nblocks * 2 == src@.len(),
            old(dst)@.len() == src@.len(),
            nblocks <= self.twiddles@.len(),
            src@.len() <= usize::MAX,
        ensures
            final(dst)@.len() == old(dst)@.len(),
            inv_rows(src@, final(dst)@, self.twiddles@, 1, nblocks as int, coset as nat),
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
        while b < nblocks
            invariant
                self.wf(),
                nblocks * 2 == src@.len(),
                dst@.len() == src@.len(),
                nblocks <= self.twiddles@.len(),
                src@.len() <= usize::MAX,
                b <= nblocks,
                lift == nats(self.lift@),
                len == self.low@.len(),
                len as nat == pow2(low_log as nat),
                low_log as nat == self.low_log(),
                b % len == 0 || b == nblocks,
                forall|bb: int| 0 <= bb < b ==> {
                    &&& #[trigger] dst@[2 * bb] as nat == bfly_lo(
                        src@[2 * bb] as nat,
                        xor(src@[2 * bb] as nat, src@[2 * bb + 1] as nat),
                        xor(coset as nat, self.twiddles@[bb] as nat),
                        128,
                    )
                    &&& dst@[2 * bb + 1] as nat == xor(src@[2 * bb] as nat, src@[2 * bb + 1] as nat)
                },
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
                    nblocks * 2 == src@.len(),
                    dst@.len() == src@.len(),
                    nblocks <= self.twiddles@.len(),
                    src@.len() <= usize::MAX,
                    start <= b <= end,
                    end == start + take,
                    take <= len,
                    end <= nblocks,
                    lift == nats(self.lift@),
                    len == self.low@.len(),
                    len as nat == pow2(low_log as nat),
                    low_log as nat == self.low_log(),
                    start as nat == c as nat * pow2(low_log as nat),
                    ch as nat == xor(coset as nat, tw_sum(lift, c as nat, low_log as nat)),
                    forall|bb: int| 0 <= bb < b ==> {
                        &&& #[trigger] dst@[2 * bb] as nat == bfly_lo(
                            src@[2 * bb] as nat,
                            xor(src@[2 * bb] as nat, src@[2 * bb + 1] as nat),
                            xor(coset as nat, self.twiddles@[bb] as nat),
                            128,
                        )
                        &&& dst@[2 * bb + 1] as nat == xor(src@[2 * bb] as nat, src@[2 * bb + 1] as nat)
                    },
                decreases end - b,
            {
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

                let p = src[2 * b];
                let q = src[2 * b + 1];
                let qv = add_flat(p, q);
                let v = add_flat(p, mul_flat(qv, tw));

                proof {
                    gf_mul_comm(tw as nat, qv as nat, 128);
                }

                let ghost pre = dst@;

                dst.set(2 * b, v);
                dst.set(2 * b + 1, qv);

                proof {
                    assert forall|bb: int| 0 <= bb < b + 1 implies {
                        &&& #[trigger] dst@[2 * bb] as nat == bfly_lo(
                            src@[2 * bb] as nat,
                            xor(src@[2 * bb] as nat, src@[2 * bb + 1] as nat),
                            xor(coset as nat, self.twiddles@[bb] as nat),
                            128,
                        )
                        &&& dst@[2 * bb + 1] as nat == xor(src@[2 * bb] as nat, src@[2 * bb + 1] as nat)
                    } by {
                        if bb < b {
                            assert(2 * bb + 1 < 2 * b);
                            assert(dst@[2 * bb] == pre[2 * bb]);
                            assert(dst@[2 * bb + 1] == pre[2 * bb + 1]);
                        } else {
                            assert(bb == b);
                        }
                    }
                }

                b += 1;
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
            rows_to_inv_rows(src@, dst@, self.twiddles@, 1, nblocks as int, coset as nat);
        }
    }

    // fwd_bottom_into, additive.rs: level 0 of a forward coset,
    // src pairs to out points 2b and 2b + 1 at row0, one per stride.
    fn fwd_bottom_into_exec(
        &self,
        src: &Vec<u128>,
        coset: u128,
        out: &mut Vec<u128>,
        row0: usize,
        stride: usize,
        nblocks: usize,
    )
        requires
            self.wf(),
            nblocks >= 1,
            nblocks * 2 == src@.len(),
            nblocks <= self.twiddles@.len(),
            stride >= 1,
            row0 + (2 * nblocks - 1) * stride < old(out)@.len(),
            old(out)@.len() <= usize::MAX,
            src@.len() <= usize::MAX,
        ensures
            final(out)@.len() == old(out)@.len(),
            forall|bb: int| 0 <= bb < nblocks ==> {
                &&& #[trigger] final(out)@[row0 + 2 * bb * stride] as nat == bfly_lo(
                    src@[bb * 2] as nat,
                    src@[bb * 2 + 1] as nat,
                    xor(coset as nat, self.twiddles@[bb] as nat),
                    128,
                )
                &&& final(out)@[row0 + 2 * bb * stride + stride] as nat == xor(
                    final(out)@[row0 + 2 * bb * stride] as nat,
                    src@[bb * 2 + 1] as nat,
                )
            },
            forall|i: int|
                0 <= i < final(out)@.len() && !slot(i, row0 as int, stride as int, 2 * nblocks)
                    ==> final(out)@[i] == old(out)@[i],
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
        while b < nblocks
            invariant
                self.wf(),
                nblocks >= 1,
                nblocks * 2 == src@.len(),
                nblocks <= self.twiddles@.len(),
                stride >= 1,
                row0 + (2 * nblocks - 1) * stride < out@.len(),
                out@.len() == old(out)@.len(),
                out@.len() <= usize::MAX,
                src@.len() <= usize::MAX,
                b <= nblocks,
                lift == nats(self.lift@),
                len == self.low@.len(),
                len as nat == pow2(low_log as nat),
                low_log as nat == self.low_log(),
                b % len == 0 || b == nblocks,
                forall|bb: int| 0 <= bb < b ==> {
                    &&& #[trigger] out@[row0 + 2 * bb * stride] as nat == bfly_lo(
                        src@[bb * 2] as nat,
                        src@[bb * 2 + 1] as nat,
                        xor(coset as nat, self.twiddles@[bb] as nat),
                        128,
                    )
                    &&& out@[row0 + 2 * bb * stride + stride] as nat == xor(
                        out@[row0 + 2 * bb * stride] as nat,
                        src@[bb * 2 + 1] as nat,
                    )
                },
                forall|i: int|
                    0 <= i < out@.len() && !slot(i, row0 as int, stride as int, 2 * b)
                        ==> out@[i] == old(out)@[i],
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
                    nblocks >= 1,
                    nblocks * 2 == src@.len(),
                    nblocks <= self.twiddles@.len(),
                    stride >= 1,
                    row0 + (2 * nblocks - 1) * stride < out@.len(),
                    out@.len() == old(out)@.len(),
                    out@.len() <= usize::MAX,
                    src@.len() <= usize::MAX,
                    start <= b <= end,
                    end == start + take,
                    take <= len,
                    end <= nblocks,
                    lift == nats(self.lift@),
                    len == self.low@.len(),
                    len as nat == pow2(low_log as nat),
                    low_log as nat == self.low_log(),
                    start as nat == c as nat * pow2(low_log as nat),
                    ch as nat == xor(coset as nat, tw_sum(lift, c as nat, low_log as nat)),
                    forall|bb: int| 0 <= bb < b ==> {
                        &&& #[trigger] out@[row0 + 2 * bb * stride] as nat == bfly_lo(
                            src@[bb * 2] as nat,
                            src@[bb * 2 + 1] as nat,
                            xor(coset as nat, self.twiddles@[bb] as nat),
                            128,
                        )
                        &&& out@[row0 + 2 * bb * stride + stride] as nat == xor(
                            out@[row0 + 2 * bb * stride] as nat,
                            src@[bb * 2 + 1] as nat,
                        )
                    },
                    forall|i: int|
                        0 <= i < out@.len() && !slot(i, row0 as int, stride as int, 2 * b)
                            ==> out@[i] == old(out)@[i],
                decreases end - b,
            {
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

                let p = src[2 * b];
                let q = src[2 * b + 1];
                let v = add_flat(p, mul_flat(q, tw));

                proof {
                    gf_mul_comm(tw as nat, q as nat, 128);

                    assert(2 * b * stride <= (2 * nblocks - 1) * stride) by (nonlinear_arith)
                        requires b < nblocks, stride >= 1;
                    assert(2 * b * stride + stride <= (2 * nblocks - 1) * stride) by (nonlinear_arith)
                        requires b < nblocks, stride >= 1;
                }

                let at = row0 + 2 * b * stride;

                proof {
                    assert(2 * b * stride + stride == (2 * b + 1) * stride) by (nonlinear_arith);

                    lemma_fundamental_div_mod_converse_div(
                        (2 * b * stride) as int,
                        stride as int,
                        (2 * b) as int,
                        0,
                    );
                    lemma_fundamental_div_mod_converse_mod(
                        (2 * b * stride) as int,
                        stride as int,
                        (2 * b) as int,
                        0,
                    );
                    lemma_fundamental_div_mod_converse_div(
                        (2 * b * stride + stride) as int,
                        stride as int,
                        (2 * b + 1) as int,
                        0,
                    );
                    lemma_fundamental_div_mod_converse_mod(
                        (2 * b * stride + stride) as int,
                        stride as int,
                        (2 * b + 1) as int,
                        0,
                    );

                    assert(slot(at as int, row0 as int, stride as int, 2 * (b + 1)));
                    assert(slot((at + stride) as int, row0 as int, stride as int, 2 * (b + 1)));
                }

                let ghost pre = out@;

                out.set(at, v);
                out.set(at + stride, add_flat(v, q));

                proof {
                    assert forall|bb: int| 0 <= bb < b implies {
                        &&& #[trigger] out@[row0 + 2 * bb * stride] == pre[row0 + 2 * bb * stride]
                        &&& out@[row0 + 2 * bb * stride + stride] == pre[row0 + 2 * bb * stride + stride]
                    } by {
                        assert(2 * bb * stride + stride < 2 * b * stride) by (nonlinear_arith)
                            requires 0 <= bb < b, stride >= 1;
                    }

                    assert forall|i: int|
                        0 <= i < out@.len() && !slot(i, row0 as int, stride as int, 2 * (b + 1))
                            implies out@[i] == old(out)@[i] by {
                        if i == at as int || i == (at + stride) as int {
                            assert(slot(i, row0 as int, stride as int, 2 * (b + 1)));
                        } else {
                            assert(!slot(i, row0 as int, stride as int, 2 * b));
                        }
                    }
                }

                b += 1;
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
    }

    // fwd_bottom_lanes_into, additive.rs: level 0 of a forward coset
    // through a 16-point tile, flushed to out[row0 + u0..] per full
    // tile and once more for the tail; one lane, point step 1.
    fn fwd_bottom_lanes_into_exec(
        &self,
        src: &Vec<u128>,
        coset: u128,
        out: &mut Vec<u128>,
        row0: usize,
        nblocks: usize,
    )
        requires
            self.wf(),
            nblocks >= 1,
            nblocks * 2 == src@.len(),
            nblocks <= self.twiddles@.len(),
            row0 + 2 * nblocks - 1 < old(out)@.len(),
            old(out)@.len() <= usize::MAX,
            src@.len() <= usize::MAX,
        ensures
            final(out)@.len() == old(out)@.len(),
            flushed_rows(src@, final(out)@, self.twiddles@, coset as nat, row0 as int, 2 * nblocks),
            forall|i: int|
                0 <= i < final(out)@.len() && !slot(i, row0 as int, 1, 2 * nblocks)
                    ==> final(out)@[i] == old(out)@[i],
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

        let mut points: Vec<u128> = Vec::new();
        let mut k: usize = 0;

        while k < LANE_TILE
            invariant
                points@.len() == k,
                k <= LANE_TILE,
            decreases LANE_TILE - k,
        {
            points.push(0);
            k += 1;
        }

        let mut filled: usize = 0;
        let mut u0: usize = 0;
        let mut b: usize = 0;

        while b < nblocks
            invariant
                self.wf(),
                nblocks >= 1,
                nblocks * 2 == src@.len(),
                nblocks <= self.twiddles@.len(),
                row0 + 2 * nblocks - 1 < out@.len(),
                out@.len() == old(out)@.len(),
                out@.len() <= usize::MAX,
                src@.len() <= usize::MAX,
                b <= nblocks,
                lift == nats(self.lift@),
                len == self.low@.len(),
                len as nat == pow2(low_log as nat),
                low_log as nat == self.low_log(),
                b % len == 0 || b == nblocks,
                points@.len() == LANE_TILE,
                filled + 2 <= LANE_TILE,
                filled % 2 == 0,
                u0 % 2 == 0,
                u0 + filled == 2 * b,
                flushed_rows(src@, out@, self.twiddles@, coset as nat, row0 as int, u0 as int),
                tile_rows(src@, points@, self.twiddles@, coset as nat, u0 as int, filled as int),
                forall|i: int|
                    0 <= i < out@.len() && !slot(i, row0 as int, 1, u0 as int)
                        ==> out@[i] == old(out)@[i],
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
                    nblocks >= 1,
                    nblocks * 2 == src@.len(),
                    nblocks <= self.twiddles@.len(),
                    row0 + 2 * nblocks - 1 < out@.len(),
                    out@.len() == old(out)@.len(),
                    out@.len() <= usize::MAX,
                    src@.len() <= usize::MAX,
                    start <= b <= end,
                    end == start + take,
                    take <= len,
                    end <= nblocks,
                    lift == nats(self.lift@),
                    len == self.low@.len(),
                    len as nat == pow2(low_log as nat),
                    low_log as nat == self.low_log(),
                    start as nat == c as nat * pow2(low_log as nat),
                    ch as nat == xor(coset as nat, tw_sum(lift, c as nat, low_log as nat)),
                    points@.len() == LANE_TILE,
                    filled + 2 <= LANE_TILE,
                    filled % 2 == 0,
                    u0 % 2 == 0,
                    u0 + filled == 2 * b,
                    flushed_rows(src@, out@, self.twiddles@, coset as nat, row0 as int, u0 as int),
                    tile_rows(src@, points@, self.twiddles@, coset as nat, u0 as int, filled as int),
                    forall|i: int|
                        0 <= i < out@.len() && !slot(i, row0 as int, 1, u0 as int)
                            ==> out@[i] == old(out)@[i],
                decreases end - b,
            {
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

                let p = src[2 * b];
                let q = src[2 * b + 1];
                let v = add_flat(p, mul_flat(q, tw));

                proof {
                    gf_mul_comm(tw as nat, q as nat, 128);
                }

                let ghost pre_points = points@;

                points.set(filled, v);
                points.set(filled + 1, add_flat(v, q));

                proof {
                    assert forall|bb: int| u0 <= 2 * bb < u0 + (filled + 2) implies {
                        &&& #[trigger] points@[2 * bb - u0] as nat == bfly_lo(
                            src@[bb * 2] as nat,
                            src@[bb * 2 + 1] as nat,
                            xor(coset as nat, self.twiddles@[bb] as nat),
                            128,
                        )
                        &&& points@[2 * bb - u0 + 1] as nat == xor(
                            points@[2 * bb - u0] as nat,
                            src@[bb * 2 + 1] as nat,
                        )
                    } by {
                        if 2 * bb < u0 + filled {
                            assert(2 * bb - u0 + 1 < filled);
                            assert(points@[2 * bb - u0] == pre_points[2 * bb - u0]);
                            assert(points@[2 * bb - u0 + 1] == pre_points[2 * bb - u0 + 1]);
                        } else {
                            assert(bb == b);
                            assert(2 * bb - u0 == filled);
                        }
                    }

                    assert(tile_rows(
                        src@,
                        points@,
                        self.twiddles@,
                        coset as nat,
                        u0 as int,
                        (filled + 2) as int,
                    ));
                }

                filled += 2;

                if filled == LANE_TILE {
                    let ghost pre_out = out@;

                    proof {
                        assert(u0 + LANE_TILE == 2 * (b + 1));
                        assert(row0 + u0 + LANE_TILE <= out@.len());
                    }

                    flush_tile_exec(&points, LANE_TILE, out, row0 + u0);

                    proof {
                        flush_extends(
                            src@,
                            pre_out,
                            out@,
                            points@,
                            self.twiddles@,
                            coset as nat,
                            row0 as int,
                            u0 as int,
                            LANE_TILE as int,
                        );
                        flush_untouched(
                            old(out)@,
                            pre_out,
                            out@,
                            row0 as int,
                            u0 as int,
                            LANE_TILE as int,
                        );
                    }

                    u0 += LANE_TILE;
                    filled = 0;

                    proof {
                        assert(tile_rows(
                            src@,
                            points@,
                            self.twiddles@,
                            coset as nat,
                            u0 as int,
                            0,
                        ));
                    }
                }

                b += 1;
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

        if filled > 0 {
            let ghost pre_out = out@;

            proof {
                assert(row0 + u0 + filled <= out@.len());
            }

            flush_tile_exec(&points, filled, out, row0 + u0);

            proof {
                flush_extends(
                    src@,
                    pre_out,
                    out@,
                    points@,
                    self.twiddles@,
                    coset as nat,
                    row0 as int,
                    u0 as int,
                    filled as int,
                );
                flush_untouched(old(out)@, pre_out, out@, row0 as int, u0 as int, filled as int);
            }

            proof {
                assert(u0 + filled == 2 * nblocks);
            }
        } else {
            proof {
                assert(u0 == 2 * nblocks);
            }
        }
    }

    // LdePlan::run, additive.rs, the inverse half: level 0 from
    // data into the first scratch half, the rest in place there.
    fn inv_levels_into_exec(&self, src: &Vec<u128>, dst: &mut Vec<u128>)
        requires
            self.wf(),
            src@.len() == pow2(self.log_n as nat),
            old(dst)@.len() == src@.len(),
        ensures
            final(dst)@.len() == old(dst)@.len(),
            nats(final(dst)@) == inv_spec(
                nats(src@),
                nats(self.twiddles@),
                self.log_n as nat,
                0,
                128,
            ),
    {
        let n = self.log_n;

        let ghost fin = inv_spec(nats(src@), nats(self.twiddles@), n as nat, 0, 128);

        proof {
            lemma_u64_pow2_no_overflow(n as nat);
            pow2_bridge(n as nat);
            lemma_u64_pow2_no_overflow((n - 1) as nat);
            lemma_u64_shl_is_mul(1u64, (n - 1) as u64);
            pow2_bridge((n - 1) as nat);

            assert(src@.len() == pow2(n as nat));
            assert(src@.len() <= usize::MAX);
            assert(pow2(n as nat) == 2 * pow2((n - 1) as nat));

            inv_spec_len(nats(src@), nats(self.twiddles@), n as nat, 0, 128);
            gather_ident(nats(src@), pow2(n as nat));
            gather_ident(fin, pow2(n as nat));

            assert forall|off: int| 0 <= off < pow2(0) implies #[trigger] inv_spec(
                gather(nats(src@), off, pow2(0) as int, pow2((n - 0) as nat)),
                nats(self.twiddles@),
                (n - 0) as nat,
                sigma_pow(0, 0, 128),
                128,
            ) == gather(fin, off, pow2(0) as int, pow2((n - 0) as nat)) by {
                assert(pow2(0) == 1);
                assert(off == 0);
                assert(sigma_pow(0, 0, 128) == 0);
            }
        }

        let nb0 = (1u64 << (n - 1)) as usize;

        proof {
            assert(nb0 as nat == pow2((n - 1) as nat));
            assert(nb0 * 2 == src@.len());
            assert(nb0 <= self.twiddles@.len());
        }

        self.inv_bottom_into_exec(src, dst, 0, nb0);

        proof {
            assert(nb0 * (2 * 1) == src@.len());

            inv_rows_bridge(src@, dst@, self.twiddles@, n as nat, 0, 1, nb0 as int, 0);
            sigma_pow_step(0, 0, 128);

            assert(nats(src@).len() == pow2(n as nat));
            assert(nats(dst@).len() == pow2(n as nat));

            inv_pass_step(
                nats(src@),
                nats(dst@),
                fin,
                nats(self.twiddles@),
                n as nat,
                0,
                sigma_pow(0, 0, 128),
                128,
            );
        }

        let mut c: u128 = 0;
        let mut lev: u32 = 1;

        proof {
            sigma_zero(128);

            assert(sigma_pow(0, 0, 128) == 0);
            assert(c as nat == sigma_pow(0, lev as nat, 128));
        }

        while lev < n
            invariant
                self.wf(),
                n == self.log_n,
                dst@.len() == pow2(n as nat),
                dst@.len() <= usize::MAX,
                dst@.len() == old(dst)@.len(),
                src@.len() == pow2(n as nat),
                fin.len() == pow2(n as nat),
                fin == inv_spec(nats(src@), nats(self.twiddles@), n as nat, 0, 128),
                1 <= lev <= n,
                c as nat == sigma_pow(0, lev as nat, 128),
                forall|off: int| 0 <= off < pow2(lev as nat) ==> #[trigger] inv_spec(
                    gather(nats(dst@), off, pow2(lev as nat) as int, pow2((n - lev) as nat)),
                    nats(self.twiddles@),
                    (n - lev) as nat,
                    sigma_pow(0, lev as nat, 128),
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

            let ghost pre = dst@;

            assert(forall|off: int| 0 <= off < pow2(lev as nat) ==> #[trigger] inv_spec(
                gather(nats(pre), off, pow2(lev as nat) as int, pow2((n - lev) as nat)),
                nats(self.twiddles@),
                (n - lev) as nat,
                sigma_pow(0, lev as nat, 128),
                128,
            ) == gather(fin, off, pow2(lev as nat) as int, pow2((n - lev) as nat)));

            self.pass_inv_exec(dst, c, s, nblocks);

            proof {
                assert(nblocks * (2 * s) == pow2(n as nat));

                inv_rows_bridge(
                    pre,
                    dst@,
                    self.twiddles@,
                    n as nat,
                    lev as nat,
                    s as int,
                    nblocks as int,
                    c as nat,
                );

                sigma_pow_step(0, lev as nat, 128);

                assert(nats(pre).len() == pow2(n as nat));
                assert(nats(dst@).len() == pow2(n as nat));

                inv_pass_step(
                    nats(pre),
                    nats(dst@),
                    fin,
                    nats(self.twiddles@),
                    n as nat,
                    lev as nat,
                    sigma_pow(0, lev as nat, 128),
                    128,
                );

                assert(forall|off: int| 0 <= off < pow2((lev + 1) as nat) ==> #[trigger] inv_spec(
                    gather(
                        nats(dst@),
                        off,
                        pow2((lev + 1) as nat) as int,
                        pow2((n - lev - 1) as nat),
                    ),
                    nats(self.twiddles@),
                    (n - lev - 1) as nat,
                    sigma_pow(0, (lev + 1) as nat, 128),
                    128,
                ) == gather(fin, off, pow2((lev + 1) as nat) as int, pow2((n - lev - 1) as nat)));
            }

            c = add_flat(mul_flat(c, c), c);
            lev += 1;
        }

        proof {
            assert(lev == n);

            assert forall|off: int| 0 <= off < pow2(n as nat) implies nats(dst@)[off] == fin[off] by {
                assert(inv_spec(
                    gather(nats(dst@), off, pow2(lev as nat) as int, pow2((n - lev) as nat)),
                    nats(self.twiddles@),
                    (n - lev) as nat,
                    sigma_pow(0, lev as nat, 128),
                    128,
                ) == gather(fin, off, pow2(lev as nat) as int, pow2((n - lev) as nat)));

                assert((n - lev) as nat == 0);
                assert(pow2((n - lev) as nat) == 1);
                assert(gather(nats(dst@), off, pow2(lev as nat) as int, 1)[0] == nats(dst@)[off]);
                assert(gather(fin, off, pow2(lev as nat) as int, 1)[0] == fin[off]);
            }

            assert(nats(dst@) =~= fin);
        }
    }

    // AdditiveFft::lde_plan, additive.rs:
    // the coset chains, one per offset, log_n entries each.
    pub fn lde_plan(self, offsets: Vec<u128>) -> (r: LdeTwin)
        requires
            self.wf(),
            offsets@.len() * self.log_n <= usize::MAX,
        ensures
            r.wf(),
            r.fft == self,
            r.cosets == offsets@.len(),
            r.offsets@ == offsets@,
    {
        let levels = self.log_n as usize;

        let mut chains: Vec<u128> = Vec::new();
        let mut j: usize = 0;

        while j < offsets.len()
            invariant
                self.wf(),
                levels == self.log_n,
                offsets@.len() * levels <= usize::MAX,
                j <= offsets@.len(),
                chains@.len() == j * levels,
                forall|jj: int, l: int| 0 <= jj < j && 0 <= l < levels
                    ==> #[trigger] chains@[jj * levels + l] as nat
                        == sigma_pow(offsets@[jj] as nat, l as nat, 128),
            decreases offsets@.len() - j,
        {
            proof {
                assert((j + 1) * levels == j * levels + levels) by (nonlinear_arith);
                assert((j + 1) * levels <= offsets@.len() * levels) by (nonlinear_arith)
                    requires j + 1 <= offsets@.len(), levels >= 0;
            }

            let mut c = offsets[j];
            let mut l: usize = 0;

            while l < levels
                invariant
                    self.wf(),
                    levels == self.log_n,
                    offsets@.len() * levels <= usize::MAX,
                    j < offsets@.len(),
                    l <= levels,
                    j * levels + levels <= offsets@.len() * levels,
                    chains@.len() == j * levels + l,
                    c as nat == sigma_pow(offsets@[j as int] as nat, l as nat, 128),
                    forall|jj: int, ll: int| 0 <= jj < j && 0 <= ll < levels
                        ==> #[trigger] chains@[jj * levels + ll] as nat
                            == sigma_pow(offsets@[jj] as nat, ll as nat, 128),
                    forall|ll: int| 0 <= ll < l
                        ==> #[trigger] chains@[j * levels + ll] as nat
                            == sigma_pow(offsets@[j as int] as nat, ll as nat, 128),
                decreases levels - l,
            {
                let ghost before = chains@;

                chains.push(c);

                proof {
                    assert forall|jj: int, ll: int| 0 <= jj < j && 0 <= ll < levels
                        implies #[trigger] chains@[jj * levels + ll] == before[jj * levels + ll] by {
                        assert(jj * levels + ll < (jj + 1) * levels) by (nonlinear_arith)
                            requires ll < levels;
                        assert((jj + 1) * levels <= j * levels) by (nonlinear_arith)
                            requires jj + 1 <= j, levels >= 0;
                    }
                }

                let sq = mul_flat(c, c);

                proof {
                    sigma_pow_step(offsets@[j as int] as nat, l as nat, 128);
                }

                c = add_flat(sq, c);
                l += 1;
            }

            proof {
                assert(chains@.len() == (j + 1) * levels);

                assert forall|jj: int, ll: int| 0 <= jj < j + 1 && 0 <= ll < levels
                    implies #[trigger] chains@[jj * levels + ll] as nat
                        == sigma_pow(offsets@[jj] as nat, ll as nat, 128) by {
                    assert(jj * levels + ll < (jj + 1) * levels) by (nonlinear_arith)
                        requires ll < levels;
                    assert((jj + 1) * levels <= (j + 1) * levels) by (nonlinear_arith)
                        requires jj + 1 <= j + 1, levels >= 0;

                    if jj == j {
                        assert(chains@[j * levels + ll] as nat
                            == sigma_pow(offsets@[j as int] as nat, ll as nat, 128));
                    }
                }
            }

            j += 1;
        }

        LdeTwin {
            fft: self,
            cosets: offsets.len(),
            chains,
            offsets: Ghost(offsets@),
        }
    }
}

proof fn bottom_rows_to_spec(
    src: Seq<u128>,
    out: Seq<u128>,
    tws: Seq<u128>,
    orig: Seq<nat>,
    n: nat,
    row0: int,
    stride: int,
    offset: nat,
)
    requires
        n >= 1,
        src.len() == pow2(n),
        orig.len() == pow2(n),
        stride >= 1,
        row0 >= 0,
        pow2((n - 1) as nat) <= tws.len(),
        row0 + (pow2(n) - 1) * stride < out.len(),
        forall|bb: int| 0 <= bb < pow2((n - 1) as nat) ==> {
            &&& #[trigger] out[row0 + 2 * bb * stride] as nat == bfly_lo(
                src[bb * 2] as nat,
                src[bb * 2 + 1] as nat,
                xor(offset, tws[bb] as nat),
                128,
            )
            &&& out[row0 + 2 * bb * stride + stride] as nat == xor(
                out[row0 + 2 * bb * stride] as nat,
                src[bb * 2 + 1] as nat,
            )
        },
        forall|off: int| 0 <= off < pow2(1) ==>
            #[trigger] gather(nats(src), off, pow2(1) as int, pow2((n - 1) as nat))
                == fwd_spec(
                    gather(orig, off, pow2(1) as int, pow2((n - 1) as nat)),
                    nats(tws),
                    (n - 1) as nat,
                    sigma(offset, 128),
                    128,
                ),
    ensures
        forall|u: int| 0 <= u < pow2(n) ==>
            #[trigger] out[row0 + u * stride] as nat == fwd_spec(orig, nats(tws), n, offset, 128)[u],
{
    let nb = pow2((n - 1) as nat);
    let fin: Seq<u128> = Seq::new(pow2(n), |u: int| out[row0 + u * stride]);

    gf_model::pow2_pos((n - 1) as nat);

    assert(pow2(n) == 2 * nb);
    assert(pow2(0) == 1);
    assert(pow2(1) == 2 * pow2(0));
    assert(pow2(1) == 2);

    assert forall|bb: int, r: int| 0 <= bb < nb && 0 <= r < 1 implies {
        &&& #[trigger] fin[bb * (2 * 1) + r] as nat == bfly_lo(
            src[bb * (2 * 1) + r] as nat,
            src[bb * (2 * 1) + 1 + r] as nat,
            xor(offset, tws[bb] as nat),
            128,
        )
        &&& fin[bb * (2 * 1) + 1 + r] as nat == xor(
            fin[bb * (2 * 1) + r] as nat,
            src[bb * (2 * 1) + 1 + r] as nat,
        )
    } by {
        assert(r == 0);
        assert(bb * (2 * 1) + r == 2 * bb);
        assert(bb * (2 * 1) + 1 + r == 2 * bb + 1);
        assert(2 * bb + 1 < pow2(n));
        assert((2 * bb + 1) * stride == 2 * bb * stride + stride) by (nonlinear_arith);
        assert(fin[2 * bb] == out[row0 + 2 * bb * stride]);
        assert(fin[2 * bb + 1] == out[row0 + (2 * bb + 1) * stride]);
    }

    assert(fwd_rows(src, fin, tws, 1, nb as int, offset));

    fwd_rows_bridge(src, fin, tws, n, 1, 1, nb as int, offset);
    fwd_pass_step(nats(src), nats(fin), orig, nats(tws), n, 1, offset, 128);

    gather_ident(nats(fin), pow2(n));
    gather_ident(orig, pow2(n));

    assert((n - 1 + 1) as nat == n);
    assert(gather(nats(fin), 0, pow2(0) as int, pow2(n))
        == fwd_spec(gather(orig, 0, pow2(0) as int, pow2(n)), nats(tws), n, offset, 128));
    assert(nats(fin) == fwd_spec(orig, nats(tws), n, offset, 128));

    assert forall|u: int| 0 <= u < pow2(n) implies
        #[trigger] out[row0 + u * stride] as nat == fwd_spec(orig, nats(tws), n, offset, 128)[u] by {
        assert(nats(fin)[u] == fin[u] as nat);
        assert(fin[u] == out[row0 + u * stride]);
    }
}

pub struct LdeTwin {
    pub fft: FftTwin,
    pub cosets: usize,
    pub chains: Vec<u128>,
    pub offsets: Ghost<Seq<u128>>,
}

impl LdeTwin {
    pub open spec fn wf(self) -> bool {
        &&& self.fft.wf()
        &&& self.offsets@.len() == self.cosets
        &&& self.cosets * self.fft.log_n <= usize::MAX
        &&& self.chains@.len() == self.cosets * self.fft.log_n
        &&& forall|j: int, l: int| 0 <= j < self.cosets && 0 <= l < self.fft.log_n
            ==> #[trigger] self.chains@[j * self.fft.log_n + l] as nat
                == sigma_pow(self.offsets@[j] as nat, l as nat, 128)
    }

    // LdePlan::run and run_lanes, additive.rs, one lane:
    // lane0 is the lane's first slot, stride its point step;
    // the two scratch halves are the twin's own vectors a and b.
    pub fn run(&self, data: &Vec<u128>, out: &mut Vec<u128>, lane0: usize, stride: usize)
        requires
            self.wf(),
            data@.len() == pow2(self.fft.log_n as nat),
            stride >= 1,
            self.cosets == 0
                || lane0 + (self.cosets * data@.len() - 1) * stride < old(out)@.len(),
            old(out)@.len() <= usize::MAX,
        ensures
            final(out)@.len() == old(out)@.len(),
            forall|j: int, u: int| 0 <= j < self.cosets && 0 <= u < data@.len() ==>
                #[trigger] final(out)@[lane0 + (j * data@.len() + u) * stride] as nat == fwd_spec(
                    inv_spec(nats(data@), nats(self.fft.twiddles@), self.fft.log_n as nat, 0, 128),
                    nats(self.fft.twiddles@),
                    self.fft.log_n as nat,
                    self.offsets@[j] as nat,
                    128,
                )[u],
            forall|i: int|
                0 <= i < final(out)@.len()
                    && !slot(i, lane0 as int, stride as int, self.cosets * data@.len())
                    ==> final(out)@[i] == old(out)@[i],
    {
        let n_log = self.fft.log_n;
        let levels = n_log as usize;

        proof {
            lemma_u64_pow2_no_overflow(n_log as nat);
            lemma_u64_shl_is_mul(1u64, n_log as u64);
            pow2_bridge(n_log as nat);
            lemma_u64_pow2_no_overflow((n_log - 1) as nat);
            lemma_u64_shl_is_mul(1u64, (n_log - 1) as u64);
            pow2_bridge((n_log - 1) as nat);
        }

        let n = (1u64 << n_log) as usize;
        let nb = (1u64 << (n_log - 1)) as usize;

        proof {
            gf_model::pow2_pos(n_log as nat);
            gf_model::pow2_pos((n_log - 1) as nat);

            assert(n as nat == pow2(n_log as nat));
            assert(nb as nat == pow2((n_log - 1) as nat));
            assert(pow2(n_log as nat) == 2 * pow2((n_log - 1) as nat));
            assert(n == data@.len());
            assert(n >= 1);
            assert(nb >= 1);
            assert(nb * 2 == n);
            assert(nb <= self.fft.twiddles@.len());
            vstd::arithmetic::div_mod::lemma_mod_multiples_basic(nb as int, 2);
        }

        let mut a: Vec<u128> = Vec::new();
        let mut b: Vec<u128> = Vec::new();
        let mut i: usize = 0;

        while i < n
            invariant
                a@.len() == i,
                b@.len() == i,
                i <= n,
            decreases n - i,
        {
            a.push(0);
            b.push(0);
            i += 1;
        }

        self.fft.inv_levels_into_exec(data, &mut a);

        let ghost inv = nats(a@);
        let ghost tws = nats(self.fft.twiddles@);

        proof {
            inv_spec_len(nats(data@), tws, n_log as nat, 0, 128);
        }

        let mut j: usize = 0;

        while j < self.cosets
            invariant
                self.wf(),
                n_log == self.fft.log_n,
                levels == n_log,
                n == data@.len(),
                n as nat == pow2(n_log as nat),
                nb as nat == pow2((n_log - 1) as nat),
                nb * 2 == n,
                n >= 1,
                nb >= 1,
                n % 2 == 0,
                nb <= self.fft.twiddles@.len(),
                a@.len() == n,
                b@.len() == n,
                out@.len() == old(out)@.len(),
                out@.len() <= usize::MAX,
                stride >= 1,
                self.cosets == 0 || lane0 + (self.cosets * n - 1) * stride < out@.len(),
                nats(a@) == inv,
                inv == inv_spec(nats(data@), tws, n_log as nat, 0, 128),
                inv.len() == pow2(n_log as nat),
                tws == nats(self.fft.twiddles@),
                j <= self.cosets,
                forall|jj: int, u: int| 0 <= jj < j && 0 <= u < n ==>
                    #[trigger] out@[lane0 + (jj * n + u) * stride] as nat
                        == fwd_spec(inv, tws, n_log as nat, self.offsets@[jj] as nat, 128)[u],
                forall|i: int|
                    0 <= i < out@.len() && !slot(i, lane0 as int, stride as int, j * n)
                        ==> out@[i] == old(out)@[i],
            decreases self.cosets - j,
        {
            proof {
                assert((j + 1) * n <= self.cosets * n) by (nonlinear_arith)
                    requires j + 1 <= self.cosets, n >= 0;
                assert((j + 1) * levels <= self.cosets * levels) by (nonlinear_arith)
                    requires j + 1 <= self.cosets, levels >= 0;
                assert((j + 1) * levels == j * levels + levels) by (nonlinear_arith);
                assert(j * n * stride + (n - 1) * stride == ((j + 1) * n - 1) * stride)
                    by (nonlinear_arith)
                    requires n >= 1;
                assert(((j + 1) * n - 1) * stride <= (self.cosets * n - 1) * stride)
                    by (nonlinear_arith)
                    requires (j + 1) * n <= self.cosets * n, stride >= 1, n >= 1;
                assert((2 * nb - 1) * stride == (n - 1) * stride);
                assert(j * n <= j * n * stride) by (nonlinear_arith) requires stride >= 1, n >= 0;
                assert(j * n * stride <= ((j + 1) * n - 1) * stride) by (nonlinear_arith)
                    requires n >= 1, stride >= 1;
                assert(lane0 + ((j + 1) * n - 1) * stride < out@.len());
            }

            let row0 = lane0 + j * n * stride;
            let base = j * levels;

            let ghost off_j = self.offsets@[j as int] as nat;
            let ghost pre_out = out@;

            proof {
                assert(base + levels <= self.chains@.len());
                assert(base as int == j * self.fft.log_n + 0);
                assert(self.chains@[j * self.fft.log_n + 0] as nat
                    == sigma_pow(self.offsets@[j as int] as nat, 0, 128));
                assert(self.chains@[base as int] as nat == sigma_pow(off_j, 0, 128));
                assert(sigma_pow(off_j, 0, 128) == off_j);
            }

            if levels == 1 {
                proof {
                    assert forall|off: int| 0 <= off < pow2(1) implies
                        #[trigger] gather(nats(a@), off, pow2(1) as int, pow2((n_log - 1) as nat))
                            == fwd_spec(
                                gather(inv, off, pow2(1) as int, pow2((n_log - 1) as nat)),
                                tws,
                                (n_log - 1) as nat,
                                sigma(off_j, 128),
                                128,
                            ) by {
                        assert((n_log - 1) as nat == 0);
                    }
                }

                if stride == 1 {
                    proof {
                        assert((2 * nb - 1) * stride == 2 * nb - 1) by (nonlinear_arith)
                            requires stride == 1;
                    }

                    self.fft.fwd_bottom_lanes_into_exec(&a, self.chains[base], out, row0, nb);

                    proof {
                        rows_stride_one(
                            a@,
                            out@,
                            self.fft.twiddles@,
                            self.chains@[base as int] as nat,
                            row0 as int,
                            stride as int,
                            nb as int,
                        );
                    }
                } else {
                    self.fft.fwd_bottom_into_exec(&a, self.chains[base], out, row0, stride, nb);
                }

                proof {
                    bottom_rows_to_spec(
                        a@,
                        out@,
                        self.fft.twiddles@,
                        inv,
                        n_log as nat,
                        row0 as int,
                        stride as int,
                        off_j,
                    );
                }
            } else {
                let ghost coset_top = self.chains@[(base + levels - 1) as int] as nat;

                proof {
                    assert((base + levels - 1) as int == j * self.fft.log_n + (levels - 1));
                    assert(self.chains@[j * self.fft.log_n + (levels - 1)] as nat
                        == sigma_pow(self.offsets@[j as int] as nat, (levels - 1) as nat, 128));
                    assert(coset_top == sigma_pow(off_j, (levels - 1) as nat, 128));
                    assert(self.fft.twiddles@[0] as nat == tw_sum(nats(self.fft.lift@), 0, 0));
                    assert(tw_sum(nats(self.fft.lift@), 0, 0) == 0);
                    xor_comm(coset_top, 0);
                    xor_zero(coset_top);
                    assert(xor(coset_top, self.fft.twiddles@[0] as nat) == coset_top);
                }

                self.fft.fwd_top_into_exec(&a, &mut b, self.chains[base + levels - 1]);

                proof {
                    assert forall|bb: int, r: int| 0 <= bb < 1 && 0 <= r < nb implies {
                        &&& #[trigger] b@[bb * (2 * nb) + r] as nat == bfly_lo(
                            a@[bb * (2 * nb) + r] as nat,
                            a@[bb * (2 * nb) + nb + r] as nat,
                            xor(coset_top, self.fft.twiddles@[bb] as nat),
                            128,
                        )
                        &&& b@[bb * (2 * nb) + nb + r] as nat == xor(
                            b@[bb * (2 * nb) + r] as nat,
                            a@[bb * (2 * nb) + nb + r] as nat,
                        )
                    } by {
                        assert(bb == 0);
                        assert(bb * (2 * nb) + r == r);
                        assert(bb * (2 * nb) + nb + r == nb + r);
                        assert(a@.len() / 2 == nb);
                    }

                    assert(fwd_rows(a@, b@, self.fft.twiddles@, nb as int, 1, coset_top));

                    assert forall|off: int| 0 <= off < pow2(n_log as nat) implies
                        #[trigger] gather(nats(a@), off, pow2(n_log as nat) as int, pow2((n_log - n_log) as nat))
                            == fwd_spec(
                                gather(inv, off, pow2(n_log as nat) as int, pow2((n_log - n_log) as nat)),
                                tws,
                                (n_log - n_log) as nat,
                                sigma(coset_top, 128),
                                128,
                            ) by {
                        assert((n_log - n_log) as nat == 0);
                        assert(pow2(0) == 1);
                    }

                    assert(1 * (2 * nb) == a@.len());
                    assert(pow2((n_log - n_log) as nat) == 1);

                    fwd_rows_bridge(
                        a@,
                        b@,
                        self.fft.twiddles@,
                        n_log as nat,
                        n_log as nat,
                        nb as int,
                        1,
                        coset_top,
                    );
                    fwd_pass_step(nats(a@), nats(b@), inv, tws, n_log as nat, n_log as nat, coset_top, 128);

                    assert((n_log - 1) as nat == (levels - 1) as nat);
                    assert((n_log - n_log + 1) as nat == 1);
                }

                let mut lev: u32 = n_log - 1;

                while lev > 1
                    invariant
                        self.wf(),
                        n_log == self.fft.log_n,
                        levels == n_log,
                        n == data@.len(),
                        n as nat == pow2(n_log as nat),
                        b@.len() == n,
                        b@.len() <= usize::MAX,
                        inv.len() == pow2(n_log as nat),
                        tws == nats(self.fft.twiddles@),
                        j < self.cosets,
                        base == j * levels,
                        base + levels <= self.chains@.len(),
                        off_j == self.offsets@[j as int] as nat,
                        1 <= lev <= n_log,
                        forall|off: int| 0 <= off < pow2(lev as nat) ==> #[trigger] gather(
                            nats(b@),
                            off,
                            pow2(lev as nat) as int,
                            pow2((n_log - lev) as nat),
                        ) == fwd_spec(
                            gather(inv, off, pow2(lev as nat) as int, pow2((n_log - lev) as nat)),
                            tws,
                            (n_log - lev) as nat,
                            sigma_pow(off_j, lev as nat, 128),
                            128,
                        ),
                    decreases lev,
                {
                    let new_l = lev - 1;

                    proof {
                        lemma_u64_pow2_no_overflow(new_l as nat);
                        lemma_u64_shl_is_mul(1u64, new_l as u64);
                        pow2_bridge(new_l as nat);

                        lemma_u64_pow2_no_overflow((n_log - lev) as nat);
                        lemma_u64_shl_is_mul(1u64, (n_log - lev) as u64);
                        pow2_bridge((n_log - lev) as nat);

                        assert(pow2(lev as nat) == 2 * pow2(new_l as nat));
                        gf_model::pow2_add((n_log - lev) as nat, lev as nat);
                        assert((n_log - lev) + lev == n_log);
                        pow2_mono(lev as nat, n_log as nat);
                        pow2_mono((n_log - lev) as nat, (n_log - 1) as nat);
                        gf_model::pow2_pos(new_l as nat);

                        assert((base + new_l) as int == j * self.fft.log_n + new_l);
                        assert(self.chains@[j * self.fft.log_n + new_l] as nat
                            == sigma_pow(self.offsets@[j as int] as nat, new_l as nat, 128));
                        assert(self.chains@[(base + new_l) as int] as nat
                            == sigma_pow(off_j, new_l as nat, 128));
                    }

                    let s = (1u64 << new_l) as usize;
                    let nblocks = (1u64 << (n_log - lev)) as usize;

                    proof {
                        assert(nblocks * (2 * s) == pow2((n_log - lev) as nat) * pow2(lev as nat));
                        assert(2 * s <= usize::MAX);
                        assert(s <= usize::MAX / 2);
                    }

                    proof {
                        assert(base + new_l < self.chains@.len());
                    }

                    let ghost pre = b@;
                    let coset = self.chains[base + new_l as usize];

                    self.fft.pass_fwd_exec(&mut b, coset, s, nblocks);

                    proof {
                        assert(nblocks * (2 * s) == pow2(n_log as nat));
                        assert(coset as nat == sigma_pow(off_j, new_l as nat, 128));

                        fwd_rows_bridge(
                            pre,
                            b@,
                            self.fft.twiddles@,
                            n_log as nat,
                            lev as nat,
                            s as int,
                            nblocks as int,
                            coset as nat,
                        );

                        sigma_pow_step(off_j, new_l as nat, 128);

                        assert(nats(pre).len() == pow2(n_log as nat));
                        assert(nats(b@).len() == pow2(n_log as nat));
                        assert((new_l as nat) + 1 == lev as nat);

                        fwd_pass_step(
                            nats(pre),
                            nats(b@),
                            inv,
                            tws,
                            n_log as nat,
                            lev as nat,
                            sigma_pow(off_j, new_l as nat, 128),
                            128,
                        );

                        assert(forall|off: int| 0 <= off < pow2(new_l as nat) ==> #[trigger] gather(
                            nats(b@),
                            off,
                            pow2(new_l as nat) as int,
                            pow2((n_log - new_l) as nat),
                        ) == fwd_spec(
                            gather(inv, off, pow2(new_l as nat) as int, pow2((n_log - new_l) as nat)),
                            tws,
                            (n_log - new_l) as nat,
                            sigma_pow(off_j, new_l as nat, 128),
                            128,
                        )) by {
                            assert(new_l as nat == (lev - 1) as nat);
                            assert((n_log - new_l) as nat == (n_log - lev + 1) as nat);
                        };
                    }

                    lev = new_l;
                }

                proof {
                    assert(lev == 1);
                    assert(sigma_pow(off_j, 1, 128) == sigma(off_j, 128)) by {
                        sigma_pow_step(off_j, 0, 128);
                    }
                }

                if stride == 1 {
                    proof {
                        assert((2 * nb - 1) * stride == 2 * nb - 1) by (nonlinear_arith)
                            requires stride == 1;
                    }

                    self.fft.fwd_bottom_lanes_into_exec(&b, self.chains[base], out, row0, nb);

                    proof {
                        rows_stride_one(
                            b@,
                            out@,
                            self.fft.twiddles@,
                            self.chains@[base as int] as nat,
                            row0 as int,
                            stride as int,
                            nb as int,
                        );
                    }
                } else {
                    self.fft.fwd_bottom_into_exec(&b, self.chains[base], out, row0, stride, nb);
                }

                proof {
                    bottom_rows_to_spec(
                        b@,
                        out@,
                        self.fft.twiddles@,
                        inv,
                        n_log as nat,
                        row0 as int,
                        stride as int,
                        off_j,
                    );
                }
            }

            proof {
                assert forall|jj: int, u: int| 0 <= jj < j + 1 && 0 <= u < n implies
                    #[trigger] out@[lane0 + (jj * n + u) * stride] as nat
                        == fwd_spec(inv, tws, n_log as nat, self.offsets@[jj] as nat, 128)[u] by {
                    if jj == j {
                        assert(lane0 + (jj * n + u) * stride == row0 + u * stride) by (nonlinear_arith)
                            requires row0 == lane0 + j * n * stride, jj == j;
                    } else {
                        assert(lane0 + (jj * n + u) * stride < row0) by (nonlinear_arith)
                            requires 0 <= jj < j, 0 <= u < n, row0 == lane0 + j * n * stride, stride >= 1, n >= 1;
                        assert(!slot(lane0 + (jj * n + u) * stride, row0 as int, stride as int, 2 * nb));
                        assert(out@[lane0 + (jj * n + u) * stride] == pre_out[lane0 + (jj * n + u) * stride]);
                    }
                }

                assert forall|i: int|
                    0 <= i < out@.len() && !slot(i, lane0 as int, stride as int, (j + 1) * n)
                        implies out@[i] == old(out)@[i] by {
                    assert(j * n <= (j + 1) * n) by (nonlinear_arith) requires n >= 0;
                    assert(!slot(i, lane0 as int, stride as int, j * n));

                    if slot(i, row0 as int, stride as int, 2 * nb) {
                        let q = (i - row0) / (stride as int);

                        lemma_fundamental_div_mod(i - row0, stride as int);

                        assert(i - row0 == (stride as int) * q);
                        assert(i - lane0 == (j * n + q) * stride) by (nonlinear_arith)
                            requires i - row0 == (stride as int) * q, row0 == lane0 + j * n * stride;

                        lemma_fundamental_div_mod_converse_div(i - lane0, stride as int, j * n + q, 0);
                        lemma_fundamental_div_mod_converse_mod(i - lane0, stride as int, j * n + q, 0);

                        assert(j * n + q < (j + 1) * n) by (nonlinear_arith)
                            requires q < 2 * nb, 2 * nb == n;
                        assert(slot(i, lane0 as int, stride as int, (j + 1) * n));
                        assert(false);
                    }

                    assert(out@[i] == pre_out[i]);
                }
            }

            j += 1;
        }
    }
}

}
