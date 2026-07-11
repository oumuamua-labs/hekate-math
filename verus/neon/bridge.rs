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

//! Ties the NEON instruction model to the `gf_model` field:
//! PMULL reflects to `clmul`, the double-fold reduction of
//! every scalar kernel is one `pmod`-congruence lemma
//! (`fold_step`), and limb-split Karatsuba is proven once at
//! the `clmul` level for any limb width.

use vstd::prelude::*;

#[path = "../gf_model.rs"]
pub mod gf_model;

#[path = "model.rs"]
pub mod neon_model;

use gf_model::{
    clmul, clmul_assoc, clmul_comm, clmul_distrib_l, clmul_distrib_r, clmul_pow2, clmul_zero_r,
    deg, deg_clmul, deg_lt_conv, deg_modulus, deg_upper, lo_plus_hipart_is_xor, modulus, pmod,
    pmod_additive, pmod_of_multiple, pow2, pow2_mono, xor, xor_assoc, xor_comm, xor_mul_pow2,
    xor_rearrange4, xor_self, xor_zero,
};
use neon_model::{clmul8_lane, vmull_p64_m};
use vstd::arithmetic::mul::{lemma_mul_is_associative, lemma_mul_is_commutative};

verus! {

// gf_model::pow2 agrees with vstd's
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

// ============================================================
// XOR reflection: gf_model::xor on uN values is native ^
// ============================================================

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

// The smaller widths embed into u128: zero-extension
// commutes with ^.
pub proof fn xor64_reflect(x: u64, y: u64)
    ensures xor(x as nat, y as nat) == (x ^ y) as nat
{
    xor128_reflect(x as u128, y as u128);

    assert((x as u128) ^ (y as u128) == (x ^ y) as u128) by (bit_vector);
}

pub proof fn xor32_reflect(x: u32, y: u32)
    ensures xor(x as nat, y as nat) == (x ^ y) as nat
{
    xor128_reflect(x as u128, y as u128);

    assert((x as u128) ^ (y as u128) == (x ^ y) as u128) by (bit_vector);
}

pub proof fn xor16_reflect(x: u16, y: u16)
    ensures xor(x as nat, y as nat) == (x ^ y) as nat
{
    xor128_reflect(x as u128, y as u128);

    assert((x as u128) ^ (y as u128) == (x ^ y) as u128) by (bit_vector);
}

pub proof fn xor8_reflect(x: u8, y: u8)
    ensures xor(x as nat, y as nat) == (x ^ y) as nat
{
    xor128_reflect(x as u128, y as u128);

    assert((x as u128) ^ (y as u128) == (x ^ y) as u128) by (bit_vector);
}

// ============================================================
// PMULL reflection: the model recursion computes clmul
// ============================================================

pub proof fn clmul64_bridge(a: u64, b: u64)
    ensures
        vmull_p64_m(a, b) as nat == clmul(a as nat, b as nat),
        vmull_p64_m(a, b) < pow2(127),
    decreases a
{
    assert(pow2(127) == 0x8000_0000_0000_0000_0000_0000_0000_0000) by (compute);

    if a == 0 {
    } else {
        clmul64_bridge(a / 2, b);

        let t = vmull_p64_m(a / 2, b);

        // deg(clmul(a/2, b)) <= 62 + 63 < 126, so the shift
        // up by one cannot truncate.
        if a / 2 == 0 || b == 0 {
            clmul_zero_r((a / 2) as nat);

            assert(clmul((a / 2) as nat, 0) == 0);
            assert((t as nat) < pow2(126)) by {
                pow2_mono(0, 126);

                if a / 2 == 0 {
                    assert(clmul(0, b as nat) == 0);
                }
            }
        } else {
            assert(pow2(63) == 0x8000_0000_0000_0000) by (compute);
            assert(pow2(64) == 0x1_0000_0000_0000_0000) by (compute);

            deg_lt_conv((a / 2) as nat, 63);
            deg_lt_conv(b as nat, 64);
            deg_clmul((a / 2) as nat, b as nat);
            deg_upper(clmul((a / 2) as nat, b as nat), 126);
        }

        assert(pow2(126) == 0x4000_0000_0000_0000_0000_0000_0000_0000) by (compute);
        assert((t << 1) as nat == 2 * (t as nat)) by (bit_vector)
            requires t < 0x4000_0000_0000_0000_0000_0000_0000_0000u128;

        clmul_shift_r_wrap((a / 2) as nat, b as nat);

        let sel: u128 = if a % 2 == 1 { b as u128 } else { 0 };

        assert(sel ^ (t << 1) < 0x8000_0000_0000_0000_0000_0000_0000_0000u128) by (bit_vector)
            requires
                sel <= 0xFFFF_FFFF_FFFF_FFFFu128,
                t < 0x4000_0000_0000_0000_0000_0000_0000_0000u128;

        xor128_reflect(sel, t << 1);

        assert((a as nat) / 2 == (a / 2) as nat);
        assert((a as nat) % 2 == (a % 2) as nat);
        assert(clmul(a as nat, b as nat)
            == xor(if a as nat % 2 == 1 { b as nat } else { 0 }, clmul((a / 2) as nat, 2 * (b as nat))));
    }
}

// clmul(a, 2b) == 2 clmul(a, b), re-exported shape.
proof fn clmul_shift_r_wrap(a: nat, b: nat)
    ensures clmul(a, 2 * b) == 2 * clmul(a, b)
{
    gf_model::clmul_shift_r(a, b);
}

pub proof fn clmul8_bridge(a: u8, b: u8)
    ensures
        clmul8_lane(a, b) as nat == clmul(a as nat, b as nat),
        clmul8_lane(a, b) < pow2(15),
    decreases a
{
    assert(pow2(15) == 0x8000) by (compute);

    if a == 0 {
    } else {
        clmul8_bridge(a / 2, b);

        let t = clmul8_lane(a / 2, b);

        if a / 2 == 0 || b == 0 {
            clmul_zero_r((a / 2) as nat);

            assert(clmul((a / 2) as nat, 0) == 0);
            assert((t as nat) < pow2(14)) by {
                pow2_mono(0, 14);

                if a / 2 == 0 {
                    assert(clmul(0, b as nat) == 0);
                }
            }
        } else {
            assert(pow2(7) == 128) by (compute);
            assert(pow2(8) == 256) by (compute);

            deg_lt_conv((a / 2) as nat, 7);
            deg_lt_conv(b as nat, 8);
            deg_clmul((a / 2) as nat, b as nat);
            deg_upper(clmul((a / 2) as nat, b as nat), 14);
        }

        assert(pow2(14) == 0x4000) by (compute);
        assert((t << 1) as nat == 2 * (t as nat)) by (bit_vector) requires t < 0x4000u16;

        clmul_shift_r_wrap((a / 2) as nat, b as nat);

        let sel: u16 = if a % 2 == 1 { b as u16 } else { 0 };

        assert(sel ^ (t << 1) < 0x8000u16) by (bit_vector)
            requires sel <= 0xFFu16, t < 0x4000u16;

        xor16_reflect(sel, t << 1);

        assert((a as nat) / 2 == (a / 2) as nat);
        assert((a as nat) % 2 == (a % 2) as nat);
        assert(clmul(a as nat, b as nat)
            == xor(if a as nat % 2 == 1 { b as nat } else { 0 }, clmul((a / 2) as nat, 2 * (b as nat))));
    }
}

// ============================================================
// The double-fold reduction, one congruence step:
// x^k ≡ r (mod x^k + r), so folding the high part through
// clmul(·, r) preserves the residue
// ============================================================

pub open spec fn r_poly(k: nat) -> nat {
    if k == 8 {
        0x1b
    } else if k == 16 {
        0x2b
    } else if k == 32 {
        0x8d
    } else if k == 64 {
        0x1b
    } else if k == 128 {
        0x87
    } else {
        0
    }
}

pub proof fn modulus_split(k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures
        modulus(k) == xor(pow2(k), r_poly(k)),
        modulus(k) == pow2(k) + r_poly(k),
{
    pow2_mono(8, k);

    assert(pow2(8) == 256) by (compute);

    lo_plus_hipart_is_xor(k, r_poly(k), 1);

    assert(pow2(k) * 1 == pow2(k));

    xor_comm(r_poly(k), pow2(k));
}

pub proof fn fold_step(l: nat, h: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures pmod(xor(l, pow2(k) * h), modulus(k))
        == pmod(xor(l, clmul(h, r_poly(k))), modulus(k))
{
    let m = modulus(k);
    let r = r_poly(k);
    let hp = pow2(k) * h;
    let cr = clmul(h, r);

    deg_modulus(k);
    modulus_split(k);

    // clmul(h, m) == xor(hp, cr)
    clmul_distrib_r(h, pow2(k), r);
    clmul_pow2(h, k);
    lemma_mul_is_commutative(h as int, pow2(k) as int);

    // hp == xor(clmul(h, m), cr)
    xor_assoc(hp, cr, cr);
    xor_self(cr);
    xor_zero(hp);

    // xor(l, hp) == xor(xor(l, cr), clmul(h, m))
    let chm = clmul(h, m);

    assert(xor(l, hp) == xor(l, xor(chm, cr)));

    xor_comm(chm, cr);
    xor_assoc(l, cr, chm);

    pmod_additive(xor(l, cr), chm, m);
    pmod_of_multiple(h, m);
    xor_zero(pmod(xor(l, cr), m));
}

// clmul of width-bounded operands is width-bounded:
// deg < da + db - 1.
pub proof fn clmul_bound(a: nat, b: nat, da: nat, db: nat)
    requires
        a < pow2(da),
        b < pow2(db),
        da >= 1,
        db >= 1,
    ensures clmul(a, b) < pow2((da + db - 1) as nat)
{
    gf_model::pow2_pos((da + db - 1) as nat);

    if a == 0 {
        assert(clmul(0, b) == 0);
    } else if b == 0 {
        clmul_zero_r(a);
    } else {
        gf_model::deg_lt_conv(a, da);
        gf_model::deg_lt_conv(b, db);
        deg_clmul(a, b);
        gf_model::deg_upper(clmul(a, b), (da + db - 1) as nat);
    }
}

// A reduced value is its own residue.
pub proof fn pmod_below(a: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        deg(a) < k,
    ensures pmod(a, modulus(k)) == a
{
    deg_modulus(k);
}

// ============================================================
// Limb-split Karatsuba at the clmul level, any limb width
// ============================================================

// clmul(x·2^m, y) == clmul(x, y)·2^m.
pub proof fn clmul_shift_limb(x: nat, y: nat, m: nat)
    ensures clmul(x * pow2(m), y) == clmul(x, y) * pow2(m)
{
    clmul_pow2(x, m);
    clmul_assoc(x, pow2(m), y);
    clmul_comm(pow2(m), y);
    clmul_assoc(x, y, pow2(m));
    clmul_pow2(clmul(x, y), m);
}

pub proof fn clmul_shift_limb_r(x: nat, y: nat, m: nat)
    ensures clmul(x, y * pow2(m)) == clmul(x, y) * pow2(m)
{
    clmul_comm(x, y * pow2(m));
    clmul_shift_limb(y, x, m);
    clmul_comm(y, x);
}

// The 2×2 limb product with the d1 ^ d0 ^ d2 mid-term:
// cross terms survive, the diagonal cancels in char 2.
pub proof fn karatsuba_clmul(a0: nat, a1: nat, b0: nat, b1: nat, m: nat)
    ensures ({
        let p = pow2(m);
        let d0 = clmul(a0, b0);
        let d2 = clmul(a1, b1);
        let d1 = clmul(xor(a0, a1), xor(b0, b1));
        let mid = xor(d1, xor(d0, d2));

        clmul(xor(a0, a1 * p), xor(b0, b1 * p))
            == xor(d0, xor(mid * p, d2 * p * p))
    })
{
    let p = pow2(m);
    let d0 = clmul(a0, b0);
    let d2 = clmul(a1, b1);
    let d1 = clmul(xor(a0, a1), xor(b0, b1));
    let c01 = clmul(a0, b1);
    let c10 = clmul(a1, b0);
    let bb = xor(b0, b1 * p);

    // Full expansion of the packed product.
    clmul_distrib_l(a0, a1 * p, bb);
    clmul_distrib_r(a0, b0, b1 * p);
    clmul_distrib_r(a1 * p, b0, b1 * p);
    clmul_shift_limb_r(a0, b1, m);
    clmul_shift_limb(a1, b0, m);
    clmul_shift_limb(a1, b1 * p, m);
    clmul_shift_limb_r(a1, b1, m);

    assert(clmul(a1 * p, b1 * p) == d2 * p * p) by {
        lemma_mul_is_associative(d2 as int, p as int, p as int);
    }

    assert(clmul(xor(a0, a1 * p), bb)
        == xor(xor(d0, c01 * p), xor(c10 * p, d2 * p * p)));

    // mid == xor(c01, c10): the d0/d2 diagonal cancels.
    clmul_distrib_l(a0, a1, xor(b0, b1));
    clmul_distrib_r(a0, b0, b1);
    clmul_distrib_r(a1, b0, b1);

    assert(d1 == xor(xor(d0, c01), xor(c10, d2)));

    let mid = xor(d1, xor(d0, d2));
    let dd = xor(d0, d2);
    let cc = xor(c01, c10);

    assert(mid == cc) by {
        // Regroup d1's four terms into (d0 ^ d2) ^ (c01 ^ c10),
        // then the dd pair cancels against mid's dd.
        xor_comm(c10, d2);
        xor_rearrange4(d0, c01, d2, c10);

        assert(d1 == xor(dd, cc));

        xor_comm(dd, cc);
        xor_assoc(cc, dd, dd);
        xor_self(dd);
        xor_zero(cc);
    }

    // mid·p splits back into the two cross terms.
    xor_mul_pow2(m, c01, c10);
    lemma_mul_is_commutative(p as int, c01 as int);
    lemma_mul_is_commutative(p as int, c10 as int);
    lemma_mul_is_commutative(p as int, mid as int);

    // Regroup xor(xor(d0, c01·p), xor(c10·p, d2·p²))
    // as xor(d0, xor(mid·p, d2·p²)).
    xor_assoc(d0, c01 * p, xor(c10 * p, d2 * p * p));
    xor_assoc(c01 * p, c10 * p, d2 * p * p);
}

// ============================================================
// Packing reflections: the LE u128 lane view as nat
// ============================================================

pub proof fn u128_split(x: u128)
    ensures
        x as nat == xor(neon_model::lo64(x) as nat, pow2(64) * (neon_model::hi64(x) as nat)),
        (neon_model::lo64(x) as nat) < pow2(64),
{
    assert(pow2(64) == 0x1_0000_0000_0000_0000) by (compute);
    assert(x == (x as u64) as u128 + 0x1_0000_0000_0000_0000u128 * (((x >> 64) as u64) as u128))
        by (bit_vector);

    lo_plus_hipart_is_xor(64, (x as u64) as nat, ((x >> 64) as u64) as nat);
}

pub proof fn u128_pack(lo: u64, hi: u64)
    ensures ((lo as u128) | ((hi as u128) << 64)) as nat == xor(lo as nat, pow2(64) * (hi as nat))
{
    assert(pow2(64) == 0x1_0000_0000_0000_0000) by (compute);
    assert((lo as u128) | ((hi as u128) << 64)
        == (lo as u128) + 0x1_0000_0000_0000_0000u128 * (hi as u128)) by (bit_vector);

    lo_plus_hipart_is_xor(64, lo as nat, hi as nat);
}

fn main() {
}

} // verus!
