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

//! Twins of the packed NEON kernels (mul_flat_packed_8/16,
//! mul_flat_scalar_packed_16), each lane proven equal to
//! `gf_model::gf_mul`. The 16-bit kernel is a different
//! algorithm than the scalar, byte-Karatsuba with a
//! shift-decomposed 0x2b fold, and the 8-bit kernel reduces
//! through two inline nibble tables; both become theorems
//! here, table bytes included.

use vstd::prelude::*;

#[path = "flat.rs"]
pub mod flat;

use flat::bridge;
use flat::bridge::gf_model::{
    clmul, clmul_distrib_l, clmul_distrib_r, clmul_one_r, clmul_pow2, deg_lt_conv, deg_modulus,
    gf_mul, lo_plus_hipart_is_xor, modulus, pmod, pmod_additive, pow2, pow2_mono, xor, xor_assoc,
    xor_comm, xor_lt_pow2, xor_mul_pow2,
};
use flat::bridge::neon_model::{
    clmul8_lane, hi8, lo8, vand_m8, vcombine_m8, vdup_m8, veor_m8, veor_m16, vget_high_m8,
    vget_low_m8, vmovn_m16, vmull_p8_m, vqtbl1_m, vshl_m16, vshr_m8, vshr_m16,
};
use flat::bridge::{
    clmul_bound, clmul8_bridge, fold_step, karatsuba_clmul, pmod_below, r_poly, u128_pack,
    xor8_reflect, xor16_reflect, xor32_reflect,
};
use flat::{mul_flat_32_twin, mul_flat_64_twin, mul_flat_128_twin, u16_split8};
use vstd::arithmetic::mul::lemma_mul_is_commutative;

verus! {

// ============================================================
// One lane of mul_flat_packed_16 / mul_flat_scalar_packed_16:
// byte-Karatsuba (three vmull_p8 lanes), then the
// shift-decomposed 0x2b fold of reduce_packed_16
// (block16.rs:740-764)
// ============================================================

pub open spec fn reduce_packed_16_lane(ll: u16, mm: u16, hh: u16) -> u16 {
    let mid = (mm ^ ll) ^ hh;
    let l = ll ^ (mid << 8);
    let h = hh ^ (mid >> 8);

    let h_fold = ((h << 5) ^ (h << 3)) ^ ((h << 1) ^ h);
    let carry = ((h >> 11) ^ (h >> 13)) ^ (h >> 15);
    let carry_fold = ((carry << 5) ^ (carry << 3)) ^ ((carry << 1) ^ carry);

    (l ^ h_fold) ^ carry_fold
}

pub open spec fn packed_16_lane(a: u16, b: u16) -> u16 {
    let ll = clmul8_lane(lo8(a), lo8(b));
    let hh = clmul8_lane(hi8(a), hi8(b));
    let mm = clmul8_lane(lo8(a) ^ hi8(a), lo8(b) ^ hi8(b));

    reduce_packed_16_lane(ll, mm, hh)
}

// clmul(h, 0x2b) splits into the {5,3,1,0} shift set:
// the truncated shifts are the low u16, the shifted-out
// bits {11,13,15} the carry.
proof fn shift_set_is_clmul_2b(h: u16)
    ensures ({
        let h_fold = ((h << 5) ^ (h << 3)) ^ ((h << 1) ^ h);
        let carry = ((h >> 11) ^ (h >> 13)) ^ (h >> 15);

        clmul(h as nat, 0x2b) == xor(h_fold as nat, pow2(16) * (carry as nat))
            && (carry as nat) < pow2(5)
    })
{
    let h_fold = ((h << 5) ^ (h << 3)) ^ ((h << 1) ^ h);
    let carry = ((h >> 11) ^ (h >> 13)) ^ (h >> 15);
    let hn = h as nat;

    assert(pow2(16) == 0x10000) by (compute);
    assert(pow2(5) == 0x20) by (compute);

    // The u32-wide shift set splits at bit 16 into the
    // truncated u16 fold plus the shifted-out carry.
    assert((((h as u32) << 5) ^ ((h as u32) << 3)) ^ (((h as u32) << 1) ^ (h as u32)) ==
        ((((h << 5) ^ (h << 3)) ^ ((h << 1) ^ h)) as u32) +
        0x10000 * ((((h >> 11) ^ (h >> 13)) ^ (h >> 15)) as u32)) by (bit_vector);
    assert(((((h >> 11) ^ (h >> 13)) ^ (h >> 15)) as u32) < 0x20) by (bit_vector);

    lo_plus_hipart_is_xor(16, h_fold as nat, carry as nat);

    // The u32 shift set as nat is the clmul expansion
    // 0x2b = x^5 + x^3 + x + 1.
    assert(((h as u32) << 5) == 32 * (h as u32)) by (bit_vector);
    assert(((h as u32) << 3) == 8 * (h as u32)) by (bit_vector);
    assert(((h as u32) << 1) == 2 * (h as u32)) by (bit_vector);

    xor32_reflect((h as u32) << 5, (h as u32) << 3);
    xor32_reflect((h as u32) << 1, h as u32);
    xor32_reflect(((h as u32) << 5) ^ ((h as u32) << 3), ((h as u32) << 1) ^ (h as u32));

    clmul_2b_expand(hn);
}

// clmul(h, 0x2b) == 32h ^ 8h ^ 2h ^ h
proof fn clmul_2b_expand(h: nat)
    ensures clmul(h, 0x2b) == xor(xor(32 * h, 8 * h), xor(2 * h, h))
{
    assert(pow2(5) == 0x20) by (compute);
    assert(pow2(3) == 8) by (compute);
    assert(pow2(1) == 2) by (compute);
    assert(0x2b == xor(0x28nat, 3nat)) by (compute);
    assert(0x28 == xor(0x20nat, 8nat)) by (compute);
    assert(3 == xor(2nat, 1nat)) by (compute);

    clmul_distrib_r(h, 0x28, 3);
    clmul_distrib_r(h, 0x20, 8);
    clmul_distrib_r(h, 2, 1);
    clmul_pow2(h, 5);
    clmul_pow2(h, 3);
    clmul_pow2(h, 1);
    clmul_one_r(h);

    lemma_mul_is_commutative(h as int, 32);
    lemma_mul_is_commutative(h as int, 8);
    lemma_mul_is_commutative(h as int, 2);
}

pub proof fn packed_16_lane_correct(a: u16, b: u16)
    ensures packed_16_lane(a, b) as nat == gf_mul(a as nat, b as nat, 16)
{
    let p8 = pow2(8);

    assert(pow2(8) == 0x100) by (compute);
    assert(pow2(16) == 0x10000) by (compute);
    assert(pow2(15) == 0x8000) by (compute);
    assert(pow2(5) == 0x20) by (compute);
    assert(pow2(10) == 0x400) by (compute);

    let a0 = lo8(a);
    let a1 = hi8(a);
    let b0 = lo8(b);
    let b1 = hi8(b);

    // Byte-limb split of both operands
    u16_split8(a);
    u16_split8(b);

    lemma_mul_is_commutative(pow2(8) as int, a1 as int);
    lemma_mul_is_commutative(pow2(8) as int, b1 as int);

    karatsuba_clmul(a0 as nat, a1 as nat, b0 as nat, b1 as nat, 8);

    let ll = clmul8_lane(a0, b0);
    let hh = clmul8_lane(a1, b1);
    let mm = clmul8_lane(a0 ^ a1, b0 ^ b1);
    let lln = clmul(a0 as nat, b0 as nat);
    let hhn = clmul(a1 as nat, b1 as nat);
    let mmn = clmul(xor(a0 as nat, a1 as nat), xor(b0 as nat, b1 as nat));

    clmul8_bridge(a0, b0);
    clmul8_bridge(a1, b1);
    clmul8_bridge(a0 ^ a1, b0 ^ b1);
    xor8_reflect(a0, a1);
    xor8_reflect(b0, b1);

    let prn = clmul(a as nat, b as nat);
    let midn = xor(mmn, xor(lln, hhn));

    // The kernel's mid = (mm ^ ll) ^ hh matches Karatsuba's
    // d1 ^ (d0 ^ d2).
    let mid = (mm ^ ll) ^ hh;

    xor16_reflect(mm, ll);
    xor16_reflect(mm ^ ll, hh);
    xor_assoc(mmn, lln, hhn);

    assert(mid as nat == midn);
    assert(prn == xor(lln, xor(midn * p8, (hhn * p8) * p8)));

    // Lane packing: P == l ^ 2^16·h with the truncated
    // mid << 8 in l and the spilled byte in h.
    let l = ll ^ (mid << 8);
    let h = hh ^ (mid >> 8);

    assert((mid << 8) as nat + 0x10000 * ((mid >> 8) as nat) == 0x100 * (mid as nat)
        && ((mid << 8) as nat) < 0x10000) by (bit_vector);

    let mlo = (mid << 8) as nat;
    let mhi = (mid >> 8) as nat;

    lo_plus_hipart_is_xor(16, mlo, mhi);
    lemma_mul_is_commutative(midn as int, pow2(8) as int);

    assert(midn * p8 == xor(mlo, pow2(16) * mhi));

    // hh·2^8·2^8 == 2^16·hh
    assert((hhn * p8) * p8 == pow2(16) * hhn) by {
        bridge::gf_model::pow2_add(8, 8);
        vstd::arithmetic::mul::lemma_mul_is_associative(hhn as int, p8 as int, p8 as int);
        lemma_mul_is_commutative(hhn as int, pow2(16) as int);
    }

    let ln = xor(lln, mlo);
    let hn = xor(hhn, mhi);

    assert(prn == xor(ln, pow2(16) * hn)) by {
        xor_mul_pow2(16, mhi, hhn);
        xor_comm(mhi, hhn);

        // (ll ^ (mlo ^ 2^16·mhi)) ^ 2^16·hh regroups to
        // (ll ^ mlo) ^ 2^16·(hh ^ mhi).
        xor_assoc(mlo, pow2(16) * mhi, pow2(16) * hhn);
        xor_assoc(lln, mlo, xor(pow2(16) * mhi, pow2(16) * hhn));
    }

    xor16_reflect(ll, mid << 8);
    xor16_reflect(hh, mid >> 8);

    assert(l as nat == ln);
    assert(h as nat == hn);

    // First fold
    fold_step(ln, hn, 16);

    let h_fold = ((h << 5) ^ (h << 3)) ^ ((h << 1) ^ h);
    let carry = ((h >> 11) ^ (h >> 13)) ^ (h >> 15);
    let carry_fold = ((carry << 5) ^ (carry << 3)) ^ ((carry << 1) ^ carry);

    shift_set_is_clmul_2b(h);

    // Regroup and fold the carry
    xor_assoc(ln, h_fold as nat, pow2(16) * (carry as nat));
    fold_step(xor(ln, h_fold as nat), carry as nat, 16);

    // carry < 2^5, so its fold never spills: the truncated
    // u16 shift set is the whole clmul.
    assert(clmul(carry as nat, 0x2b) == carry_fold as nat) by {
        shift_set_is_clmul_2b(carry);

        let cc = ((carry >> 11) ^ (carry >> 13)) ^ (carry >> 15);

        assert((((carry >> 11) ^ (carry >> 13)) ^ (carry >> 15)) == 0) by (bit_vector)
            requires carry < 0x20u16;
        assert(pow2(16) * ((cc) as nat) == 0);

        bridge::gf_model::xor_zero(carry_fold as nat);
    }

    // The result is reduced
    xor16_reflect(l, h_fold);
    xor16_reflect(l ^ h_fold, carry_fold);
    xor_lt_pow2(ln, h_fold as nat, 16);
    xor_lt_pow2(xor(ln, h_fold as nat), carry_fold as nat, 16);
    deg_lt_conv(xor(xor(ln, h_fold as nat), carry_fold as nat), 16);
    pmod_below(xor(xor(ln, h_fold as nat), carry_fold as nat), 16);
}

// ============================================================
// One lane of mul_flat_packed_8: vmull_p8 then the nibble-TBL
// reduction (block8.rs:727-803); the two 16-byte tables are
// source literals, proven byte by byte
// ============================================================

// block8.rs:751-756
pub open spec fn tbl_lo_8(n: u8) -> u8 {
    if n == 0 { 0x00 } else if n == 1 { 0x1b } else if n == 2 { 0x36 } else if n == 3 { 0x2d }
    else if n == 4 { 0x6c } else if n == 5 { 0x77 } else if n == 6 { 0x5a } else if n == 7 { 0x41 }
    else if n == 8 { 0xd8 } else if n == 9 { 0xc3 } else if n == 10 { 0xee } else if n == 11 { 0xf5 }
    else if n == 12 { 0xb4 } else if n == 13 { 0xaf } else if n == 14 { 0x82 } else { 0x99 }
}

// block8.rs:759-764
pub open spec fn tbl_hi_8(n: u8) -> u8 {
    if n == 0 { 0x00 } else if n == 1 { 0xab } else if n == 2 { 0x4d } else if n == 3 { 0xe6 }
    else if n == 4 { 0x9a } else if n == 5 { 0x31 } else if n == 6 { 0xd7 } else if n == 7 { 0x7c }
    else if n == 8 { 0x2f } else if n == 9 { 0x84 } else if n == 10 { 0x62 } else if n == 11 { 0xc9 }
    else if n == 12 { 0xb5 } else if n == 13 { 0x1e } else if n == 14 { 0xf8 } else { 0x53 }
}

pub open spec fn tbl_lo_8_seq() -> Seq<u8> {
    Seq::new(16, |i: int| tbl_lo_8(i as u8))
}

pub open spec fn tbl_hi_8_seq() -> Seq<u8> {
    Seq::new(16, |i: int| tbl_hi_8(i as u8))
}

// tbl_lo[n] is the raw fold of the low carry nibble:
// n·0x1b never reaches degree 8.
proof fn tbl_lo_8_correct(n: u8)
    requires n < 16,
    ensures tbl_lo_8(n) as nat == clmul(n as nat, 0x1b)
{
    if n == 0 { assert(clmul(0, 0x1b) == 0x00nat) by (compute); }
    else if n == 1 { assert(clmul(1, 0x1b) == 0x1bnat) by (compute); }
    else if n == 2 { assert(clmul(2, 0x1b) == 0x36nat) by (compute); }
    else if n == 3 { assert(clmul(3, 0x1b) == 0x2dnat) by (compute); }
    else if n == 4 { assert(clmul(4, 0x1b) == 0x6cnat) by (compute); }
    else if n == 5 { assert(clmul(5, 0x1b) == 0x77nat) by (compute); }
    else if n == 6 { assert(clmul(6, 0x1b) == 0x5anat) by (compute); }
    else if n == 7 { assert(clmul(7, 0x1b) == 0x41nat) by (compute); }
    else if n == 8 { assert(clmul(8, 0x1b) == 0xd8nat) by (compute); }
    else if n == 9 { assert(clmul(9, 0x1b) == 0xc3nat) by (compute); }
    else if n == 10 { assert(clmul(10, 0x1b) == 0xeenat) by (compute); }
    else if n == 11 { assert(clmul(11, 0x1b) == 0xf5nat) by (compute); }
    else if n == 12 { assert(clmul(12, 0x1b) == 0xb4nat) by (compute); }
    else if n == 13 { assert(clmul(13, 0x1b) == 0xafnat) by (compute); }
    else if n == 14 { assert(clmul(14, 0x1b) == 0x82nat) by (compute); }
    else { assert(clmul(15, 0x1b) == 0x99nat) by (compute); }
}

// tbl_hi[n] is the reduced fold of the high carry nibble:
// (16n)·0x1b crosses degree 8 and re-reduces mod 0x11b.
proof fn tbl_hi_8_correct(n: u8)
    requires n < 16,
    ensures tbl_hi_8(n) as nat == pmod(clmul(16 * (n as nat), 0x1b), modulus(8))
{
    assert(modulus(8) == 0x11b) by (compute);

    if n == 0 { assert(pmod(clmul(0, 0x1b), 0x11b) == 0x00nat) by (compute); }
    else if n == 1 { assert(pmod(clmul(16, 0x1b), 0x11b) == 0xabnat) by (compute); }
    else if n == 2 { assert(pmod(clmul(32, 0x1b), 0x11b) == 0x4dnat) by (compute); }
    else if n == 3 { assert(pmod(clmul(48, 0x1b), 0x11b) == 0xe6nat) by (compute); }
    else if n == 4 { assert(pmod(clmul(64, 0x1b), 0x11b) == 0x9anat) by (compute); }
    else if n == 5 { assert(pmod(clmul(80, 0x1b), 0x11b) == 0x31nat) by (compute); }
    else if n == 6 { assert(pmod(clmul(96, 0x1b), 0x11b) == 0xd7nat) by (compute); }
    else if n == 7 { assert(pmod(clmul(112, 0x1b), 0x11b) == 0x7cnat) by (compute); }
    else if n == 8 { assert(pmod(clmul(128, 0x1b), 0x11b) == 0x2fnat) by (compute); }
    else if n == 9 { assert(pmod(clmul(144, 0x1b), 0x11b) == 0x84nat) by (compute); }
    else if n == 10 { assert(pmod(clmul(160, 0x1b), 0x11b) == 0x62nat) by (compute); }
    else if n == 11 { assert(pmod(clmul(176, 0x1b), 0x11b) == 0xc9nat) by (compute); }
    else if n == 12 { assert(pmod(clmul(192, 0x1b), 0x11b) == 0xb5nat) by (compute); }
    else if n == 13 { assert(pmod(clmul(208, 0x1b), 0x11b) == 0x1enat) by (compute); }
    else if n == 14 { assert(pmod(clmul(224, 0x1b), 0x11b) == 0xf8nat) by (compute); }
    else { assert(pmod(clmul(240, 0x1b), 0x11b) == 0x53nat) by (compute); }
}

pub open spec fn packed_8_lane(a: u8, b: u8) -> u8 {
    let prod = clmul8_lane(a, b);
    let data = lo8(prod);
    let carry = hi8(prod);

    data ^ (tbl_lo_8(carry & 0xF) ^ tbl_hi_8(carry >> 4))
}

pub proof fn packed_8_lane_correct(a: u8, b: u8)
    ensures packed_8_lane(a, b) as nat == gf_mul(a as nat, b as nat, 8)
{
    assert(pow2(4) == 0x10) by (compute);
    assert(pow2(5) == 0x20) by (compute);
    assert(pow2(8) == 0x100) by (compute);

    clmul8_bridge(a, b);

    let prod = clmul8_lane(a, b);
    let prn = clmul(a as nat, b as nat);
    let data = lo8(prod);
    let carry = hi8(prod);

    u16_split8(prod);

    assert(prn == xor(data as nat, pow2(8) * (carry as nat)));

    fold_step(data as nat, carry as nat, 8);

    // The carry splits into nibbles; the fold distributes
    let c_lo = carry & 0xF;
    let c_hi = carry >> 4;

    assert(carry == (carry & 0xF) + 16 * (carry >> 4) &&
        ((carry & 0xF)) < 16 &&
        ((carry >> 4)) < 16) by (bit_vector);

    lo_plus_hipart_is_xor(4, c_lo as nat, c_hi as nat);

    assert((carry as nat) == xor(c_lo as nat, pow2(4) * (c_hi as nat)));

    let t1 = clmul(c_lo as nat, 0x1b);
    let t2 = clmul(pow2(4) * (c_hi as nat), 0x1b);

    clmul_distrib_l(c_lo as nat, pow2(4) * (c_hi as nat), 0x1b);

    assert(clmul(carry as nat, 0x1b) == xor(t1, t2));

    // pmod splits over the xor; each summand is a table row
    xor_assoc(data as nat, t1, t2);
    deg_modulus(8);
    pmod_additive(xor(data as nat, t1), t2, modulus(8));

    // data ^ t1 is already reduced
    clmul_bound(c_lo as nat, 0x1b, 4, 5);
    pow2_mono(8, 8);
    xor_lt_pow2(data as nat, t1, 8);
    deg_lt_conv(xor(data as nat, t1), 8);
    pmod_below(xor(data as nat, t1), 8);

    // t2's residue is the high table row
    tbl_hi_8_correct(c_hi);

    assert(pow2(4) * (c_hi as nat) == 16 * (c_hi as nat));
    assert(pmod(t2, modulus(8)) == tbl_hi_8(c_hi) as nat);

    // t1 is the low table row
    tbl_lo_8_correct(c_lo);

    // Assemble:
    // gf == (data ^ t1) ^ tbl_hi == data ^ (t1 ^ tbl_hi)
    xor8_reflect(tbl_lo_8(c_lo), tbl_hi_8(c_hi));
    xor8_reflect(data, tbl_lo_8(c_lo) ^ tbl_hi_8(c_hi));
    xor_assoc(data as nat, t1, tbl_hi_8(c_hi) as nat);
}

// ============================================================
// Vector twins: the lane wiring of the production kernels
// over the instruction model
// ============================================================

// reduce_tbl closure, block8.rs:770-792
pub open spec fn reduce_tbl_8_m(val: Seq<u16>) -> Seq<u8> {
    let data = vmovn_m16(val);
    let carry = vmovn_m16(vshr_m16(val, 8));
    let h_lo = vand_m8(carry, vdup_m8(0x0F, 8));
    let h_hi = vshr_m8(carry, 4);

    veor_m8(data, veor_m8(vqtbl1_m(tbl_lo_8_seq(), h_lo), vqtbl1_m(tbl_hi_8_seq(), h_hi)))
}

// mul_flat_packed_8, block8.rs:727-803
pub open spec fn mul_flat_packed_8_twin(a: Seq<u8>, b: Seq<u8>) -> Seq<u8> {
    let res_lo = reduce_tbl_8_m(vmull_p8_m(vget_low_m8(a), vget_low_m8(b)));
    let res_hi = reduce_tbl_8_m(vmull_p8_m(vget_high_m8(a), vget_high_m8(b)));

    vcombine_m8(res_lo, res_hi)
}

pub proof fn mul_flat_packed_8_correct(a: Seq<u8>, b: Seq<u8>)
    requires
        a.len() == 16,
        b.len() == 16,
    ensures
        mul_flat_packed_8_twin(a, b).len() == 16,
        forall|l: int| 0 <= l < 16 ==> #[trigger] mul_flat_packed_8_twin(a, b)[l] as nat
            == gf_mul(a[l] as nat, b[l] as nat, 8),
{
    assert forall|l: int| 0 <= l < 16 implies #[trigger] mul_flat_packed_8_twin(a, b)[l] as nat
        == gf_mul(a[l] as nat, b[l] as nat, 8) by {
        let prod = clmul8_lane(a[l], b[l]);
        let carry = hi8(prod);

        assert((((prod >> 8) as u8) & 0xF) < 16 && (((prod >> 8) as u8) >> 4) < 16)
            by (bit_vector);

        if l < 8 {
            assert(mul_flat_packed_8_twin(a, b)[l] == packed_8_lane(a[l], b[l]));
        } else {
            assert(mul_flat_packed_8_twin(a, b)[l] == packed_8_lane(a[l], b[l]));
        }

        packed_8_lane_correct(a[l], b[l]);
    }
}

// reduce_packed_16, block16.rs:740-764
pub open spec fn reduce_packed_16_m(ll: Seq<u16>, mm: Seq<u16>, hh: Seq<u16>) -> Seq<u16> {
    let mid = veor_m16(veor_m16(mm, ll), hh);
    let l = veor_m16(ll, vshl_m16(mid, 8));
    let h = veor_m16(hh, vshr_m16(mid, 8));

    let h_fold = veor_m16(
        veor_m16(vshl_m16(h, 5), vshl_m16(h, 3)),
        veor_m16(vshl_m16(h, 1), h),
    );
    let carry = veor_m16(
        veor_m16(vshr_m16(h, 11), vshr_m16(h, 13)),
        vshr_m16(h, 15),
    );
    let carry_fold = veor_m16(
        veor_m16(vshl_m16(carry, 5), vshl_m16(carry, 3)),
        veor_m16(vshl_m16(carry, 1), carry),
    );

    veor_m16(veor_m16(l, h_fold), carry_fold)
}

// mul_flat_packed_16, block16.rs:668-697
pub open spec fn mul_flat_packed_16_twin(a: Seq<u16>, b: Seq<u16>) -> Seq<u16> {
    let a_lo = vmovn_m16(a);
    let a_hi = vmovn_m16(vshr_m16(a, 8));
    let b_lo = vmovn_m16(b);
    let b_hi = vmovn_m16(vshr_m16(b, 8));

    let ll = vmull_p8_m(a_lo, b_lo);
    let hh = vmull_p8_m(a_hi, b_hi);
    let mm = vmull_p8_m(veor_m8(a_lo, a_hi), veor_m8(b_lo, b_hi));

    reduce_packed_16_m(ll, mm, hh)
}

// mul_flat_scalar_packed_16, block16.rs:702-735: the
// lane-uniform byte split of the scalar is hoisted.
pub open spec fn mul_flat_scalar_packed_16_twin(a: Seq<u16>, s: u16) -> Seq<u16> {
    let a_lo = vmovn_m16(a);
    let a_hi = vmovn_m16(vshr_m16(a, 8));

    let ll = vmull_p8_m(a_lo, vdup_m8(lo8(s), 8));
    let hh = vmull_p8_m(a_hi, vdup_m8(hi8(s), 8));
    let mm = vmull_p8_m(veor_m8(a_lo, a_hi), vdup_m8(lo8(s) ^ hi8(s), 8));

    reduce_packed_16_m(ll, mm, hh)
}

pub proof fn mul_flat_packed_16_correct(a: Seq<u16>, b: Seq<u16>)
    requires
        a.len() == 8,
        b.len() == 8,
    ensures
        mul_flat_packed_16_twin(a, b).len() == 8,
        forall|l: int| 0 <= l < 8 ==> #[trigger] mul_flat_packed_16_twin(a, b)[l] as nat
            == gf_mul(a[l] as nat, b[l] as nat, 16),
{
    assert forall|l: int| 0 <= l < 8 implies #[trigger] mul_flat_packed_16_twin(a, b)[l] as nat
        == gf_mul(a[l] as nat, b[l] as nat, 16) by {
        assert(mul_flat_packed_16_twin(a, b)[l] == packed_16_lane(a[l], b[l]));

        packed_16_lane_correct(a[l], b[l]);
    }
}

pub proof fn mul_flat_scalar_packed_16_correct(a: Seq<u16>, s: u16)
    requires a.len() == 8,
    ensures
        mul_flat_scalar_packed_16_twin(a, s).len() == 8,
        forall|l: int| 0 <= l < 8 ==> #[trigger] mul_flat_scalar_packed_16_twin(a, s)[l] as nat
            == gf_mul(a[l] as nat, s as nat, 16),
{
    assert forall|l: int| 0 <= l < 8 implies #[trigger] mul_flat_scalar_packed_16_twin(a, s)[l] as nat
        == gf_mul(a[l] as nat, s as nat, 16) by {
        assert(mul_flat_scalar_packed_16_twin(a, s)[l] == packed_16_lane(a[l], s));

        packed_16_lane_correct(a[l], s);
    }
}

// ============================================================
// The remaining packed kernels compute the proven scalar dataflow
// per lane: block64.rs:601-636 (PMULL/PMULL2 pairs with uzp lane
// regroup, lane values unchanged), block32.rs:596 (scalar-kernel loop),
// and the mul_hardware_packed loop in block128.rs:497
// ============================================================

pub open spec fn mul_flat_packed_64_twin(a: Seq<u64>, b: Seq<u64>) -> Seq<u64> {
    Seq::new(a.len(), |i: int| mul_flat_64_twin(a[i], b[i]))
}

pub proof fn mul_flat_packed_64_correct(a: Seq<u64>, b: Seq<u64>)
    requires
        a.len() == 2,
        b.len() == 2,
    ensures forall|l: int| 0 <= l < 2 ==> #[trigger] mul_flat_packed_64_twin(a, b)[l] as nat
        == gf_mul(a[l] as nat, b[l] as nat, 64),
{
    assert forall|l: int| 0 <= l < 2 implies #[trigger] mul_flat_packed_64_twin(a, b)[l] as nat
        == gf_mul(a[l] as nat, b[l] as nat, 64) by {
        flat::mul_flat_64_correct(a[l], b[l]);
    }
}

pub open spec fn mul_flat_packed_32_twin(a: Seq<u32>, b: Seq<u32>) -> Seq<u32> {
    Seq::new(a.len(), |i: int| mul_flat_32_twin(a[i], b[i]))
}

pub proof fn mul_flat_packed_32_correct(a: Seq<u32>, b: Seq<u32>)
    requires
        a.len() == 4,
        b.len() == 4,
    ensures forall|l: int| 0 <= l < 4 ==> #[trigger] mul_flat_packed_32_twin(a, b)[l] as nat
        == gf_mul(a[l] as nat, b[l] as nat, 32),
{
    assert forall|l: int| 0 <= l < 4 implies #[trigger] mul_flat_packed_32_twin(a, b)[l] as nat
        == gf_mul(a[l] as nat, b[l] as nat, 32) by {
        flat::mul_flat_32_correct(a[l], b[l]);
    }
}

pub open spec fn mul_flat_packed_128_twin(a: Seq<u128>, b: Seq<u128>) -> Seq<u128> {
    Seq::new(a.len(), |i: int| mul_flat_128_twin(a[i], b[i]))
}

pub proof fn mul_flat_packed_128_correct(a: Seq<u128>, b: Seq<u128>)
    requires
        a.len() == 4,
        b.len() == 4,
    ensures forall|l: int| 0 <= l < 4 ==> #[trigger] mul_flat_packed_128_twin(a, b)[l] as nat
        == gf_mul(a[l] as nat, b[l] as nat, 128),
{
    assert forall|l: int| 0 <= l < 4 implies #[trigger] mul_flat_packed_128_twin(a, b)[l] as nat
        == gf_mul(a[l] as nat, b[l] as nat, 128) by {
        flat::mul_flat_128_correct(a[l], b[l]);
    }
}

fn main() {
}

} // verus!
