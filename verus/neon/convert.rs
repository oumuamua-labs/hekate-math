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

//! Twins of the constant-time basis-conversion kernels:
//! `map_ct_{8,16,32,64}`, `map_ct_128_split`, and `lift_ct`
//! (src/towers/block*.rs). Each masked-accumulation loop is
//! proven to compute `bit_comb`, the XOR of `basis[i]` over
//! the set bits of the input, which is the registered φ map
//! applied to the concrete basis arrays. The non-aarch64
//! multiply fallback is a composition lemma over φ.

use vstd::prelude::*;

#[path = "bridge.rs"]
pub mod bridge;

use bridge::gf_model::{
    deg_lt_conv, deg_xor_lt, gf_mul, gf_mul_tower, gf_mul_tower_bound, gf_mul_tower_distrib_l,
    gf_mul_tower_distrib_r, in_field, phi, phi_additive, phi_inv, phi_multiplicative,
    phi_roundtrip, pow2, tau_tower, thi, tlo, xor, xor_assoc, xor_comm, xor_self, xor_zero,
};
use bridge::{
    pow2_bridge, u128_pack, xor8_reflect, xor16_reflect, xor32_reflect, xor64_reflect,
    xor128_reflect,
};
use vstd::bits::lemma_u64_shr_is_div;

verus! {

// ============================================================
// The bit-combination map: Σ_{i < n, bit i of x} basis[i]
// ============================================================

pub open spec fn bit_comb(x: nat, basis: Seq<nat>, n: nat) -> nat
    decreases n
{
    if n == 0 {
        0
    } else {
        xor(
            bit_comb(x, basis, (n - 1) as nat),
            if (x / pow2((n - 1) as nat)) % 2 == 1 { basis[n - 1] } else { 0 },
        )
    }
}

// One loop step of every map_ct kernel: the extracted bit is
// the quotient bit, and the mask select is the basis gate.
proof fn bit_gate_u64(x: u64, i: u64)
    requires i < 64,
    ensures
        ((x >> i) & 1) as nat == ((x as nat) / pow2(i as nat)) % 2,
        ((x >> i) & 1) == 0 || ((x >> i) & 1) == 1,
{
    lemma_u64_shr_is_div(x, i);
    pow2_bridge(i as nat);

    assert(((x >> i) & 1) == (x >> i) % 2) by (bit_vector);
}

// u128 form of the same gate (vstd's shr lemma stops at u64).
proof fn u128_shr_div(x: u128, i: u128)
    requires i < 128,
    ensures (x >> i) as nat == (x as nat) / pow2(i as nat)
    decreases i
{
    if i == 0 {
        assert(pow2(0) == 1) by (compute);
        assert(x >> 0 == x) by (bit_vector);
    } else {
        u128_shr_div(x, (i - 1) as u128);

        assert(sub(i, 1u128) == (i - 1) as u128) by (bit_vector) requires 0 < i < 128u128;
        assert(x >> i == (x >> sub(i, 1u128)) >> 1) by (bit_vector) requires 0 < i < 128u128;
        assert((x >> sub(i, 1u128)) >> 1 == ((x >> sub(i, 1u128)) / 2)) by (bit_vector);

        bridge::gf_model::pow2_pos((i - 1) as nat);
        vstd::arithmetic::div_mod::lemma_div_denominator(
            x as int,
            pow2((i - 1) as nat) as int,
            2,
        );

        assert(pow2(i as nat) == pow2((i - 1) as nat) * 2) by {
            vstd::arithmetic::mul::lemma_mul_is_commutative(2, pow2((i - 1) as nat) as int);
        }
    }
}

proof fn bit_gate_u128(x: u128, i: u128)
    requires i < 128,
    ensures
        ((x >> i) & 1) as nat == ((x as nat) / pow2(i as nat)) % 2,
        ((x >> i) & 1) == 0 || ((x >> i) & 1) == 1,
{
    u128_shr_div(x, i);

    assert(((x >> i) & 1) == (x >> i) % 2) by (bit_vector);
}

// ============================================================
// map_ct twins: the masked accumulation computes bit_comb
// (block8.rs:568, block16.rs:564, block32.rs:556,
// block64.rs:561, block128.rs:794)
// ============================================================

fn map_ct_8_twin(x: u8, basis: &[u8; 8]) -> (r: u8)
    ensures r as nat == bit_comb(x as nat, basis@.map_values(|v: u8| v as nat), 8)
{
    let ghost s = basis@.map_values(|v: u8| v as nat);

    let mut acc: u8 = 0;
    let mut i: usize = 0;

    while i < 8
        invariant
            i <= 8,
            s == basis@.map_values(|v: u8| v as nat),
            acc as nat == bit_comb(x as nat, s, i as nat),
        decreases 8 - i,
    {
        let bit = (x >> i) & 1;
        let mask = 0u8.wrapping_sub(bit);
        let bv = basis[i];
        let gated = bv & mask;

        proof {
            bit_gate_u64(x as u64, i as u64);

            assert(((x as u64) >> (i as u64)) & 1 == ((x >> i) & 1) as u64) by (bit_vector)
                requires i < 8usize;
            assert(gated == (if bit == 1 { bv } else { 0u8 })) by (bit_vector)
                requires gated == bv & (0u8.wrapping_sub(bit)), bit < 2u8;
            assert(s[i as int] == bv as nat);

            xor8_reflect(acc, gated);
        }

        acc ^= gated;
        i += 1;
    }

    acc
}

fn map_ct_16_twin(x: u16, basis: &[u16; 16]) -> (r: u16)
    ensures r as nat == bit_comb(x as nat, basis@.map_values(|v: u16| v as nat), 16)
{
    let ghost s = basis@.map_values(|v: u16| v as nat);

    let mut acc: u16 = 0;
    let mut i: usize = 0;

    while i < 16
        invariant
            i <= 16,
            s == basis@.map_values(|v: u16| v as nat),
            acc as nat == bit_comb(x as nat, s, i as nat),
        decreases 16 - i,
    {
        let bit = (x >> i) & 1;
        let mask = 0u16.wrapping_sub(bit);
        let bv = basis[i];
        let gated = bv & mask;

        proof {
            bit_gate_u64(x as u64, i as u64);

            assert(((x as u64) >> (i as u64)) & 1 == ((x >> i) & 1) as u64) by (bit_vector)
                requires i < 16usize;
            assert(gated == (if bit == 1 { bv } else { 0u16 })) by (bit_vector)
                requires gated == bv & (0u16.wrapping_sub(bit)), bit < 2u16;
            assert(s[i as int] == bv as nat);

            xor16_reflect(acc, gated);
        }

        acc ^= gated;
        i += 1;
    }

    acc
}

fn map_ct_32_twin(x: u32, basis: &[u32; 32]) -> (r: u32)
    ensures r as nat == bit_comb(x as nat, basis@.map_values(|v: u32| v as nat), 32)
{
    let ghost s = basis@.map_values(|v: u32| v as nat);

    let mut acc: u32 = 0;
    let mut i: usize = 0;

    while i < 32
        invariant
            i <= 32,
            s == basis@.map_values(|v: u32| v as nat),
            acc as nat == bit_comb(x as nat, s, i as nat),
        decreases 32 - i,
    {
        let bit = (x >> i) & 1;
        let mask = 0u32.wrapping_sub(bit);
        let bv = basis[i];
        let gated = bv & mask;

        proof {
            bit_gate_u64(x as u64, i as u64);

            assert(((x as u64) >> (i as u64)) & 1 == ((x >> i) & 1) as u64) by (bit_vector)
                requires i < 32usize;
            assert(gated == (if bit == 1 { bv } else { 0u32 })) by (bit_vector)
                requires gated == bv & (0u32.wrapping_sub(bit)), bit < 2u32;
            assert(s[i as int] == bv as nat);

            xor32_reflect(acc, gated);
        }

        acc ^= gated;
        i += 1;
    }

    acc
}

fn map_ct_64_twin(x: u64, basis: &[u64; 64]) -> (r: u64)
    ensures r as nat == bit_comb(x as nat, basis@.map_values(|v: u64| v as nat), 64)
{
    let ghost s = basis@.map_values(|v: u64| v as nat);

    let mut acc: u64 = 0;
    let mut i: usize = 0;

    while i < 64
        invariant
            i <= 64,
            s == basis@.map_values(|v: u64| v as nat),
            acc as nat == bit_comb(x as nat, s, i as nat),
        decreases 64 - i,
    {
        let bit = (x >> i) & 1;
        let mask = 0u64.wrapping_sub(bit);
        let bv = basis[i];
        let gated = bv & mask;

        proof {
            bit_gate_u64(x, i as u64);

            assert(gated == (if bit == 1 { bv } else { 0u64 })) by (bit_vector)
                requires gated == bv & (0u64.wrapping_sub(bit)), bit < 2u64;
            assert(s[i as int] == bv as nat);

            xor64_reflect(acc, gated);
        }

        acc ^= gated;
        i += 1;
    }

    acc
}

// block128.rs:794-811: the accumulator is split into
// two u64 halves; the packed view carries the invariant.
fn map_ct_128_split_twin(x: u128, basis: &[u128; 128]) -> (r: u128)
    ensures r as nat == bit_comb(x as nat, basis@.map_values(|v: u128| v as nat), 128)
{
    let ghost s = basis@.map_values(|v: u128| v as nat);

    let mut acc_lo: u64 = 0;
    let mut acc_hi: u64 = 0;
    let mut i: usize = 0;

    proof {
        assert(((0u64 as u128) | ((0u64 as u128) << 64)) == 0) by (bit_vector);
    }

    while i < 128
        invariant
            i <= 128,
            s == basis@.map_values(|v: u128| v as nat),
            (((acc_lo as u128) | ((acc_hi as u128) << 64)) as nat)
                == bit_comb(x as nat, s, i as nat),
        decreases 128 - i,
    {
        let bit = ((x >> i) & 1) as u64;
        let mask = 0u64.wrapping_sub(bit);
        let b = basis[i];

        let ghost old_lo = acc_lo;
        let ghost old_hi = acc_hi;

        proof {
            bit_gate_u128(x, i as u128);

            assert((x >> (i as u128)) == (x >> i)) by (bit_vector) requires i < 128usize;

            // The split masked update is the packed
            // update by the duplicated mask.
            let m = 0u64.wrapping_sub(bit);

            assert(((old_lo ^ ((b as u64) & m)) as u128)
                | (((old_hi ^ (((b >> 64) as u64) & m)) as u128) << 64)
                == ((old_lo as u128) | ((old_hi as u128) << 64))
                    ^ (b & ((m as u128) | ((m as u128) << 64)))) by (bit_vector);
            assert(b & ((m as u128) | ((m as u128) << 64))
                == (if bit == 1 { b } else { 0u128 })) by (bit_vector)
                requires m == 0u64.wrapping_sub(bit), bit < 2u64;
            assert(s[i as int] == basis[i as int] as nat);

            xor128_reflect(
                (old_lo as u128) | ((old_hi as u128) << 64),
                b & ((m as u128) | ((m as u128) << 64)),
            );
        }

        acc_lo ^= (b as u64) & mask;
        acc_hi ^= ((b >> 64) as u64) & mask;
        i += 1;
    }

    (acc_lo as u128) | ((acc_hi as u128) << 64)
}

// lift_ct, block128.rs:815-827: the promote kernels' scalar
// core, same masked accumulation over the lifting basis.
fn lift_ct_twin(x: u64, basis: &[u128]) -> (r: u128)
    requires basis@.len() <= 64,
    ensures r as nat == bit_comb(x as nat, basis@.map_values(|v: u128| v as nat), basis@.len())
{
    let ghost s = basis@.map_values(|v: u128| v as nat);
    let n = basis.len();

    let mut acc: u128 = 0;
    let mut i: usize = 0;

    while i < n
        invariant
            i <= n,
            n == basis@.len() <= 64,
            s == basis@.map_values(|v: u128| v as nat),
            acc as nat == bit_comb(x as nat, s, i as nat),
        decreases n - i,
    {
        let bit = (x >> i) & 1;
        let mask = 0u128.wrapping_sub(bit as u128);
        let bv = basis[i];
        let gated = bv & mask;

        proof {
            bit_gate_u64(x, i as u64);

            assert(gated == (if bit == 1 { bv } else { 0u128 })) by (bit_vector)
                requires
                    gated == bv & (0u128.wrapping_sub(bit as u128)),
                    bit < 2u64;
            assert(s[i as int] == bv as nat);

            xor128_reflect(acc, gated);
        }

        acc ^= gated;
        i += 1;
    }

    acc
}

// ============================================================
// The non-pmull mul_hardware fallback, block128.rs:487-493:
// to_hardware(from_hardware(a) * from_hardware(b)).
// Also covers aarch64 without the `aes` feature.
// ============================================================

// On every value in φ's image the round-trip computes gf_mul;
// that the image is all of GF(2^128) is the mutual-inverse
// half of verify_isomorphism_128 (TRUSTED_AXIOMS.md).
pub proof fn fallback_mul_128_correct(x: nat, y: nat)
    requires
        in_field(x, 128),
        in_field(y, 128),
    ensures phi(
        gf_mul_tower(phi_inv(phi(x, 128), 128), phi_inv(phi(y, 128), 128), 128),
        128,
    ) == gf_mul(phi(x, 128), phi(y, 128), 128)
{
    phi_roundtrip(x, 128);
    phi_roundtrip(y, 128);
    phi_multiplicative(x, y, 128);
}

// ============================================================
// The flat-256 glue, block256.rs:426-447:
// pair-Karatsuba over the flat-128 field is the tower
// quadratic extension seen through φ, half by half.
// ============================================================

pub open spec fn mul_hardware_256_twin(
    a0: nat, a1: nat, b0: nat, b1: nat, tau_flat: nat,
) -> (nat, nat) {
    let v0 = gf_mul(a0, b0, 128);
    let v1 = gf_mul(a1, b1, 128);
    let v_sum = gf_mul(xor(a0, a1), xor(b0, b1), 128);

    (xor(v0, gf_mul(v1, tau_flat, 128)), xor(v0, v_sum))
}

proof fn tower_in_field(x: nat, y: nat)
    requires in_field(x, 128), in_field(y, 128),
    ensures in_field(gf_mul_tower(x, y, 128), 128)
{
    gf_mul_tower_bound(x, y, 128);
    deg_lt_conv(gf_mul_tower(x, y, 128), 128);
}

// p00 ^ (p00 ^ p01 ^ p10 ^ p11) == p01 ^ p10 ^ p11:
// the Karatsuba diagonal cancels.
proof fn karatsuba_cancel(p00: nat, p01: nat, p10: nat, p11: nat)
    ensures xor(p00, xor(xor(p00, p01), xor(p10, p11))) == xor(xor(p01, p10), p11)
{
    xor_assoc(p00, p01, xor(p10, p11));
    xor_assoc(p00, p00, xor(p01, xor(p10, p11)));
    xor_self(p00);
    xor_zero(xor(p01, xor(p10, p11)));
    xor_assoc(p01, p10, p11);
}

proof fn quad_hi_half(x0: nat, x1: nat, y0: nat, y1: nat)
    requires
        in_field(x0, 128),
        in_field(x1, 128),
        in_field(y0, 128),
        in_field(y1, 128),
    ensures xor(
        gf_mul(phi(x0, 128), phi(y0, 128), 128),
        gf_mul(
            xor(phi(x0, 128), phi(x1, 128)),
            xor(phi(y0, 128), phi(y1, 128)),
            128,
        ),
    ) == phi(thi(x0, x1, y0, y1, 128), 128)
{
    let xs = xor(x0, x1);
    let ys = xor(y0, y1);
    let p00 = gf_mul_tower(x0, y0, 128);
    let p01 = gf_mul_tower(x0, y1, 128);
    let p10 = gf_mul_tower(x1, y0, 128);
    let p11 = gf_mul_tower(x1, y1, 128);

    deg_xor_lt(x0, x1, 128);
    deg_xor_lt(y0, y1, 128);
    phi_additive(x0, x1, 128);
    phi_additive(y0, y1, 128);
    phi_multiplicative(x0, y0, 128);
    phi_multiplicative(xs, ys, 128);

    // v_sum's tower pre-image expands to all four products
    gf_mul_tower_distrib_l(x0, x1, ys, 128);
    gf_mul_tower_distrib_r(x0, y0, y1, 128);
    gf_mul_tower_distrib_r(x1, y0, y1, 128);

    karatsuba_cancel(p00, p01, p10, p11);

    tower_in_field(x0, y0);
    tower_in_field(xs, ys);

    phi_additive(p00, gf_mul_tower(xs, ys, 128), 128);
}

proof fn quad_lo_half(x0: nat, x1: nat, y0: nat, y1: nat)
    requires
        in_field(x0, 128),
        in_field(x1, 128),
        in_field(y0, 128),
        in_field(y1, 128),
    ensures xor(
        gf_mul(phi(x0, 128), phi(y0, 128), 128),
        gf_mul(gf_mul(phi(x1, 128), phi(y1, 128), 128), phi(tau_tower(128), 128), 128),
    ) == phi(tlo(x0, x1, y0, y1, 128), 128)
{
    let p00 = gf_mul_tower(x0, y0, 128);
    let p11 = gf_mul_tower(x1, y1, 128);

    assert(in_field(tau_tower(128), 128)) by {
        assert(pow2(128) == 0x1_0000_0000_0000_0000_0000_0000_0000_0000) by (compute);

        deg_lt_conv(tau_tower(128), 128);
    }

    phi_multiplicative(x0, y0, 128);
    phi_multiplicative(x1, y1, 128);

    tower_in_field(x1, y1);

    phi_multiplicative(p11, tau_tower(128), 128);

    tower_in_field(x0, y0);
    tower_in_field(p11, tau_tower(128));

    phi_additive(p00, gf_mul_tower(p11, tau_tower(128), 128), 128);
}

// With TAU_FLAT == φ(tau_tower(128)), the build-checked constant
// row, the production Karatsuba computes φ(tlo), φ(thi) of the
// tower halves: the pair extension is the image of the tower field.
pub proof fn mul_hardware_256_correct(x0: nat, x1: nat, y0: nat, y1: nat)
    requires
        in_field(x0, 128),
        in_field(x1, 128),
        in_field(y0, 128),
        in_field(y1, 128),
    ensures ({
        let r = mul_hardware_256_twin(
            phi(x0, 128), phi(x1, 128), phi(y0, 128), phi(y1, 128),
            phi(tau_tower(128), 128),
        );

        r.0 == phi(tlo(x0, x1, y0, y1, 128), 128) && r.1 == phi(thi(x0, x1, y0, y1, 128), 128)
    })
{
    quad_lo_half(x0, x1, y0, y1);
    quad_hi_half(x0, x1, y0, y1);
}

fn main() {
}

} // verus!
