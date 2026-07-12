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

//! Per-instruction model of the aarch64 NEON surface the flat
//! path uses. Definitions only, zero proof content: every spec
//! fn transcribes one instruction's operation from the Arm ARM
//! (DDI 0487, A-profile). The tie to real silicon is dynamic,
//! `tests/neon_differential.rs`, and every row is trusted, per
//! TRUSTED_AXIOMS.md. Vectors are lane Seqs, lane 0 first; the
//! `u128`/lane-array transmute view is little-endian (AAPCS64,
//! `aarch64_be` unsupported).

use vstd::prelude::*;

verus! {

// ============================================================
// PMULL: polynomial (carry-less) multiply
// ============================================================

// PMULL Vd.1Q, Vn.1D, Vm.1D (vmull_p64), DDI 0487 C7.2.246:
// 64×64 → 128 product over GF(2)[x], low-bit recursion.
pub open spec fn vmull_p64_m(a: u64, b: u64) -> u128
    decreases a
{
    if a == 0 {
        0
    } else {
        (if a % 2 == 1 { b as u128 } else { 0 }) ^ (vmull_p64_m(a / 2, b) << 1)
    }
}

// One lane of PMULL Vd.8H: 8×8 → 16 over GF(2)[x].
pub open spec fn clmul8_lane(a: u8, b: u8) -> u16
    decreases a
{
    if a == 0 {
        0
    } else {
        (if a % 2 == 1 { b as u16 } else { 0 }) ^ (clmul8_lane(a / 2, b) << 1)
    }
}

// PMULL Vd.8H, Vn.8B, Vm.8B (vmull_p8), DDI 0487 C7.2.246.
pub open spec fn vmull_p8_m(a: Seq<u8>, b: Seq<u8>) -> Seq<u16> {
    Seq::new(8, |i: int| clmul8_lane(a[i], b[i]))
}

// ============================================================
// Lane-wise logic and shifts
// ============================================================

// EOR Vd.16B (veor/veorq), DDI 0487 C7.2.126.
pub open spec fn veor_m8(a: Seq<u8>, b: Seq<u8>) -> Seq<u8> {
    Seq::new(a.len(),|i: int| a[i] ^ b[i])
}

pub open spec fn veor_m16(a: Seq<u16>, b: Seq<u16>) -> Seq<u16> {
    Seq::new(a.len(),|i: int| a[i] ^ b[i])
}

// AND Vd.16B (vand/vandq), DDI 0487 C7.2.10.
pub open spec fn vand_m8(a: Seq<u8>, b: Seq<u8>) -> Seq<u8> {
    Seq::new(a.len(),|i: int| a[i] & b[i])
}

// SHL Vd.8H, #n (vshlq_n_u16), DDI 0487 C7.2.315: truncating.
pub open spec fn vshl_m16(a: Seq<u16>, n: u16) -> Seq<u16> {
    Seq::new(a.len(),|i: int| a[i] << n)
}

// USHR Vd.8H, #n (vshrq_n_u16), DDI 0487 C7.2.416.
pub open spec fn vshr_m16(a: Seq<u16>, n: u16) -> Seq<u16> {
    Seq::new(a.len(),|i: int| a[i] >> n)
}

// USHR Vd.8B / Vd.16B, #n (vshr_n_u8 / vshrq_n_u8).
pub open spec fn vshr_m8(a: Seq<u8>, n: u8) -> Seq<u8> {
    Seq::new(a.len(),|i: int| a[i] >> n)
}

// ============================================================
// Moves, narrowing, table lookup, permutes
// ============================================================

// DUP Vd.16B, Wn (vdup_n_u8 / vdupq_n_u8), DDI 0487 C7.2.39.
pub open spec fn vdup_m8(x: u8, lanes: nat) -> Seq<u8> {
    Seq::new(lanes, |_i: int| x)
}

// XTN Vd.8B, Vn.8H (vmovn_u16), DDI 0487 C7.2.435: per-lane
// truncate to the low byte.
pub open spec fn vmovn_m16(a: Seq<u16>) -> Seq<u8> {
    Seq::new(a.len(),|i: int| a[i] as u8)
}

// TBL Vd.8B, {Vn.16B}, Vm.8B (vqtbl1_u8), DDI 0487 C7.2.358:
// index < 16 selects, out-of-range yields 0.
pub open spec fn vqtbl1_m(t: Seq<u8>, idx: Seq<u8>) -> Seq<u8> {
    Seq::new(idx.len(), |i: int| if idx[i] < 16 { t[idx[i] as int] } else { 0 })
}

// vget_low_u8 / vget_high_u8: 128-bit register halves.
pub open spec fn vget_low_m8(a: Seq<u8>) -> Seq<u8> {
    a.subrange(0, 8)
}

pub open spec fn vget_high_m8(a: Seq<u8>) -> Seq<u8> {
    a.subrange(8, 16)
}

// vcombine_u8: low half first (little-endian lane order).
pub open spec fn vcombine_m8(lo: Seq<u8>, hi: Seq<u8>) -> Seq<u8> {
    lo + hi
}

// TRN1/TRN2 Vd.16B (vtrn1q/vtrn2q), DDI 0487 C7.2.367-368:
// interleave even (TRN1) or odd (TRN2) lanes of the pair.
pub open spec fn vtrn1_m<T>(a: Seq<T>, b: Seq<T>) -> Seq<T> {
    Seq::new(a.len(),|i: int| if i % 2 == 0 { a[i] } else { b[i - 1] })
}

pub open spec fn vtrn2_m<T>(a: Seq<T>, b: Seq<T>) -> Seq<T> {
    Seq::new(a.len(),|i: int| if i % 2 == 0 { a[i + 1] } else { b[i] })
}

// UZP1/UZP2 Vd.16B (vuzp1q/vuzp2q), DDI 0487 C7.2.425-426:
// concatenate, then take even (UZP1) or odd (UZP2) lanes.
pub open spec fn vuzp1_m<T>(a: Seq<T>, b: Seq<T>) -> Seq<T> {
    Seq::new(a.len(),|i: int| if 2 * i < a.len() { a[2 * i] } else { b[2 * i - a.len()] })
}

pub open spec fn vuzp2_m<T>(a: Seq<T>, b: Seq<T>) -> Seq<T> {
    Seq::new(
        a.len(),
        |i: int| if 2 * i + 1 < a.len() { a[2 * i + 1] } else { b[2 * i + 1 - a.len()] },
    )
}

// ============================================================
// The little-endian transmute view (AAPCS64)
// ============================================================

// u128 <-> uint64x2_t: vgetq_lane_u64(transmute(x), 0) is the
// low 64 bits, lane 1 the high.
pub open spec fn lo64(x: u128) -> u64 {
    x as u64
}

pub open spec fn hi64(x: u128) -> u64 {
    (x >> 64) as u64
}

// u16 ↔ byte pair inside a lane: low byte first.
pub open spec fn lo8(x: u16) -> u8 {
    x as u8
}

pub open spec fn hi8(x: u16) -> u8 {
    (x >> 8) as u8
}

fn main() {
}

} // verus!