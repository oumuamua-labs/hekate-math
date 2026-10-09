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

//! Executable twins of the `neon_t.rs` rows, each
//! proven equal to its row; `verus/exec/rows.rs`
//! runs them against the intrinsics.

use vstd::prelude::*;

#[cfg(verus_keep_ghost)]
#[path = "neon_t.rs"]
pub mod neon_t;

#[cfg(verus_keep_ghost)]
use neon_t::{
    bytes16, bytes32, bytes64, clmul8_lane, hi64, lanes16, lanes32, lanes64, lanes64_u128, lo64,
    u128_bytes, u128_lanes64, vand_m8, vcombine_m8, vdup_m8, vdupq_n_p64_m, veor_m8, veor_m16,
    veor_m64, vextq_m, vget_high_m8, vget_low_m8, vmovn_m16, vmull_high_p64_m, vmull_p8_m,
    vmull_p64_m, vqtbl1_m, vshl_m16, vshr_m8, vshr_m16, vtrn1_m, vtrn2_m, vuzp1_m, vuzp2_m,
};

verus! {

// ============================================================
// PMULL
// ============================================================

pub fn vmull_p64_x(a: u64, b: u64) -> (r: u128)
    ensures r == vmull_p64_m(a, b)
    decreases a
{
    if a == 0 {
        0
    } else {
        let low: u128 = if a % 2 == 1 { b as u128 } else { 0 };

        low ^ (vmull_p64_x(a / 2, b) << 1)
    }
}

pub fn clmul8_lane_x(a: u8, b: u8) -> (r: u16)
    ensures r == clmul8_lane(a, b)
    decreases a
{
    if a == 0 {
        0
    } else {
        let low: u16 = if a % 2 == 1 { b as u16 } else { 0 };

        low ^ (clmul8_lane_x(a / 2, b) << 1)
    }
}

pub fn vmull_p8_x(a: &[u8], b: &[u8]) -> (r: Vec<u16>)
    requires
        a.len() == 8,
        b.len() == 8,
    ensures r@ == vmull_p8_m(a@, b@)
{
    let mut r: Vec<u16> = Vec::new();
    let mut i = 0;

    while i < 8
        invariant
            i <= 8,
            a.len() == 8,
            b.len() == 8,
            r@.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j] == clmul8_lane(a@[j], b@[j]),
        decreases 8 - i
    {
        r.push(clmul8_lane_x(a[i], b[i]));
        i += 1;
    }

    assert(r@ =~= vmull_p8_m(a@, b@));

    r
}

pub fn vmull_high_p64_x(a: u128, b: u128) -> (r: u128)
    ensures r == vmull_high_p64_m(a, b)
{
    vmull_p64_x(hi64_x(a), hi64_x(b))
}

// ============================================================
// Lane-wise logic and shifts
// ============================================================

pub fn veor_x8(a: &[u8], b: &[u8]) -> (r: Vec<u8>)
    requires a.len() == b.len()
    ensures r@ == veor_m8(a@, b@)
{
    let mut r: Vec<u8> = Vec::new();
    let mut i = 0;

    while i < a.len()
        invariant
            i <= a.len(),
            a.len() == b.len(),
            r@.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j] == a@[j] ^ b@[j],
        decreases a.len() - i
    {
        r.push(a[i] ^ b[i]);
        i += 1;
    }

    assert(r@ =~= veor_m8(a@, b@));

    r
}

pub fn veor_x16(a: &[u16], b: &[u16]) -> (r: Vec<u16>)
    requires a.len() == b.len()
    ensures r@ == veor_m16(a@, b@)
{
    let mut r: Vec<u16> = Vec::new();
    let mut i = 0;

    while i < a.len()
        invariant
            i <= a.len(),
            a.len() == b.len(),
            r@.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j] == a@[j] ^ b@[j],
        decreases a.len() - i
    {
        r.push(a[i] ^ b[i]);
        i += 1;
    }

    assert(r@ =~= veor_m16(a@, b@));

    r
}

pub fn veor_x64(a: &[u64], b: &[u64]) -> (r: Vec<u64>)
    requires a.len() == b.len()
    ensures r@ == veor_m64(a@, b@)
{
    let mut r: Vec<u64> = Vec::new();
    let mut i = 0;

    while i < a.len()
        invariant
            i <= a.len(),
            a.len() == b.len(),
            r@.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j] == a@[j] ^ b@[j],
        decreases a.len() - i
    {
        r.push(a[i] ^ b[i]);
        i += 1;
    }

    assert(r@ =~= veor_m64(a@, b@));

    r
}

pub fn vand_x8(a: &[u8], b: &[u8]) -> (r: Vec<u8>)
    requires a.len() == b.len()
    ensures r@ == vand_m8(a@, b@)
{
    let mut r: Vec<u8> = Vec::new();
    let mut i = 0;

    while i < a.len()
        invariant
            i <= a.len(),
            a.len() == b.len(),
            r@.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j] == a@[j] & b@[j],
        decreases a.len() - i
    {
        r.push(a[i] & b[i]);
        i += 1;
    }

    assert(r@ =~= vand_m8(a@, b@));

    r
}

pub fn vshl_x16(a: &[u16], n: u16) -> (r: Vec<u16>)
    requires n < 16
    ensures r@ == vshl_m16(a@, n)
{
    let mut r: Vec<u16> = Vec::new();
    let mut i = 0;

    while i < a.len()
        invariant
            i <= a.len(),
            n < 16,
            r@.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j] == a@[j] << n,
        decreases a.len() - i
    {
        r.push(a[i] << n);
        i += 1;
    }

    assert(r@ =~= vshl_m16(a@, n));

    r
}

pub fn vshr_x16(a: &[u16], n: u16) -> (r: Vec<u16>)
    requires n < 16
    ensures r@ == vshr_m16(a@, n)
{
    let mut r: Vec<u16> = Vec::new();
    let mut i = 0;

    while i < a.len()
        invariant
            i <= a.len(),
            n < 16,
            r@.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j] == a@[j] >> n,
        decreases a.len() - i
    {
        r.push(a[i] >> n);
        i += 1;
    }

    assert(r@ =~= vshr_m16(a@, n));

    r
}

pub fn vshr_x8(a: &[u8], n: u8) -> (r: Vec<u8>)
    requires n < 8
    ensures r@ == vshr_m8(a@, n)
{
    let mut r: Vec<u8> = Vec::new();
    let mut i = 0;

    while i < a.len()
        invariant
            i <= a.len(),
            n < 8,
            r@.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j] == a@[j] >> n,
        decreases a.len() - i
    {
        r.push(a[i] >> n);
        i += 1;
    }

    assert(r@ =~= vshr_m8(a@, n));

    r
}

// ============================================================
// Moves, narrowing, table lookup, permutes
// ============================================================

pub fn vdup_x8(x: u8, lanes: usize) -> (r: Vec<u8>)
    ensures r@ == vdup_m8(x, lanes as nat)
{
    let mut r: Vec<u8> = Vec::new();
    let mut i = 0;

    while i < lanes
        invariant
            i <= lanes,
            r@.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j] == x,
        decreases lanes - i
    {
        r.push(x);
        i += 1;
    }

    assert(r@ =~= vdup_m8(x, lanes as nat));

    r
}

pub fn vdupq_n_p64_x(x: u64) -> (r: u128)
    ensures r == vdupq_n_p64_m(x)
{
    (x as u128) | ((x as u128) << 64)
}

pub fn vmovn_x16(a: &[u16]) -> (r: Vec<u8>)
    ensures r@ == vmovn_m16(a@)
{
    let mut r: Vec<u8> = Vec::new();
    let mut i = 0;

    while i < a.len()
        invariant
            i <= a.len(),
            r@.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j] == a@[j] as u8,
        decreases a.len() - i
    {
        r.push(a[i] as u8);
        i += 1;
    }

    assert(r@ =~= vmovn_m16(a@));

    r
}

pub fn vqtbl1_x(t: &[u8], idx: &[u8]) -> (r: Vec<u8>)
    requires t.len() == 16
    ensures r@ == vqtbl1_m(t@, idx@)
{
    let mut r: Vec<u8> = Vec::new();
    let mut i = 0;

    while i < idx.len()
        invariant
            i <= idx.len(),
            t.len() == 16,
            r@.len() == i,
            forall|j: int|
                0 <= j < i ==> r@[j] == if idx@[j] < 16 { t@[idx@[j] as int] } else { 0 },
        decreases idx.len() - i
    {
        let v = if idx[i] < 16 { t[idx[i] as usize] } else { 0 };

        r.push(v);
        i += 1;
    }

    assert(r@ =~= vqtbl1_m(t@, idx@));

    r
}

pub fn vget_low_x8(a: &[u8]) -> (r: Vec<u8>)
    requires a.len() == 16
    ensures r@ == vget_low_m8(a@)
{
    let mut r: Vec<u8> = Vec::new();
    let mut i = 0;

    while i < 8
        invariant
            i <= 8,
            a.len() == 16,
            r@.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j] == a@[j],
        decreases 8 - i
    {
        r.push(a[i]);
        i += 1;
    }

    assert(r@ =~= vget_low_m8(a@));

    r
}

pub fn vget_high_x8(a: &[u8]) -> (r: Vec<u8>)
    requires a.len() == 16
    ensures r@ == vget_high_m8(a@)
{
    let mut r: Vec<u8> = Vec::new();
    let mut i = 8;

    while i < 16
        invariant
            8 <= i <= 16,
            a.len() == 16,
            r@.len() == i - 8,
            forall|j: int| 0 <= j < i - 8 ==> r@[j] == a@[j + 8],
        decreases 16 - i
    {
        r.push(a[i]);
        i += 1;
    }

    assert(r@ =~= vget_high_m8(a@));

    r
}

pub fn vcombine_x8(lo: &[u8], hi: &[u8]) -> (r: Vec<u8>)
    ensures r@ == vcombine_m8(lo@, hi@)
{
    let mut r: Vec<u8> = Vec::new();
    let mut i = 0;

    while i < lo.len()
        invariant
            i <= lo.len(),
            r@ =~= lo@.subrange(0, i as int),
        decreases lo.len() - i
    {
        r.push(lo[i]);
        i += 1;
    }

    let mut k = 0;

    while k < hi.len()
        invariant
            k <= hi.len(),
            r@ =~= lo@ + hi@.subrange(0, k as int),
        decreases hi.len() - k
    {
        r.push(hi[k]);
        k += 1;
    }

    assert(hi@.subrange(0, hi.len() as int) =~= hi@);

    r
}

pub fn vextq_x(a: u128, b: u128, n: u8) -> (r: u128)
    requires n < 16
    ensures r == vextq_m(a, b, n as nat)
{
    if n == 0 {
        a
    } else {
        let s = 8 * (n as u128);

        assert((8 * (n as nat)) as u128 == s);
        assert((128 - 8 * (n as nat)) as u128 == 128 - s);

        (a >> s) | (b << (128 - s))
    }
}

pub fn vtrn1_x<T: Copy>(a: &[T], b: &[T]) -> (r: Vec<T>)
    requires
        a.len() == b.len(),
        a.len() % 2 == 0,
    ensures r@ == vtrn1_m(a@, b@)
{
    let mut r: Vec<T> = Vec::new();
    let mut i = 0;

    while i < a.len()
        invariant
            i <= a.len(),
            a.len() == b.len(),
            a.len() % 2 == 0,
            r@.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j] == if j % 2 == 0 { a@[j] } else { b@[j - 1] },
        decreases a.len() - i
    {
        let v = if i % 2 == 0 { a[i] } else { b[i - 1] };

        r.push(v);
        i += 1;
    }

    assert(r@ =~= vtrn1_m(a@, b@));

    r
}

pub fn vtrn2_x<T: Copy>(a: &[T], b: &[T]) -> (r: Vec<T>)
    requires
        a.len() == b.len(),
        a.len() % 2 == 0,
    ensures r@ == vtrn2_m(a@, b@)
{
    let mut r: Vec<T> = Vec::new();
    let mut i = 0;

    while i < a.len()
        invariant
            i <= a.len(),
            a.len() == b.len(),
            a.len() % 2 == 0,
            r@.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j] == if j % 2 == 0 { a@[j + 1] } else { b@[j] },
        decreases a.len() - i
    {
        let v = if i % 2 == 0 { a[i + 1] } else { b[i] };

        r.push(v);
        i += 1;
    }

    assert(r@ =~= vtrn2_m(a@, b@));

    r
}

pub fn vuzp1_x<T: Copy>(a: &[T], b: &[T]) -> (r: Vec<T>)
    requires
        a.len() == b.len(),
        a.len() % 2 == 0,
        a.len() <= 16,
    ensures r@ == vuzp1_m(a@, b@)
{
    let mut r: Vec<T> = Vec::new();
    let mut i = 0;

    while i < a.len()
        invariant
            i <= a.len(),
            a.len() == b.len(),
            a.len() % 2 == 0,
            a.len() <= 16,
            r@.len() == i,
            forall|j: int|
                0 <= j < i ==> r@[j] == if 2 * j < a.len() { a@[2 * j] } else { b@[2 * j - a.len()] },
        decreases a.len() - i
    {
        let v = if 2 * i < a.len() { a[2 * i] } else { b[2 * i - a.len()] };

        r.push(v);
        i += 1;
    }

    assert(r@ =~= vuzp1_m(a@, b@));

    r
}

pub fn vuzp2_x<T: Copy>(a: &[T], b: &[T]) -> (r: Vec<T>)
    requires
        a.len() == b.len(),
        a.len() % 2 == 0,
        a.len() <= 16,
    ensures r@ == vuzp2_m(a@, b@)
{
    let mut r: Vec<T> = Vec::new();
    let mut i = 0;

    while i < a.len()
        invariant
            i <= a.len(),
            a.len() == b.len(),
            a.len() % 2 == 0,
            a.len() <= 16,
            r@.len() == i,
            forall|j: int|
                0 <= j < i ==> r@[j] == if 2 * j + 1 < a.len() {
                    a@[2 * j + 1]
                } else {
                    b@[2 * j + 1 - a.len()]
                },
        decreases a.len() - i
    {
        let v = if 2 * i + 1 < a.len() { a[2 * i + 1] } else { b[2 * i + 1 - a.len()] };

        r.push(v);
        i += 1;
    }

    assert(r@ =~= vuzp2_m(a@, b@));

    r
}

// ============================================================
// The little-endian transmute view
// ============================================================

pub fn lo64_x(x: u128) -> (r: u64)
    ensures r == lo64(x)
{
    x as u64
}

pub fn hi64_x(x: u128) -> (r: u64)
    ensures r == hi64(x)
{
    (x >> 64) as u64
}

pub fn u128_lanes64_x(x: u128) -> (r: Vec<u64>)
    ensures r@ == u128_lanes64(x)
{
    let r = vec![lo64_x(x), hi64_x(x)];

    assert(r@ =~= u128_lanes64(x));

    r
}

pub fn lanes64_u128_x(s: &[u64]) -> (r: u128)
    requires s.len() == 2
    ensures r == lanes64_u128(s@)
{
    (s[0] as u128) | ((s[1] as u128) << 64)
}

pub fn u128_bytes_x(x: u128) -> (r: Vec<u8>)
    ensures r@ == u128_bytes(x)
{
    let mut r: Vec<u8> = Vec::new();
    let mut i: u128 = 0;

    while i < 16
        invariant
            i <= 16,
            r@.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j] == (x >> ((8 * j) as u128)) as u8,
        decreases 16 - i
    {
        r.push((x >> (8 * i)) as u8);
        i += 1;
    }

    assert(r@ =~= u128_bytes(x));

    r
}

pub fn lanes16_x(v: &[u8]) -> (r: Vec<u16>)
    ensures r@ == lanes16(v@)
{
    let mut r: Vec<u16> = Vec::new();
    let mut l = 0;

    while l < v.len() / 2
        invariant
            l <= v.len() / 2,
            r@.len() == l,
            forall|j: int|
                0 <= j < l ==> r@[j] == (v@[2 * j] as u16) | ((v@[2 * j + 1] as u16) << 8),
        decreases v.len() / 2 - l
    {
        r.push((v[2 * l] as u16) | ((v[2 * l + 1] as u16) << 8));
        l += 1;
    }

    assert(r@ =~= lanes16(v@));

    r
}

pub fn lanes32_x(v: &[u8]) -> (r: Vec<u32>)
    ensures r@ == lanes32(v@)
{
    let mut r: Vec<u32> = Vec::new();
    let mut l = 0;

    while l < v.len() / 4
        invariant
            l <= v.len() / 4,
            r@.len() == l,
            forall|j: int|
                0 <= j < l ==> r@[j] == (v@[4 * j] as u32) | ((v@[4 * j + 1] as u32) << 8)
                    | ((v@[4 * j + 2] as u32) << 16) | ((v@[4 * j + 3] as u32) << 24),
        decreases v.len() / 4 - l
    {
        r.push(
            (v[4 * l] as u32) | ((v[4 * l + 1] as u32) << 8) | ((v[4 * l + 2] as u32) << 16)
                | ((v[4 * l + 3] as u32) << 24),
        );
        l += 1;
    }

    assert(r@ =~= lanes32(v@));

    r
}

pub fn lanes64_x(v: &[u8]) -> (r: Vec<u64>)
    ensures r@ == lanes64(v@)
{
    let mut r: Vec<u64> = Vec::new();
    let mut l = 0;

    while l < v.len() / 8
        invariant
            l <= v.len() / 8,
            r@.len() == l,
            forall|j: int|
                0 <= j < l ==> r@[j] == (v@[8 * j] as u64) | ((v@[8 * j + 1] as u64) << 8)
                    | ((v@[8 * j + 2] as u64) << 16) | ((v@[8 * j + 3] as u64) << 24)
                    | ((v@[8 * j + 4] as u64) << 32) | ((v@[8 * j + 5] as u64) << 40)
                    | ((v@[8 * j + 6] as u64) << 48) | ((v@[8 * j + 7] as u64) << 56),
        decreases v.len() / 8 - l
    {
        r.push(
            (v[8 * l] as u64) | ((v[8 * l + 1] as u64) << 8) | ((v[8 * l + 2] as u64) << 16)
                | ((v[8 * l + 3] as u64) << 24) | ((v[8 * l + 4] as u64) << 32)
                | ((v[8 * l + 5] as u64) << 40) | ((v[8 * l + 6] as u64) << 48)
                | ((v[8 * l + 7] as u64) << 56),
        );
        l += 1;
    }

    assert(r@ =~= lanes64(v@));

    r
}

pub fn bytes16_x(s: &[u16]) -> (r: Vec<u8>)
    requires s.len() <= 8
    ensures r@ == bytes16(s@)
{
    let mut r: Vec<u8> = Vec::new();
    let mut i = 0;

    while i < 2 * s.len()
        invariant
            s.len() <= 8,
            i <= 2 * s.len(),
            r@.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j] == (s@[j / 2] >> ((8 * (j % 2)) as u16)) as u8,
        decreases 2 * s.len() - i
    {
        r.push((s[i / 2] >> (8 * (i % 2)) as u16) as u8);
        i += 1;
    }

    assert(r@ =~= bytes16(s@));

    r
}

pub fn bytes32_x(s: &[u32]) -> (r: Vec<u8>)
    requires s.len() <= 4
    ensures r@ == bytes32(s@)
{
    let mut r: Vec<u8> = Vec::new();
    let mut i = 0;

    while i < 4 * s.len()
        invariant
            s.len() <= 4,
            i <= 4 * s.len(),
            r@.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j] == (s@[j / 4] >> ((8 * (j % 4)) as u32)) as u8,
        decreases 4 * s.len() - i
    {
        r.push((s[i / 4] >> (8 * (i % 4)) as u32) as u8);
        i += 1;
    }

    assert(r@ =~= bytes32(s@));

    r
}

pub fn bytes64_x(s: &[u64]) -> (r: Vec<u8>)
    requires s.len() <= 2
    ensures r@ == bytes64(s@)
{
    let mut r: Vec<u8> = Vec::new();
    let mut i = 0;

    while i < 8 * s.len()
        invariant
            s.len() <= 2,
            i <= 8 * s.len(),
            r@.len() == i,
            forall|j: int| 0 <= j < i ==> r@[j] == (s@[j / 8] >> ((8 * (j % 8)) as u64)) as u8,
        decreases 8 * s.len() - i
    {
        r.push((s[i / 8] >> (8 * (i % 8)) as u64) as u8);
        i += 1;
    }

    assert(r@ =~= bytes64(s@));

    r
}

fn main() {
}

}
