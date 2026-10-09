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

use super::neon_exec::{
    bytes16_x, bytes32_x, bytes64_x, hi64_x, lanes16_x, lanes32_x, lanes64_u128_x, lanes64_x,
    lo64_x, u128_bytes_x, u128_lanes64_x, vand_x8, vcombine_x8, vdup_x8, vdupq_n_p64_x, veor_x8,
    veor_x16, veor_x64, vextq_x, vget_high_x8, vget_low_x8, vmovn_x16, vmull_high_p64_x,
    vmull_p8_x, vmull_p64_x, vqtbl1_x, vshl_x16, vshr_x8, vshr_x16, vtrn1_x, vtrn2_x, vuzp1_x,
    vuzp2_x,
};
use core::arch::aarch64::*;
use core::mem::transmute;
use rand::{RngExt, SeedableRng, rngs::StdRng};

const EDGES: [u64; 11] = [
    0,
    1,
    u64::MAX,
    1 << 63,
    1 << 32,
    0x5555_5555_5555_5555,
    0xAAAA_AAAA_AAAA_AAAA,
    0x1b,
    0x2b,
    0x8d,
    0x87,
];

const RANDOM: usize = 4096;

macro_rules! register_views {
    ($($name:ident: $from:ty => $to:ty;)*) => {
        $(
            fn $name(x: $from) -> $to {
                unsafe { transmute::<$from, $to>(x) }
            }
        )*
    };
}

macro_rules! ext_cases {
    ($a:expr, $b:expr, $($n:literal)*) => {
        $(
            let got = unsafe {
                of_q8(vextq_u8::<$n>(q8($a.to_ne_bytes()), q8($b.to_ne_bytes())))
            };

            assert_eq!(
                u128::from_ne_bytes(got),
                vextq_x($a, $b, $n),
                "EXT #{} {:#x} {:#x}",
                $n,
                $a,
                $b
            );
        )*
    };
}

register_views! {
    q8: [u8; 16] => uint8x16_t;
    of_q8: uint8x16_t => [u8; 16];
    d8: [u8; 8] => uint8x8_t;
    of_d8: uint8x8_t => [u8; 8];
    q16: [u16; 8] => uint16x8_t;
    of_q16: uint16x8_t => [u16; 8];
    q32: [u32; 4] => uint32x4_t;
    of_q32: uint32x4_t => [u32; 4];
    q64: [u64; 2] => uint64x2_t;
    of_q64: uint64x2_t => [u64; 2];
    p8: [u8; 8] => poly8x8_t;
    of_p16: poly16x8_t => [u16; 8];
    p64: u128 => poly64x2_t;
    of_p64: poly64x2_t => u128;
}

fn u16s(x: u128) -> [u16; 8] {
    core::array::from_fn(|i| (x >> (16 * i)) as u16)
}

fn u32s(x: u128) -> [u32; 4] {
    core::array::from_fn(|i| (x >> (32 * i)) as u32)
}

fn u64s(x: u128) -> [u64; 2] {
    [x as u64, (x >> 64) as u64]
}

fn registers() -> Vec<u128> {
    let mut rng = StdRng::seed_from_u64(0x6e65_6f6e);

    let edges = EDGES.iter().flat_map(|&lo| {
        EDGES
            .iter()
            .map(move |&hi| u128::from(lo) | u128::from(hi) << 64)
    });

    let random = (0..RANDOM).map(|_| rng.random::<u128>());

    edges.chain(random).collect()
}

fn pairs() -> Vec<(u128, u128)> {
    let regs = registers();
    let edge_grid = EDGES.len() * EDGES.len();
    let random = &regs[edge_grid..];

    regs.iter()
        .flat_map(|&a| regs.iter().take(edge_grid).map(move |&b| (a, b)))
        .chain(random.windows(2).map(|w| (w[0], w[1])))
        .collect()
}

#[test]
fn pmull_matches_its_rows() {
    for (a, b) in pairs() {
        let (a0, b0) = (lo64_x(a), lo64_x(b));
        let (a8, b8) = (a0.to_ne_bytes(), b0.to_ne_bytes());

        let (lo, hi, lanes) = unsafe {
            (
                vmull_p64(a0, b0),
                vmull_high_p64(p64(a), p64(b)),
                of_p16(vmull_p8(p8(a8), p8(b8))),
            )
        };

        assert_eq!(lo, vmull_p64_x(a0, b0), "PMULL {a:#x} {b:#x}");
        assert_eq!(hi, vmull_high_p64_x(a, b), "PMULL2 {a:#x} {b:#x}");
        assert_eq!(
            lanes.to_vec(),
            vmull_p8_x(&a8, &b8),
            "PMULL.8H {a0:#x} {b0:#x}"
        );
    }
}

#[test]
fn logic_matches_its_rows() {
    for (a, b) in pairs() {
        let (a8, b8) = (a.to_ne_bytes(), b.to_ne_bytes());
        let (a16, b16) = (u16s(a), u16s(b));
        let (a64, b64) = (u64s(a), u64s(b));
        let (l8, m8) = (lo64_x(a).to_ne_bytes(), lo64_x(b).to_ne_bytes());

        let (eor8, eor16, eor64, and8, eor8x8, and8x8) = unsafe {
            (
                of_q8(veorq_u8(q8(a8), q8(b8))),
                of_q16(veorq_u16(q16(a16), q16(b16))),
                of_q64(veorq_u64(q64(a64), q64(b64))),
                of_q8(vandq_u8(q8(a8), q8(b8))),
                of_d8(veor_u8(d8(l8), d8(m8))),
                of_d8(vand_u8(d8(l8), d8(m8))),
            )
        };

        assert_eq!(eor8.to_vec(), veor_x8(&a8, &b8), "EOR.16B {a:#x} {b:#x}");
        assert_eq!(eor16.to_vec(), veor_x16(&a16, &b16), "EOR.8H {a:#x} {b:#x}");
        assert_eq!(eor64.to_vec(), veor_x64(&a64, &b64), "EOR.2D {a:#x} {b:#x}");
        assert_eq!(and8.to_vec(), vand_x8(&a8, &b8), "AND.16B {a:#x} {b:#x}");
        assert_eq!(eor8x8.to_vec(), veor_x8(&l8, &m8), "EOR.8B {a:#x} {b:#x}");
        assert_eq!(and8x8.to_vec(), vand_x8(&l8, &m8), "AND.8B {a:#x} {b:#x}");
    }
}

#[test]
fn shifts_match_their_rows() {
    for a in registers() {
        let a8 = a.to_ne_bytes();
        let a16 = u16s(a);
        let l8 = lo64_x(a).to_ne_bytes();

        let (shl, shr, shr16b, shr8b) = unsafe {
            (
                [
                    of_q16(vshlq_n_u16::<1>(q16(a16))),
                    of_q16(vshlq_n_u16::<3>(q16(a16))),
                    of_q16(vshlq_n_u16::<5>(q16(a16))),
                    of_q16(vshlq_n_u16::<8>(q16(a16))),
                ],
                [
                    of_q16(vshrq_n_u16::<8>(q16(a16))),
                    of_q16(vshrq_n_u16::<11>(q16(a16))),
                    of_q16(vshrq_n_u16::<13>(q16(a16))),
                    of_q16(vshrq_n_u16::<15>(q16(a16))),
                ],
                of_q8(vshrq_n_u8::<4>(q8(a8))),
                of_d8(vshr_n_u8::<4>(d8(l8))),
            )
        };

        for (got, n) in shl.iter().zip([1, 3, 5, 8]) {
            assert_eq!(got.to_vec(), vshl_x16(&a16, n), "SHL.8H #{n} {a:#x}");
        }

        for (got, n) in shr.iter().zip([8, 11, 13, 15]) {
            assert_eq!(got.to_vec(), vshr_x16(&a16, n), "USHR.8H #{n} {a:#x}");
        }

        assert_eq!(shr16b.to_vec(), vshr_x8(&a8, 4), "USHR.16B #4 {a:#x}");
        assert_eq!(shr8b.to_vec(), vshr_x8(&l8, 4), "USHR.8B #4 {a:#x}");
    }
}

#[test]
fn moves_match_their_rows() {
    for a in registers() {
        let a8 = a.to_ne_bytes();
        let a16 = u16s(a);
        let x = a8[0];

        let (dup16b, dup8b, dup2d, narrow, low, high) = unsafe {
            (
                of_q8(vdupq_n_u8(x)),
                of_d8(vdup_n_u8(x)),
                of_p64(vdupq_n_p64(lo64_x(a))),
                of_d8(vmovn_u16(q16(a16))),
                of_d8(vget_low_u8(q8(a8))),
                of_d8(vget_high_u8(q8(a8))),
            )
        };

        let joined = unsafe { of_q8(vcombine_u8(d8(high), d8(low))) };

        assert_eq!(dup16b.to_vec(), vdup_x8(x, 16), "DUP.16B {x:#x}");
        assert_eq!(dup8b.to_vec(), vdup_x8(x, 8), "DUP.8B {x:#x}");
        assert_eq!(dup2d, vdupq_n_p64_x(lo64_x(a)), "DUP.2D {a:#x}");
        assert_eq!(narrow.to_vec(), vmovn_x16(&a16), "XTN.8B {a:#x}");
        assert_eq!(low.to_vec(), vget_low_x8(&a8), "vget_low {a:#x}");
        assert_eq!(high.to_vec(), vget_high_x8(&a8), "vget_high {a:#x}");
        assert_eq!(joined.to_vec(), vcombine_x8(&high, &low), "vcombine {a:#x}");
    }
}

#[test]
fn tbl_matches_its_row() {
    let identity: [u8; 16] = core::array::from_fn(|i| i as u8);
    let reversed: [u8; 16] = core::array::from_fn(|i| 15 - i as u8);

    let edge: [u8; 16] = [
        0, 15, 16, 17, 31, 32, 63, 64, 127, 128, 200, 254, 255, 8, 7, 1,
    ];

    for (a, b) in pairs() {
        let table = a.to_ne_bytes();

        for idx in [identity, reversed, edge, b.to_ne_bytes()] {
            let low: [u8; 8] = core::array::from_fn(|i| idx[i]);

            let (q, d) = unsafe {
                (
                    of_q8(vqtbl1q_u8(q8(table), q8(idx))),
                    of_d8(vqtbl1_u8(q8(table), d8(low))),
                )
            };

            assert_eq!(q.to_vec(), vqtbl1_x(&table, &idx), "TBL.16B {a:#x} {idx:?}");
            assert_eq!(d.to_vec(), vqtbl1_x(&table, &low), "TBL.8B {a:#x} {low:?}");
        }
    }
}

#[test]
fn ext_matches_its_row_at_every_immediate() {
    for (a, b) in pairs() {
        ext_cases!(a, b, 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15);
    }
}

#[test]
fn permutes_match_their_rows() {
    for (a, b) in pairs() {
        let (a8, b8) = (a.to_ne_bytes(), b.to_ne_bytes());
        let (a16, b16) = (u16s(a), u16s(b));
        let (a32, b32) = (u32s(a), u32s(b));
        let (a64, b64) = (u64s(a), u64s(b));

        let (trn8, trn16, trn32, trn64, uzp8, uzp64) = unsafe {
            (
                [
                    of_q8(vtrn1q_u8(q8(a8), q8(b8))),
                    of_q8(vtrn2q_u8(q8(a8), q8(b8))),
                ],
                [
                    of_q16(vtrn1q_u16(q16(a16), q16(b16))),
                    of_q16(vtrn2q_u16(q16(a16), q16(b16))),
                ],
                [
                    of_q32(vtrn1q_u32(q32(a32), q32(b32))),
                    of_q32(vtrn2q_u32(q32(a32), q32(b32))),
                ],
                [
                    of_q64(vtrn1q_u64(q64(a64), q64(b64))),
                    of_q64(vtrn2q_u64(q64(a64), q64(b64))),
                ],
                [
                    of_q8(vuzp1q_u8(q8(a8), q8(b8))),
                    of_q8(vuzp2q_u8(q8(a8), q8(b8))),
                ],
                [
                    of_q64(vuzp1q_u64(q64(a64), q64(b64))),
                    of_q64(vuzp2q_u64(q64(a64), q64(b64))),
                ],
            )
        };

        assert_eq!(
            trn8[0].to_vec(),
            vtrn1_x(&a8, &b8),
            "TRN1.16B {a:#x} {b:#x}"
        );
        assert_eq!(
            trn8[1].to_vec(),
            vtrn2_x(&a8, &b8),
            "TRN2.16B {a:#x} {b:#x}"
        );
        assert_eq!(
            trn16[0].to_vec(),
            vtrn1_x(&a16, &b16),
            "TRN1.8H {a:#x} {b:#x}"
        );
        assert_eq!(
            trn16[1].to_vec(),
            vtrn2_x(&a16, &b16),
            "TRN2.8H {a:#x} {b:#x}"
        );
        assert_eq!(
            trn32[0].to_vec(),
            vtrn1_x(&a32, &b32),
            "TRN1.4S {a:#x} {b:#x}"
        );
        assert_eq!(
            trn32[1].to_vec(),
            vtrn2_x(&a32, &b32),
            "TRN2.4S {a:#x} {b:#x}"
        );
        assert_eq!(
            trn64[0].to_vec(),
            vtrn1_x(&a64, &b64),
            "TRN1.2D {a:#x} {b:#x}"
        );
        assert_eq!(
            trn64[1].to_vec(),
            vtrn2_x(&a64, &b64),
            "TRN2.2D {a:#x} {b:#x}"
        );
        assert_eq!(
            uzp8[0].to_vec(),
            vuzp1_x(&a8, &b8),
            "UZP1.16B {a:#x} {b:#x}"
        );
        assert_eq!(
            uzp8[1].to_vec(),
            vuzp2_x(&a8, &b8),
            "UZP2.16B {a:#x} {b:#x}"
        );
        assert_eq!(
            uzp64[0].to_vec(),
            vuzp1_x(&a64, &b64),
            "UZP1.2D {a:#x} {b:#x}"
        );
        assert_eq!(
            uzp64[1].to_vec(),
            vuzp2_x(&a64, &b64),
            "UZP2.2D {a:#x} {b:#x}"
        );
    }
}

#[test]
fn lane_views_match_their_rows() {
    for a in registers() {
        let bytes = a.to_ne_bytes();

        let (w16, w32, w64) = unsafe {
            (
                transmute::<u128, [u16; 8]>(a),
                transmute::<u128, [u32; 4]>(a),
                transmute::<u128, [u64; 2]>(a),
            )
        };

        let (p0, p1, u0, u1, lane16, reinterpreted) = unsafe {
            (
                vgetq_lane_p64::<0>(p64(a)),
                vgetq_lane_p64::<1>(p64(a)),
                vgetq_lane_u64::<0>(q64(w64)),
                vgetq_lane_u64::<1>(q64(w64)),
                vgetq_lane_u16::<0>(q16(w16)),
                of_q64(vreinterpretq_u64_u8(q8(bytes))),
            )
        };

        assert_eq!(p0, lo64_x(a), "vgetq_lane_p64 0 {a:#x}");
        assert_eq!(p1, hi64_x(a), "vgetq_lane_p64 1 {a:#x}");
        assert_eq!(u0, lo64_x(a), "vgetq_lane_u64 0 {a:#x}");
        assert_eq!(u1, hi64_x(a), "vgetq_lane_u64 1 {a:#x}");
        assert_eq!(lane16, lanes16_x(&bytes)[0], "vgetq_lane_u16 0 {a:#x}");
        assert_eq!(w64.to_vec(), u128_lanes64_x(a), "u128 as 2D {a:#x}");
        assert_eq!(lanes64_u128_x(&w64), a, "2D as u128 {a:#x}");
        assert_eq!(bytes.to_vec(), u128_bytes_x(a), "u128 as 16B {a:#x}");
        assert_eq!(w16.to_vec(), lanes16_x(&bytes), "16B as 8H {a:#x}");
        assert_eq!(w32.to_vec(), lanes32_x(&bytes), "16B as 4S {a:#x}");
        assert_eq!(w64.to_vec(), lanes64_x(&bytes), "16B as 2D {a:#x}");
        assert_eq!(
            reinterpreted.to_vec(),
            lanes64_x(&bytes),
            "vreinterpretq_u64_u8 {a:#x}"
        );
        assert_eq!(bytes16_x(&w16), bytes.to_vec(), "8H as 16B {a:#x}");
        assert_eq!(bytes32_x(&w32), bytes.to_vec(), "4S as 16B {a:#x}");
        assert_eq!(bytes64_x(&w64), bytes.to_vec(), "2D as 16B {a:#x}");
    }
}

#[test]
fn loads_and_stores_move_bytes() {
    for a in registers() {
        let bytes = a.to_ne_bytes();
        let mut stored = [0u8; 16];

        let loaded = unsafe { of_q8(vld1q_u8(bytes.as_ptr())) };

        unsafe { vst1q_u8(stored.as_mut_ptr(), q8(bytes)) };

        assert_eq!(loaded, bytes, "LD1 {a:#x}");
        assert_eq!(stored, bytes, "ST1 {a:#x}");
    }
}
