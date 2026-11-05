// SPDX-License-Identifier: Apache-2.0
// This file is part of the hekate-math project.
// Copyright (C) 2026 Andrei Kochergin <andrei@oumuamua.dev>
// Copyright (C) 2026 Oumuamua Labs <info@oumuamua.dev>. All rights reserved.
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

//! Lane transposes.

use core::arch::aarch64::*;
use core::mem::transmute;

/// 16×16 byte matrix transpose via TRN cascade.
#[inline(always)]
pub(crate) fn transpose_16x16(r: &[uint8x16_t; 16]) -> [uint8x16_t; 16] {
    // Shorthand reinterpret casts
    // between NEON register types.
    #[inline(always)]
    const fn u8_to_u16(v: uint8x16_t) -> uint16x8_t {
        unsafe { transmute::<uint8x16_t, uint16x8_t>(v) }
    }

    #[inline(always)]
    const fn u16_to_u32(v: uint16x8_t) -> uint32x4_t {
        unsafe { transmute::<uint16x8_t, uint32x4_t>(v) }
    }

    #[inline(always)]
    const fn u32_to_u64(v: uint32x4_t) -> uint64x2_t {
        unsafe { transmute::<uint32x4_t, uint64x2_t>(v) }
    }

    #[inline(always)]
    const fn u64_to_u8(v: uint64x2_t) -> uint8x16_t {
        unsafe { transmute::<uint64x2_t, uint8x16_t>(v) }
    }

    // SAFETY:
    // NEON is baseline on the aarch64 targets this crate builds;
    // TRN permutes lanes only.
    unsafe {
        // Phase 1:
        // TRN u8, transpose 2×2 byte blocks
        let a0 = vtrn1q_u8(r[0], r[1]);
        let a1 = vtrn2q_u8(r[0], r[1]);
        let a2 = vtrn1q_u8(r[2], r[3]);
        let a3 = vtrn2q_u8(r[2], r[3]);
        let a4 = vtrn1q_u8(r[4], r[5]);
        let a5 = vtrn2q_u8(r[4], r[5]);
        let a6 = vtrn1q_u8(r[6], r[7]);
        let a7 = vtrn2q_u8(r[6], r[7]);
        let a8 = vtrn1q_u8(r[8], r[9]);
        let a9 = vtrn2q_u8(r[8], r[9]);
        let a10 = vtrn1q_u8(r[10], r[11]);
        let a11 = vtrn2q_u8(r[10], r[11]);
        let a12 = vtrn1q_u8(r[12], r[13]);
        let a13 = vtrn2q_u8(r[12], r[13]);
        let a14 = vtrn1q_u8(r[14], r[15]);
        let a15 = vtrn2q_u8(r[14], r[15]);

        // Phase 2:
        // TRN u16, transpose 4×4 blocks
        let b0 = vtrn1q_u16(u8_to_u16(a0), u8_to_u16(a2));
        let b2 = vtrn2q_u16(u8_to_u16(a0), u8_to_u16(a2));
        let b1 = vtrn1q_u16(u8_to_u16(a1), u8_to_u16(a3));
        let b3 = vtrn2q_u16(u8_to_u16(a1), u8_to_u16(a3));
        let b4 = vtrn1q_u16(u8_to_u16(a4), u8_to_u16(a6));
        let b6 = vtrn2q_u16(u8_to_u16(a4), u8_to_u16(a6));
        let b5 = vtrn1q_u16(u8_to_u16(a5), u8_to_u16(a7));
        let b7 = vtrn2q_u16(u8_to_u16(a5), u8_to_u16(a7));
        let b8 = vtrn1q_u16(u8_to_u16(a8), u8_to_u16(a10));
        let b10 = vtrn2q_u16(u8_to_u16(a8), u8_to_u16(a10));
        let b9 = vtrn1q_u16(u8_to_u16(a9), u8_to_u16(a11));
        let b11 = vtrn2q_u16(u8_to_u16(a9), u8_to_u16(a11));
        let b12 = vtrn1q_u16(u8_to_u16(a12), u8_to_u16(a14));
        let b14 = vtrn2q_u16(u8_to_u16(a12), u8_to_u16(a14));
        let b13 = vtrn1q_u16(u8_to_u16(a13), u8_to_u16(a15));
        let b15 = vtrn2q_u16(u8_to_u16(a13), u8_to_u16(a15));

        // Phase 3:
        // TRN u32, transpose 8×8 blocks
        let c0 = vtrn1q_u32(u16_to_u32(b0), u16_to_u32(b4));
        let c4 = vtrn2q_u32(u16_to_u32(b0), u16_to_u32(b4));
        let c1 = vtrn1q_u32(u16_to_u32(b1), u16_to_u32(b5));
        let c5 = vtrn2q_u32(u16_to_u32(b1), u16_to_u32(b5));
        let c2 = vtrn1q_u32(u16_to_u32(b2), u16_to_u32(b6));
        let c6 = vtrn2q_u32(u16_to_u32(b2), u16_to_u32(b6));
        let c3 = vtrn1q_u32(u16_to_u32(b3), u16_to_u32(b7));
        let c7 = vtrn2q_u32(u16_to_u32(b3), u16_to_u32(b7));
        let c8 = vtrn1q_u32(u16_to_u32(b8), u16_to_u32(b12));
        let c12 = vtrn2q_u32(u16_to_u32(b8), u16_to_u32(b12));
        let c9 = vtrn1q_u32(u16_to_u32(b9), u16_to_u32(b13));
        let c13 = vtrn2q_u32(u16_to_u32(b9), u16_to_u32(b13));
        let c10 = vtrn1q_u32(u16_to_u32(b10), u16_to_u32(b14));
        let c14 = vtrn2q_u32(u16_to_u32(b10), u16_to_u32(b14));
        let c11 = vtrn1q_u32(u16_to_u32(b11), u16_to_u32(b15));
        let c15 = vtrn2q_u32(u16_to_u32(b11), u16_to_u32(b15));

        // Phase 4:
        // TRN u64, full 16×16 transpose
        [
            u64_to_u8(vtrn1q_u64(u32_to_u64(c0), u32_to_u64(c8))),
            u64_to_u8(vtrn1q_u64(u32_to_u64(c1), u32_to_u64(c9))),
            u64_to_u8(vtrn1q_u64(u32_to_u64(c2), u32_to_u64(c10))),
            u64_to_u8(vtrn1q_u64(u32_to_u64(c3), u32_to_u64(c11))),
            u64_to_u8(vtrn1q_u64(u32_to_u64(c4), u32_to_u64(c12))),
            u64_to_u8(vtrn1q_u64(u32_to_u64(c5), u32_to_u64(c13))),
            u64_to_u8(vtrn1q_u64(u32_to_u64(c6), u32_to_u64(c14))),
            u64_to_u8(vtrn1q_u64(u32_to_u64(c7), u32_to_u64(c15))),
            u64_to_u8(vtrn2q_u64(u32_to_u64(c0), u32_to_u64(c8))),
            u64_to_u8(vtrn2q_u64(u32_to_u64(c1), u32_to_u64(c9))),
            u64_to_u8(vtrn2q_u64(u32_to_u64(c2), u32_to_u64(c10))),
            u64_to_u8(vtrn2q_u64(u32_to_u64(c3), u32_to_u64(c11))),
            u64_to_u8(vtrn2q_u64(u32_to_u64(c4), u32_to_u64(c12))),
            u64_to_u8(vtrn2q_u64(u32_to_u64(c5), u32_to_u64(c13))),
            u64_to_u8(vtrn2q_u64(u32_to_u64(c6), u32_to_u64(c14))),
            u64_to_u8(vtrn2q_u64(u32_to_u64(c7), u32_to_u64(c15))),
        ]
    }
}
