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

//! Differential test: production `BlockN::mul` equals the `gf_oracle`
//! schoolbook (shared with `build/main.rs`, from `verus/tower/blockN.rs`).
//! Heavy cases are release-only via `cfg_attr(debug_assertions, ignore)`.

use hekate_math::{Block8, Block16, Block32, Block64, Block128, Block256};
use rand::{RngExt, SeedableRng, rngs::StdRng};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[allow(dead_code)]
mod gf_oracle {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/build/gf_oracle.rs"));
}

use gf_oracle::{
    schoolbook8, schoolbook16, schoolbook32, schoolbook64, schoolbook128, schoolbook256,
};

const N32: usize = 20_000_000;
const N64: usize = 10_000_000;
const N128: usize = 5_000_000;
const N256: usize = 2_000_000;

// Per-chunk seeded streams
fn par_differential(total: usize, seed: u64, body: impl Fn(&mut StdRng) + Sync) {
    #[cfg(feature = "parallel")]
    {
        const CHUNKS: u64 = 64;

        let per = total.div_ceil(CHUNKS as usize);

        (0..CHUNKS).into_par_iter().for_each(|c| {
            let mut r = StdRng::seed_from_u64(seed ^ c);
            for _ in 0..per {
                body(&mut r);
            }
        });
    }

    #[cfg(not(feature = "parallel"))]
    {
        let mut r = StdRng::seed_from_u64(seed);
        for _ in 0..total {
            body(&mut r);
        }
    }
}

// ============================================================
// Differential tests
// ============================================================

#[test]
fn block8_exhaustive() {
    for a in 0u16..=255 {
        for b in 0u16..=255 {
            let (a, b) = (a as u8, b as u8);
            assert_eq!(
                (Block8(a) * Block8(b)).0,
                schoolbook8(a, b),
                "Block8 {a:#04x} * {b:#04x}",
            );
        }
    }
}

fn check16(a: u16) {
    for b in 0u16..=0xffff {
        assert_eq!(
            (Block16(a) * Block16(b)).0,
            schoolbook16(a, b),
            "Block16 {a:#06x} * {b:#06x}",
        );
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore = "heavy; release only")]
fn block16_exhaustive() {
    #[cfg(feature = "parallel")]
    (0u32..0x1_0000)
        .into_par_iter()
        .for_each(|a| check16(a as u16));

    #[cfg(not(feature = "parallel"))]
    for a in 0u16..=0xffff {
        check16(a);
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore = "heavy; release only")]
fn block32_randomized() {
    par_differential(N32, 32, |r| {
        let a: u32 = r.random();
        let b: u32 = r.random();

        assert_eq!(
            (Block32(a) * Block32(b)).0,
            schoolbook32(a, b),
            "Block32 {a:#010x} * {b:#010x}",
        );
    });
}

#[test]
#[cfg_attr(debug_assertions, ignore = "heavy; release only")]
fn block64_randomized() {
    par_differential(N64, 64, |r| {
        let a: u64 = r.random();
        let b: u64 = r.random();

        assert_eq!(
            (Block64(a) * Block64(b)).0,
            schoolbook64(a, b),
            "Block64 {a:#018x} * {b:#018x}",
        );
    });
}

#[test]
#[cfg_attr(debug_assertions, ignore = "heavy; release only")]
fn block128_randomized() {
    par_differential(N128, 128, |r| {
        let a: u128 = r.random();
        let b: u128 = r.random();

        assert_eq!(
            (Block128(a) * Block128(b)).0,
            schoolbook128(a, b),
            "Block128 {a:#034x} * {b:#034x}",
        );
    });
}

#[test]
#[cfg_attr(debug_assertions, ignore = "heavy; release only")]
fn block256_randomized() {
    par_differential(N256, 256, |r| {
        let alo: u128 = r.random();
        let ahi: u128 = r.random();
        let blo: u128 = r.random();
        let bhi: u128 = r.random();

        let prod = (Block256([alo, ahi]) * Block256([blo, bhi])).0;
        let (olo, ohi) = schoolbook256(alo, ahi, blo, bhi);

        assert_eq!(
            prod,
            [olo, ohi],
            "Block256 ({ahi:#034x},{alo:#034x}) * ({bhi:#034x},{blo:#034x})"
        );
    });
}
