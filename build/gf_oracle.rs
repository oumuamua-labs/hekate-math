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

static SB8: std::sync::LazyLock<Vec<u8>> = std::sync::LazyLock::new(|| {
    let mut t = vec![0u8; 1 << 16];
    for a in 0u16..256 {
        for b in 0u16..256 {
            t[(a as usize) << 8 | b as usize] = schoolbook8(a as u8, b as u8);
        }
    }

    t
});

pub fn sb8(a: u8, b: u8) -> u8 {
    SB8[(a as usize) << 8 | b as usize]
}

// verus/tower/block8.rs::clmul8
pub fn clmul8(a: u8, b: u8) -> u16 {
    let a16 = a as u16;
    (if b & 0x01 != 0 { a16 } else { 0 })
        ^ (if b & 0x02 != 0 { a16 << 1 } else { 0 })
        ^ (if b & 0x04 != 0 { a16 << 2 } else { 0 })
        ^ (if b & 0x08 != 0 { a16 << 3 } else { 0 })
        ^ (if b & 0x10 != 0 { a16 << 4 } else { 0 })
        ^ (if b & 0x20 != 0 { a16 << 5 } else { 0 })
        ^ (if b & 0x40 != 0 { a16 << 6 } else { 0 })
        ^ (if b & 0x80 != 0 { a16 << 7 } else { 0 })
}

// verus/tower/block8.rs::reduce8 (fold x^8..x^14 mod 0x11b)
pub fn reduce8(p: u16) -> u8 {
    ((p & 0xff)
        ^ (if p & 0x0100 != 0 { 0x1b } else { 0 })
        ^ (if p & 0x0200 != 0 { 0x36 } else { 0 })
        ^ (if p & 0x0400 != 0 { 0x6c } else { 0 })
        ^ (if p & 0x0800 != 0 { 0xd8 } else { 0 })
        ^ (if p & 0x1000 != 0 { 0xab } else { 0 })
        ^ (if p & 0x2000 != 0 { 0x4d } else { 0 })
        ^ (if p & 0x4000 != 0 { 0x9a } else { 0 })) as u8
}

// verus/tower/block8.rs::schoolbook8
pub fn schoolbook8(a: u8, b: u8) -> u8 {
    reduce8(clmul8(a, b))
}

// verus/tower/block16.rs::schoolbook16 (tau = 0x20)
pub fn schoolbook16(a: u16, b: u16) -> u16 {
    let a0 = (a & 0xff) as u8;
    let a1 = (a >> 8) as u8;
    let b0 = (b & 0xff) as u8;
    let b1 = (b >> 8) as u8;

    let lo = sb8(a0, b0) ^ sb8(sb8(a1, b1), 0x20);
    let hi = sb8(a0, b1) ^ sb8(a1, b0) ^ sb8(a1, b1);

    (lo as u16) | ((hi as u16) << 8)
}

// verus/tower/block32.rs::schoolbook32 (tau = 0x2000)
pub fn schoolbook32(a: u32, b: u32) -> u32 {
    let a0 = (a & 0xffff) as u16;
    let a1 = (a >> 16) as u16;
    let b0 = (b & 0xffff) as u16;
    let b1 = (b >> 16) as u16;

    let lo = schoolbook16(a0, b0) ^ schoolbook16(schoolbook16(a1, b1), 0x2000);
    let hi = schoolbook16(a0, b1) ^ schoolbook16(a1, b0) ^ schoolbook16(a1, b1);

    (lo as u32) | ((hi as u32) << 16)
}

// verus/tower/block64.rs::schoolbook64 (tau = 0x2000_0000)
pub fn schoolbook64(a: u64, b: u64) -> u64 {
    let a0 = (a & 0xffffffff) as u32;
    let a1 = (a >> 32) as u32;
    let b0 = (b & 0xffffffff) as u32;
    let b1 = (b >> 32) as u32;

    let lo = schoolbook32(a0, b0) ^ schoolbook32(schoolbook32(a1, b1), 0x2000_0000);
    let hi = schoolbook32(a0, b1) ^ schoolbook32(a1, b0) ^ schoolbook32(a1, b1);

    (lo as u64) | ((hi as u64) << 32)
}

// verus/tower/block128.rs::schoolbook128 (tau = 0x2000_0000_0000_0000)
pub fn schoolbook128(a: u128, b: u128) -> u128 {
    let a0 = (a & 0xffffffffffffffff) as u64;
    let a1 = (a >> 64) as u64;
    let b0 = (b & 0xffffffffffffffff) as u64;
    let b1 = (b >> 64) as u64;

    let lo = schoolbook64(a0, b0) ^ schoolbook64(schoolbook64(a1, b1), 0x2000_0000_0000_0000);
    let hi = schoolbook64(a0, b1) ^ schoolbook64(a1, b0) ^ schoolbook64(a1, b1);

    (lo as u128) | ((hi as u128) << 64)
}

// verus/tower/block256.rs::schoolbook256 (tau = 2^125; element is the (lo, hi) pair)
pub fn schoolbook256(alo: u128, ahi: u128, blo: u128, bhi: u128) -> (u128, u128) {
    const TAU: u128 = 0x2000_0000_0000_0000_0000_0000_0000_0000;

    let lo = schoolbook128(alo, blo) ^ schoolbook128(schoolbook128(ahi, bhi), TAU);
    let hi = schoolbook128(alo, bhi) ^ schoolbook128(ahi, blo) ^ schoolbook128(ahi, bhi);

    (lo, hi)
}
