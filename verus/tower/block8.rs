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

use vstd::prelude::*;

verus! {

pub open spec fn clmul8(a: u8, b: u8) -> u16 {
    let a16 = a as u16;
    (if b & 0x01 != 0 { a16 } else { 0 }) ^ (if b & 0x02 != 0 { a16 << 1 } else { 0 })
        ^ (if b & 0x04 != 0 { a16 << 2 } else { 0 }) ^ (if b & 0x08 != 0 { a16 << 3 } else { 0 })
        ^ (if b & 0x10 != 0 { a16 << 4 } else { 0 }) ^ (if b & 0x20 != 0 { a16 << 5 } else { 0 })
        ^ (if b & 0x40 != 0 { a16 << 6 } else { 0 }) ^ (if b & 0x80 != 0 { a16 << 7 } else { 0 })
}

// Reduce mod P = x^8 + x^4 + x^3 + x + 1 (0x11b): fold x^8..x^14.
pub open spec fn reduce8(p: u16) -> u8 {
    ((p & 0xff)
        ^ (if p & 0x0100 != 0 { 0x1b } else { 0 }) ^ (if p & 0x0200 != 0 { 0x36 } else { 0 })
        ^ (if p & 0x0400 != 0 { 0x6c } else { 0 }) ^ (if p & 0x0800 != 0 { 0xd8 } else { 0 })
        ^ (if p & 0x1000 != 0 { 0xab } else { 0 }) ^ (if p & 0x2000 != 0 { 0x4d } else { 0 })
        ^ (if p & 0x4000 != 0 { 0x9a } else { 0 })) as u8
}

pub open spec fn schoolbook8(a: u8, b: u8) -> u8 {
    reduce8(clmul8(a, b))
}

pub open spec fn xtime(a: u8) -> u8 {
    (a << 1) ^ (if a & 0x80 != 0 { 0x1b } else { 0 })
}

pub open spec fn gf8(a: u8, b: u8) -> u8 {
    let a1 = xtime(a);
    let a2 = xtime(a1);
    let a3 = xtime(a2);
    let a4 = xtime(a3);
    let a5 = xtime(a4);
    let a6 = xtime(a5);
    let a7 = xtime(a6);
    (if b & 0x01 != 0 { a } else { 0 }) ^ (if b & 0x02 != 0 { a1 } else { 0 })
        ^ (if b & 0x04 != 0 { a2 } else { 0 }) ^ (if b & 0x08 != 0 { a3 } else { 0 })
        ^ (if b & 0x10 != 0 { a4 } else { 0 }) ^ (if b & 0x20 != 0 { a5 } else { 0 })
        ^ (if b & 0x40 != 0 { a6 } else { 0 }) ^ (if b & 0x80 != 0 { a7 } else { 0 })
}

pub proof fn gf8_is_schoolbook(a: u8, b: u8)
    ensures gf8(a, b) == schoolbook8(a, b)
{
    assert(gf8(a, b) == schoolbook8(a, b)) by (bit_vector);
}

fn xtime_exec(a: u8) -> (r: u8)
    ensures r == xtime(a)
{
    (a << 1) ^ (if a & 0x80 != 0 { 0x1b } else { 0 })
}

// Block8::mul, block8.rs (shift-and-add), unrolled.
pub fn mul8(a: u8, b: u8) -> (r: u8)
    ensures r == schoolbook8(a, b)
{
    let a1 = xtime_exec(a);
    let a2 = xtime_exec(a1);
    let a3 = xtime_exec(a2);
    let a4 = xtime_exec(a3);
    let a5 = xtime_exec(a4);
    let a6 = xtime_exec(a5);
    let a7 = xtime_exec(a6);

    let acc: u8 = (if b & 0x01 != 0 { a } else { 0 }) ^ (if b & 0x02 != 0 { a1 } else { 0 })
        ^ (if b & 0x04 != 0 { a2 } else { 0 }) ^ (if b & 0x08 != 0 { a3 } else { 0 })
        ^ (if b & 0x10 != 0 { a4 } else { 0 }) ^ (if b & 0x20 != 0 { a5 } else { 0 })
        ^ (if b & 0x40 != 0 { a6 } else { 0 }) ^ (if b & 0x80 != 0 { a7 } else { 0 });

    proof {
        gf8_is_schoolbook(a, b);
    }

    acc
}

pub proof fn clmul8_lin_l(a: u8, d: u8, b: u8)
    ensures clmul8(a ^ d, b) == clmul8(a, b) ^ clmul8(d, b)
{
    assert(clmul8(a ^ d, b) == clmul8(a, b) ^ clmul8(d, b)) by (bit_vector);
}

pub proof fn clmul8_lin_r(a: u8, b: u8, c: u8)
    ensures clmul8(a, b ^ c) == clmul8(a, b) ^ clmul8(a, c)
{
    assert(clmul8(a, b ^ c) == clmul8(a, b) ^ clmul8(a, c)) by (bit_vector);
}

pub proof fn reduce8_lin(x: u16, y: u16)
    ensures reduce8(x ^ y) == reduce8(x) ^ reduce8(y)
{
    assert(reduce8(x ^ y) == reduce8(x) ^ reduce8(y)) by (bit_vector);
}

pub proof fn mul8_distrib_l(a: u8, d: u8, b: u8)
    ensures schoolbook8(a ^ d, b) == schoolbook8(a, b) ^ schoolbook8(d, b)
{
    clmul8_lin_l(a, d, b);
    reduce8_lin(clmul8(a, b), clmul8(d, b));
}

pub proof fn mul8_distrib_r(a: u8, b: u8, c: u8)
    ensures schoolbook8(a, b ^ c) == schoolbook8(a, b) ^ schoolbook8(a, c)
{
    clmul8_lin_r(a, b, c);
    reduce8_lin(clmul8(a, b), clmul8(a, c));
}

pub proof fn schoolbook8_zero(a: u8)
    ensures schoolbook8(a, 0) == 0
{
    assert(schoolbook8(a, 0) == 0) by (bit_vector);
}

// mul_tau_fold, block8.rs:
// a·x^5, two folds by 0x1b.
pub open spec fn mul_tau8(a: u8) -> u8 {
    let p = (a as u16) << 5;

    let h1 = p >> 8;
    let s = (p & 0x00ff) ^ (h1 ^ (h1 << 1) ^ (h1 << 3) ^ (h1 << 4));

    let h2 = s >> 8;

    ((s & 0x00ff) ^ (h2 ^ (h2 << 1) ^ (h2 << 3) ^ (h2 << 4))) as u8
}

pub proof fn mul_tau8_is_schoolbook(a: u8)
    ensures mul_tau8(a) == schoolbook8(a, 0x20)
{
    assert(mul_tau8(a) == schoolbook8(a, 0x20)) by (bit_vector);
}

fn main() {}

}
