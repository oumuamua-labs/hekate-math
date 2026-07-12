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

#[path = "axioms_t.rs"]
pub mod axioms_t;

pub use axioms_t::{frobenius_order_gen, norm_nonzero, phi_mult_gen, phi_roundtrip};

verus! {

// ============================================================
// Polynomial layer: GF(2)[x] as a bit-encoded nat
// ============================================================

pub open spec fn pow2(n: nat) -> nat
    decreases n
{
    if n == 0 { 1 } else { 2 * pow2((n - 1) as nat) }
}

pub open spec fn xor(a: nat, b: nat) -> nat
    decreases a + b
{
    if a == 0 && b == 0 { 0 } else { (a % 2 + b % 2) % 2 + 2 * xor(a / 2, b / 2) }
}

pub open spec fn clmul(a: nat, b: nat) -> nat
    decreases a
{
    if a == 0 { 0 } else { xor(if a % 2 == 1 { b } else { 0 }, clmul(a / 2, 2 * b)) }
}

pub open spec fn deg(a: nat) -> int
    decreases a
{
    if a == 0 { -1 } else { 1 + deg(a / 2) }
}

pub open spec fn sub_step(a: nat, m: nat) -> nat {
    xor(a, clmul(m, pow2((deg(a) - deg(m)) as nat)))
}

pub open spec fn pmod(a: nat, m: nat) -> nat
    decreases a
    when deg(m) >= 0
    via pmod_decreases
{
    if deg(a) < deg(m) {
        a
    } else {
        pmod(sub_step(a, m), m)
    }
}

#[verifier::decreases_by]
proof fn pmod_decreases(a: nat, m: nat) {
    if !(deg(a) < deg(m)) {
        sub_step_lt(a, m);
    }
}

// ============================================================
// Field layer: GF(2^k) in the flat (monomial) basis
// ============================================================

// x^k + POLY_k, generated in build/main.rs (trusted).
pub open spec fn modulus(k: nat) -> nat {
    if k == 8 {
        pow2(8) + 0x1b
    } else if k == 16 {
        pow2(16) + 0x2b
    } else if k == 32 {
        pow2(32) + 0x8d
    } else if k == 64 {
        pow2(64) + 0x1b
    } else if k == 128 {
        pow2(128) + 0x87
    } else {
        0
    }
}

pub open spec fn in_field(a: nat, k: nat) -> bool {
    deg(a) < k
}

pub open spec fn gf_add(a: nat, b: nat) -> nat {
    xor(a, b)
}

pub open spec fn gf_mul(a: nat, b: nat, k: nat) -> nat {
    pmod(clmul(a, b), modulus(k))
}

proof fn xor_bits(a: nat, b: nat)
    ensures
        xor(a, b) % 2 == (a % 2 + b % 2) % 2,
        xor(a, b) / 2 == xor(a / 2, b / 2),
{
    if a == 0 && b == 0 {
    } else {
        let l = (a % 2 + b % 2) % 2;
        let h = xor(a / 2, b / 2);

        assert(l < 2);
        assert(xor(a, b) == l + 2 * h);
        assert((l + 2 * h) % 2 == l) by (nonlinear_arith)
            requires l < 2,
        {}
        assert((l + 2 * h) / 2 == h) by (nonlinear_arith)
            requires l < 2,
        {}
    }
}

proof fn nat_from_bits(x: nat, y: nat)
    requires
        x % 2 == y % 2,
        x / 2 == y / 2,
    ensures x == y,
{
    assert(x == 2 * (x / 2) + x % 2);
    assert(y == 2 * (y / 2) + y % 2);
}

pub proof fn gf_add_assoc(a: nat, b: nat, c: nat)
    ensures gf_add(gf_add(a, b), c) == gf_add(a, gf_add(b, c))
    decreases a + b + c
{
    if a == 0 && b == 0 && c == 0 {
    } else {
        gf_add_assoc(a / 2, b / 2, c / 2);

        xor_bits(a, b);
        xor_bits(b, c);
        xor_bits(xor(a, b), c);
        xor_bits(a, xor(b, c));

        assert(xor(xor(a, b), c) % 2 == xor(a, xor(b, c)) % 2) by (nonlinear_arith)
            requires
                a % 2 < 2,
                b % 2 < 2,
                c % 2 < 2,
                xor(xor(a, b), c) % 2 == ((a % 2 + b % 2) % 2 + c % 2) % 2,
                xor(a, xor(b, c)) % 2 == (a % 2 + (b % 2 + c % 2) % 2) % 2,
        {}

        nat_from_bits(xor(xor(a, b), c), xor(a, xor(b, c)));
    }
}

pub proof fn gf_mul_comm(a: nat, b: nat, k: nat)
    ensures gf_mul(a, b, k) == gf_mul(b, a, k)
{
    clmul_comm(a, b);
}

pub proof fn gf_mul_assoc(a: nat, b: nat, c: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures gf_mul(gf_mul(a, b, k), c, k) == gf_mul(a, gf_mul(b, c, k), k)
{
    deg_modulus(k);

    let bc = clmul(b, c);

    pmod_mul_congr(clmul(a, b), c, modulus(k));
    clmul_assoc(a, b, c);
    clmul_comm(a, pmod(bc, modulus(k)));
    pmod_mul_congr(bc, a, modulus(k));
    clmul_comm(bc, a);
}

pub proof fn gf_distrib(a: nat, b: nat, c: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures gf_mul(a, gf_add(b, c), k) == gf_add(gf_mul(a, b, k), gf_mul(a, c, k))
{
    deg_modulus(k);
    clmul_distrib_r(a, b, c);
    pmod_additive(clmul(a, b), clmul(a, c), modulus(k));
}

proof fn deg_pow2_plus(k: nat, c: nat)
    requires c < pow2(k)
    ensures deg(pow2(k) + c) == k
    decreases k
{
    if k == 0 {
        assert(c == 0);
        assert(pow2(0) == 1);
        assert(deg(0) == -1);
        assert(deg(1) == 1 + deg(0));
    } else {
        let p = pow2((k - 1) as nat);

        assert(pow2(k) == 2 * p);
        assert(c / 2 < p) by (nonlinear_arith)
            requires c < 2 * p,
        {}
        assert((pow2(k) + c) / 2 == p + c / 2) by (nonlinear_arith)
            requires pow2(k) == 2 * p,
        {}
        assert(pow2(k) + c > 0);
        assert(deg(pow2(k) + c) == 1 + deg((pow2(k) + c) / 2));

        deg_pow2_plus((k - 1) as nat, c / 2);

        assert(deg(p + c / 2) == (k - 1) as nat);
    }
}

pub proof fn deg_modulus(k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures deg(modulus(k)) == k,
{
    if k == 8 {
        assert(0x1b < pow2(8)) by (compute);
        deg_pow2_plus(8, 0x1b);
    } else if k == 16 {
        assert(0x2b < pow2(16)) by (compute);
        deg_pow2_plus(16, 0x2b);
    } else if k == 32 {
        assert(0x8d < pow2(32)) by (compute);
        deg_pow2_plus(32, 0x8d);
    } else if k == 64 {
        assert(0x1b < pow2(64)) by (compute);
        deg_pow2_plus(64, 0x1b);
    } else {
        assert(0x87 < pow2(128)) by (compute);
        deg_pow2_plus(128, 0x87);
    }
}

// modulus(k) == 0 for other k, pmod is unconstrained and closure fails.
pub proof fn gf_mul_closed(a: nat, b: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures in_field(gf_mul(a, b, k), k)
{
    deg_modulus(k);
    pmod_deg(clmul(a, b), modulus(k));
}

// ============================================================
// GF(2)[x] ring laws: xor = +, clmul = *
// ============================================================

pub proof fn xor_comm(a: nat, b: nat)
    ensures xor(a, b) == xor(b, a)
    decreases a + b
{
    if a == 0 && b == 0 {
    } else {
        xor_comm(a / 2, b / 2);
        xor_bits(a, b);
        xor_bits(b, a);

        nat_from_bits(xor(a, b), xor(b, a));
    }
}

pub proof fn xor_assoc(a: nat, b: nat, c: nat)
    ensures xor(xor(a, b), c) == xor(a, xor(b, c))
{
    gf_add_assoc(a, b, c);
}

pub proof fn xor_zero(a: nat)
    ensures xor(a, 0) == a, xor(0, a) == a
    decreases a
{
    if a == 0 {
    } else {
        xor_zero(a / 2);
        xor_bits(a, 0);
        xor_bits(0, a);

        nat_from_bits(xor(a, 0), a);
        nat_from_bits(xor(0, a), a);
    }
}

proof fn xor_shift(x: nat, y: nat)
    ensures xor(2 * x, 2 * y) == 2 * xor(x, y)
{
    xor_bits(2 * x, 2 * y);
    nat_from_bits(xor(2 * x, 2 * y), 2 * xor(x, y));
}

pub proof fn clmul_zero_r(a: nat)
    ensures clmul(a, 0) == 0
    decreases a
{
    if a == 0 {
    } else {
        clmul_zero_r(a / 2);
        xor_zero(clmul(a / 2, 0));
    }
}

pub proof fn clmul_shift_r(a: nat, b: nat)
    ensures clmul(a, 2 * b) == 2 * clmul(a, b)
    decreases a
{
    if a == 0 {
    } else {
        clmul_shift_r(a / 2, 2 * b);
        xor_shift(if a % 2 == 1 { b } else { 0 }, clmul(a / 2, 2 * b));
    }
}

pub proof fn xor_self(a: nat)
    ensures xor(a, a) == 0
    decreases a
{
    if a == 0 {
    } else {
        xor_self(a / 2);
        xor_bits(a, a);
        nat_from_bits(xor(a, a), 0);
    }
}

pub proof fn xor_rearrange4(a: nat, b: nat, c: nat, d: nat)
    ensures xor(xor(a, b), xor(c, d)) == xor(xor(a, c), xor(b, d))
{
    xor_assoc(a, b, xor(c, d));
    xor_assoc(b, c, d);
    xor_comm(b, c);
    xor_assoc(c, b, d);
    xor_assoc(a, c, xor(b, d));
}

proof fn clmul_shift_l(a: nat, b: nat)
    ensures clmul(2 * a, b) == 2 * clmul(a, b)
{
    clmul_shift_r(a, b);
    xor_zero(clmul(a, 2 * b));
}

pub proof fn clmul_distrib_l(a1: nat, a2: nat, b: nat)
    ensures clmul(xor(a1, a2), b) == xor(clmul(a1, b), clmul(a2, b))
    decreases a1 + a2
{
    if a1 == 0 && a2 == 0 {
    } else {
        let a = xor(a1, a2);

        xor_bits(a1, a2);
        clmul_distrib_l(a1 / 2, a2 / 2, 2 * b);

        let s1 = if a1 % 2 == 1 { b } else { 0nat };
        let s2 = if a2 % 2 == 1 { b } else { 0nat };
        let p1 = clmul(a1 / 2, 2 * b);
        let p2 = clmul(a2 / 2, 2 * b);

        assert((if a % 2 == 1 { b } else { 0nat }) == xor(s1, s2)) by {
            if a1 % 2 == 1 && a2 % 2 == 1 {
                xor_self(b);
            } else {
                xor_zero(b);
            }
        }

        xor_rearrange4(s1, s2, p1, p2);
    }
}

pub proof fn clmul_one_l(b: nat)
    ensures clmul(1, b) == b
{
    assert(clmul(0, 2 * b) == 0);
    assert(clmul(1, b) == xor(b, 0));
    xor_zero(b);
}

pub proof fn clmul_one_r(a: nat)
    ensures clmul(a, 1) == a
    decreases a
{
    if a == 0 {
    } else {
        clmul_one_r(a / 2);
        clmul_shift_r(a / 2, 1);
        split_low(a);
        xor_comm(2 * (a / 2), a % 2);
    }
}

pub proof fn split_low(a: nat)
    ensures a == xor(2 * (a / 2), a % 2)
{
    xor_zero(a / 2);
    xor_bits(2 * (a / 2), a % 2);
    nat_from_bits(a, xor(2 * (a / 2), a % 2));
}

pub proof fn clmul_distrib_r(a: nat, b1: nat, b2: nat)
    ensures clmul(a, xor(b1, b2)) == xor(clmul(a, b1), clmul(a, b2))
    decreases a
{
    if a == 0 {
    } else {
        clmul_distrib_r(a / 2, 2 * b1, 2 * b2);
        xor_shift(b1, b2);

        let s1 = if a % 2 == 1 { b1 } else { 0nat };
        let s2 = if a % 2 == 1 { b2 } else { 0nat };
        let p1 = clmul(a / 2, 2 * b1);
        let p2 = clmul(a / 2, 2 * b2);

        assert((if a % 2 == 1 { xor(b1, b2) } else { 0nat }) == xor(s1, s2)) by {
            if a % 2 == 1 {
            } else {
                xor_zero(0);
            }
        }

        xor_rearrange4(s1, s2, p1, p2);
    }
}

pub proof fn clmul_comm(a: nat, b: nat)
    ensures clmul(a, b) == clmul(b, a)
    decreases a
{
    if a == 0 {
        clmul_zero_r(b);
    } else {
        clmul_comm(a / 2, b);
        split_low(a);
        clmul_distrib_l(2 * (a / 2), a % 2, b);
        clmul_distrib_r(b, 2 * (a / 2), a % 2);
        clmul_shift_l(a / 2, b);
        clmul_shift_r(b, a / 2);

        assert(clmul(a % 2, b) == clmul(b, a % 2)) by {
            if a % 2 == 0 {
                clmul_zero_r(b);
            } else {
                clmul_one_l(b);
                clmul_one_r(b);
            }
        }
    }
}

pub proof fn clmul_assoc(a: nat, b: nat, c: nat)
    ensures clmul(clmul(a, b), c) == clmul(a, clmul(b, c))
    decreases a
{
    if a == 0 {
    } else {
        clmul_assoc(a / 2, b, c);
        split_low(a);
        clmul_distrib_l(2 * (a / 2), a % 2, b);
        clmul_shift_l(a / 2, b);
        clmul_distrib_l(2 * clmul(a / 2, b), clmul(a % 2, b), c);
        clmul_shift_l(clmul(a / 2, b), c);
        clmul_distrib_l(2 * (a / 2), a % 2, clmul(b, c));
        clmul_shift_l(a / 2, clmul(b, c));

        assert(clmul(clmul(a % 2, b), c) == clmul(a % 2, clmul(b, c))) by {
            if a % 2 == 0 {
            } else {
                clmul_one_l(b);
                clmul_one_l(clmul(b, c));
            }
        }
    }
}

// ============================================================
// Degree / value bridge
// ============================================================

pub proof fn pow2_pos(n: nat)
    ensures pow2(n) >= 1
    decreases n
{
    if n == 0 {
    } else {
        pow2_pos((n - 1) as nat);
    }
}

proof fn deg_ge_neg1(a: nat)
    ensures deg(a) >= -1
    decreases a
{
    if a == 0 {
    } else {
        deg_ge_neg1(a / 2);
    }
}

proof fn deg_zero_iff(a: nat)
    ensures (deg(a) == -1) <==> (a == 0)
{
    if a != 0 {
        deg_ge_neg1(a / 2);
    }
}

proof fn deg_shift(a: nat)
    requires a > 0
    ensures deg(2 * a) == deg(a) + 1
{
    assert((2 * a) / 2 == a);
    assert(2 * a > 0);
}

pub proof fn deg_upper(a: nat, d: nat)
    requires deg(a) < d
    ensures a < pow2(d)
    decreases a
{
    pow2_pos(d);

    if a == 0 {
    } else {
        deg_ge_neg1(a / 2);
        assert(d >= 1);
        deg_upper(a / 2, (d - 1) as nat);
        assert(pow2(d) == 2 * pow2((d - 1) as nat));
    }
}

proof fn deg_lower(a: nat)
    requires a > 0
    ensures pow2(deg(a) as nat) <= a
    decreases a
{
    if a / 2 == 0 {
        assert(a == 1);
        assert(deg(0) == -1);
        assert(deg(1) == 1 + deg(0));
    } else {
        deg_lower(a / 2);
        deg_zero_iff(a / 2);
        deg_ge_neg1(a / 2);

        assert(deg(a / 2) >= 0);

        let e = deg(a / 2) as nat;

        assert(deg(a) == e + 1);
        assert(pow2((e + 1) as nat) == 2 * pow2(e));
    }
}

pub proof fn pow2_mono(i: nat, j: nat)
    requires i <= j
    ensures pow2(i) <= pow2(j)
    decreases j
{
    if i < j {
        pow2_mono(i, (j - 1) as nat);
        pow2_pos((j - 1) as nat);
    }
}

proof fn xor_eq_zero(a: nat, b: nat)
    requires xor(a, b) == 0
    ensures a == b
    decreases a + b
{
    if a == 0 && b == 0 {
    } else {
        xor_bits(a, b);

        assert(xor(a / 2, b / 2) == 0);
        assert(a % 2 == b % 2);

        xor_eq_zero(a / 2, b / 2);
        nat_from_bits(a, b);
    }
}

pub proof fn deg_xor_lt(a: nat, b: nat, d: nat)
    requires deg(a) < d, deg(b) < d
    ensures deg(xor(a, b)) < d
    decreases a + b
{
    if a == 0 && b == 0 {
    } else {
        xor_bits(a, b);
        deg_ge_neg1(a);
        deg_ge_neg1(b);
        deg_zero_iff(a);
        deg_zero_iff(b);

        assert(a > 0 || b > 0);
        assert(d >= 1);
        assert(deg(a / 2) < d - 1) by {
            if a == 0 {
                assert(deg(a / 2) == -1);
            } else {
                assert(deg(a) == 1 + deg(a / 2));
            }
        }
        assert(deg(b / 2) < d - 1) by {
            if b == 0 {
                assert(deg(b / 2) == -1);
            } else {
                assert(deg(b) == 1 + deg(b / 2));
            }
        }

        deg_xor_lt(a / 2, b / 2, (d - 1) as nat);

        if xor(a, b) != 0 {
            assert(deg(xor(a, b)) == 1 + deg(xor(a / 2, b / 2)));
        }
    }
}

pub proof fn deg_lt_conv(a: nat, d: nat)
    requires a < pow2(d)
    ensures deg(a) < d
{
    if a == 0 {
        assert(deg(0) == -1);
    } else {
        deg_ge_neg1(a);
        deg_zero_iff(a);
        deg_lower(a);

        assert(deg(a) < d) by {
            if deg(a) >= d {
                pow2_mono(d, deg(a) as nat);
            }
        }
    }
}

proof fn pow2_plus_lo_is_xor(dd: nat, lo: nat)
    requires lo < pow2(dd)
    ensures pow2(dd) + lo == xor(pow2(dd), lo)
    decreases dd
{
    if dd == 0 {
        assert(lo == 0);
        xor_zero(1);
    } else {
        pow2_pos((dd - 1) as nat);

        assert(pow2(dd) == 2 * pow2((dd - 1) as nat));
        assert(lo / 2 < pow2((dd - 1) as nat));

        pow2_plus_lo_is_xor((dd - 1) as nat, lo / 2);
        xor_bits(pow2(dd), lo);
        nat_from_bits(pow2(dd) + lo, xor(pow2(dd), lo));
    }
}

proof fn deg_xor_cancel(x: nat, y: nat)
    requires x > 0, deg(x) == deg(y)
    ensures deg(xor(x, y)) < deg(x)
{
    deg_ge_neg1(x);
    deg_zero_iff(x);
    deg_zero_iff(y);

    assert(deg(x) >= 0);

    let dd = deg(x) as nat;
    deg_lower(x);
    deg_lower(y);

    assert(pow2(dd + 1) == 2 * pow2(dd)) by { pow2_pos(dd); }

    deg_upper(x, (dd + 1) as nat);
    deg_upper(y, (dd + 1) as nat);

    let xlo = (x - pow2(dd)) as nat;
    let ylo = (y - pow2(dd)) as nat;

    assert(xlo < pow2(dd));
    assert(ylo < pow2(dd));

    pow2_plus_lo_is_xor(dd, xlo);
    pow2_plus_lo_is_xor(dd, ylo);

    assert(x == xor(pow2(dd), xlo));
    assert(y == xor(pow2(dd), ylo));

    xor_rearrange4(pow2(dd), xlo, pow2(dd), ylo);
    xor_self(pow2(dd));
    xor_zero(xor(xlo, ylo));

    assert(xor(x, y) == xor(xlo, ylo));

    deg_lt_conv(xlo, dd);
    deg_lt_conv(ylo, dd);
    deg_xor_lt(xlo, ylo, dd);
}

proof fn deg_xor_dominant(x: nat, y: nat)
    requires deg(y) < deg(x)
    ensures deg(xor(x, y)) == deg(x)
{
    deg_ge_neg1(x);
    deg_ge_neg1(y);
    deg_zero_iff(x);

    assert(deg(x) >= 0);

    let dd = deg(x) as nat;
    deg_lower(x);
    assert(pow2(dd + 1) == 2 * pow2(dd)) by { pow2_pos(dd); }
    deg_upper(x, (dd + 1) as nat);

    let xlo = (x - pow2(dd)) as nat;
    assert(xlo < pow2(dd));
    pow2_plus_lo_is_xor(dd, xlo);
    assert(x == xor(pow2(dd), xlo));
    deg_upper(y, dd);
    deg_lt_conv(xlo, dd);
    deg_xor_lt(xlo, y, dd);
    xor_assoc(pow2(dd), xlo, y);

    let z = xor(xlo, y);
    deg_upper(z, dd);
    pow2_plus_lo_is_xor(dd, z);
    deg_pow2_plus(dd, z);
}

pub proof fn deg_pow2(k: nat)
    ensures deg(pow2(k)) == k
{
    pow2_pos(k);
    deg_pow2_plus(k, 0);
}

pub proof fn clmul_pow2(a: nat, k: nat)
    ensures clmul(a, pow2(k)) == a * pow2(k)
    decreases k
{
    if k == 0 {
        clmul_one_r(a);
        assert(pow2(0) == 1);
    } else {
        clmul_pow2(a, (k - 1) as nat);
        assert(pow2(k) == 2 * pow2((k - 1) as nat));

        clmul_shift_r(a, pow2((k - 1) as nat));
        assert(2 * (a * pow2((k - 1) as nat)) == a * pow2(k)) by (nonlinear_arith)
            requires pow2(k) == 2 * pow2((k - 1) as nat);
    }
}

pub proof fn deg_clmul(a: nat, b: nat)
    requires a > 0, b > 0
    ensures deg(clmul(a, b)) == deg(a) + deg(b)
    decreases a
{
    split_low(a);
    clmul_distrib_l(2 * (a / 2), a % 2, b);
    clmul_shift_l(a / 2, b);

    if a / 2 == 0 {
        clmul_one_l(b);
        xor_zero(b);

        assert(deg(0) == -1);
        assert(deg(1) == 1 + deg(0));
    } else {
        deg_clmul(a / 2, b);
        deg_zero_iff(a / 2);
        deg_zero_iff(b);
        deg_ge_neg1(a / 2);
        deg_ge_neg1(b);
        deg_zero_iff(clmul(a / 2, b));

        assert(clmul(a / 2, b) > 0);

        deg_shift(clmul(a / 2, b));

        assert(deg(a) == 1 + deg(a / 2));

        assert(deg(clmul(a % 2, b)) < deg(2 * clmul(a / 2, b))) by {
            if a % 2 == 0 {
            } else {
                clmul_one_l(b);
            }
        }

        deg_xor_dominant(2 * clmul(a / 2, b), clmul(a % 2, b));
    }
}

// ============================================================
// Reduction: pmod as polynomial long division
// ============================================================

proof fn sub_step_lt(a: nat, m: nat)
    requires deg(m) >= 0, deg(a) >= deg(m)
    ensures sub_step(a, m) < a
{
    let d = (deg(a) - deg(m)) as nat;

    deg_zero_iff(m);
    deg_ge_neg1(m);
    pow2_pos(d);
    deg_pow2(d);
    deg_clmul(m, pow2(d));
    deg_zero_iff(a);

    assert(a > 0);

    deg_xor_cancel(a, clmul(m, pow2(d)));
    deg_lower(a);
    deg_upper(sub_step(a, m), deg(a) as nat);
}

pub proof fn pmod_deg(a: nat, m: nat)
    requires deg(m) >= 0
    ensures deg(pmod(a, m)) < deg(m)
    decreases a
{
    if deg(a) < deg(m) {
    } else {
        sub_step_lt(a, m);
        pmod_deg(sub_step(a, m), m);
    }
}

proof fn pmod_congruent(a: nat, m: nat)
    requires deg(m) >= 0
    ensures exists|q: nat| xor(a, pmod(a, m)) == clmul(q, m)
    decreases a
{
    if deg(a) < deg(m) {
        xor_self(a);
        assert(xor(a, pmod(a, m)) == clmul(0, m));
    } else {
        sub_step_lt(a, m);
        pmod_congruent(sub_step(a, m), m);

        let d = (deg(a) - deg(m)) as nat;
        let t = clmul(m, pow2(d));
        let s = sub_step(a, m);
        let p = pmod(s, m);

        xor_assoc(a, t, t);
        xor_self(t);
        xor_zero(a);

        assert(a == xor(s, t));

        let qp = choose|q: nat| xor(s, p) == clmul(q, m);

        xor_assoc(s, t, p);
        xor_comm(t, p);
        xor_assoc(s, p, t);

        assert(xor(a, p) == xor(xor(s, p), t));

        clmul_comm(m, pow2(d));
        clmul_distrib_l(qp, pow2(d), m);

        assert(xor(a, pmod(a, m)) == clmul(xor(qp, pow2(d)), m));
    }
}

pub proof fn pmod_unique(a: nat, r: nat, m: nat)
    requires
        deg(m) >= 0,
        deg(r) < deg(m),
        exists|q: nat| xor(a, r) == clmul(q, m),
    ensures r == pmod(a, m)
{
    pmod_deg(a, m);
    pmod_congruent(a, m);

    let p = pmod(a, m);
    let q1 = choose|q: nat| xor(a, r) == clmul(q, m);
    let q2 = choose|q: nat| xor(a, p) == clmul(q, m);

    xor_rearrange4(a, r, a, p);
    xor_self(a);
    xor_zero(xor(r, p));

    clmul_distrib_l(q1, q2, m);

    assert(xor(r, p) == clmul(xor(q1, q2), m));

    deg_xor_lt(r, p, deg(m) as nat);

    assert(xor(q1, q2) == 0) by {
        if xor(q1, q2) != 0 {
            deg_clmul(xor(q1, q2), m);
            deg_zero_iff(xor(q1, q2));
            deg_ge_neg1(xor(q1, q2));
        }
    }

    assert(clmul(0, m) == 0);

    xor_eq_zero(r, p);
}

pub proof fn pmod_additive(a: nat, b: nat, m: nat)
    requires deg(m) >= 0
    ensures pmod(xor(a, b), m) == xor(pmod(a, m), pmod(b, m))
{
    pmod_deg(a, m);
    pmod_deg(b, m);
    pmod_congruent(a, m);
    pmod_congruent(b, m);

    let pa = pmod(a, m);
    let pb = pmod(b, m);
    let r = xor(pa, pb);
    let qa = choose|q: nat| xor(a, pa) == clmul(q, m);
    let qb = choose|q: nat| xor(b, pb) == clmul(q, m);

    deg_xor_lt(pa, pb, deg(m) as nat);
    xor_rearrange4(a, b, pa, pb);
    clmul_distrib_l(qa, qb, m);

    assert(xor(xor(a, b), r) == clmul(xor(qa, qb), m));

    pmod_unique(xor(a, b), r, m);
}

pub proof fn pmod_of_multiple(q: nat, m: nat)
    requires deg(m) >= 0
    ensures pmod(clmul(q, m), m) == 0
{
    xor_zero(clmul(q, m));
    assert(deg(0) == -1);
    pmod_unique(clmul(q, m), 0, m);
}

proof fn pmod_mul_congr(a: nat, b: nat, m: nat)
    requires deg(m) >= 0
    ensures pmod(clmul(pmod(a, m), b), m) == pmod(clmul(a, b), m)
{
    pmod_congruent(a, m);

    let pa = pmod(a, m);
    let qa = choose|q: nat| xor(a, pa) == clmul(q, m);

    xor_self(pa);
    xor_assoc(a, pa, pa);
    xor_zero(a);
    xor_comm(clmul(qa, m), pa);

    assert(a == xor(pa, clmul(qa, m)));

    clmul_distrib_l(pa, clmul(qa, m), b);
    clmul_assoc(qa, m, b);
    clmul_comm(m, b);
    clmul_assoc(qa, b, m);

    let bigq = clmul(qa, b);
    assert(clmul(clmul(qa, m), b) == clmul(bigq, m));
    assert(clmul(a, b) == xor(clmul(pa, b), clmul(bigq, m)));

    pmod_additive(clmul(pa, b), clmul(bigq, m), m);
    pmod_of_multiple(bigq, m);
    xor_zero(pmod(clmul(pa, b), m));
}

// ============================================================
// Inversion: inv(0) = 0 convention
// ============================================================

// Product law holds only for a != 0; divisors inherit `a != 0`.
// in_field(r, k): the inverse is the reduced representative (deg < k), an ensures
// obligation quad_ext_inverse discharges for its result.
pub open spec fn is_correct_inverse(a: nat, r: nat, k: nat) -> bool {
    &&& in_field(r, k)
    &&& (a != 0 ==> gf_mul_tower(a, r, k) == 1)
    &&& (a == 0 ==> r == 0)
}

// ============================================================
// Tower layer: F_{2^{2m}} = F_{2^m}[X]/(X^2 + X + tau)
// ============================================================

// tau_tower(m) = BlockM::EXTENSION_TAU (generated tower-construction constant).
pub open spec fn tau_tower(m: nat) -> nat {
    if m == 8 {
        0x20
    } else if m == 16 {
        0x2000
    } else if m == 32 {
        0x2000_0000
    } else if m == 64 {
        0x2000_0000_0000_0000
    } else if m == 128 {
        0x2000_0000_0000_0000_0000_0000_0000_0000
    } else {
        0
    }
}

pub open spec fn lo_half(x: nat, k: nat) -> nat {
    x % pow2((k / 2) as nat)
}

pub open spec fn hi_half(x: nat, k: nat) -> nat {
    x / pow2((k / 2) as nat)
}

// Naive schoolbook oracle: four base multiplies. Leaf is GF(2^8).
pub open spec fn gf_mul_tower(a: nat, b: nat, k: nat) -> nat
    decreases k
{
    if k <= 8 {
        gf_mul(a, b, k)
    } else {
        let m = (k / 2) as nat;
        let a_lo = lo_half(a, k);
        let a_hi = hi_half(a, k);
        let b_lo = lo_half(b, k);
        let b_hi = hi_half(b, k);

        let p_ll = gf_mul_tower(a_lo, b_lo, m);
        let p_lh = gf_mul_tower(a_lo, b_hi, m);
        let p_hl = gf_mul_tower(a_hi, b_lo, m);
        let p_hh = gf_mul_tower(a_hi, b_hi, m);

        let c_lo = xor(p_ll, gf_mul_tower(p_hh, tau_tower(m), m));
        let c_hi = xor(xor(p_lh, p_hl), p_hh);

        c_lo + pow2(m) * c_hi
    }
}

pub proof fn gf_mul_tower_comm(a: nat, b: nat, k: nat)
    ensures gf_mul_tower(a, b, k) == gf_mul_tower(b, a, k)
    decreases k
{
    if k <= 8 {
        gf_mul_comm(a, b, k);
    } else {
        let m = (k / 2) as nat;
        let a_lo = lo_half(a, k);
        let a_hi = hi_half(a, k);
        let b_lo = lo_half(b, k);
        let b_hi = hi_half(b, k);

        gf_mul_tower_comm(a_lo, b_lo, m);
        gf_mul_tower_comm(a_hi, b_hi, m);
        gf_mul_tower_comm(a_lo, b_hi, m);
        gf_mul_tower_comm(a_hi, b_lo, m);

        xor_comm(gf_mul_tower(a_lo, b_hi, m), gf_mul_tower(a_hi, b_lo, m));
    }
}

pub proof fn xor_mul_pow2(m: nat, x: nat, y: nat)
    ensures xor(pow2(m) * x, pow2(m) * y) == pow2(m) * xor(x, y)
    decreases m
{
    if m == 0 {
        assert(pow2(0) == 1);
    } else {
        pow2_pos((m - 1) as nat);
        assert(pow2(m) == 2 * pow2((m - 1) as nat));

        let p = pow2((m - 1) as nat);
        assert(pow2(m) * x == 2 * (p * x)) by (nonlinear_arith)
            requires pow2(m) == 2 * p;
        assert(pow2(m) * y == 2 * (p * y)) by (nonlinear_arith)
            requires pow2(m) == 2 * p;
        assert(pow2(m) * xor(x, y) == 2 * (p * xor(x, y))) by (nonlinear_arith)
            requires pow2(m) == 2 * p;

        xor_mul_pow2((m - 1) as nat, x, y);
        xor_shift(p * x, p * y);
    }
}

pub proof fn lo_plus_hipart_is_xor(m: nat, lo: nat, h: nat)
    requires lo < pow2(m)
    ensures lo + pow2(m) * h == xor(lo, pow2(m) * h)
    decreases m
{
    if m == 0 {
        assert(lo == 0);
        assert(pow2(0) == 1);
        xor_zero(h);
    } else {
        pow2_pos((m - 1) as nat);

        assert(pow2(m) == 2 * pow2((m - 1) as nat));
        assert(pow2(m) * h == 2 * (pow2((m - 1) as nat) * h)) by (nonlinear_arith)
            requires pow2(m) == 2 * pow2((m - 1) as nat);
        assert(lo / 2 < pow2((m - 1) as nat));

        lo_plus_hipart_is_xor((m - 1) as nat, lo / 2, h);
        xor_bits(lo, pow2(m) * h);
        nat_from_bits(lo + pow2(m) * h, xor(lo, pow2(m) * h));
    }
}

pub proof fn pack_mod_div(lo: nat, hi: nat, m: nat)
    requires lo < pow2(m)
    ensures
        (lo + pow2(m) * hi) % pow2(m) == lo,
        (lo + pow2(m) * hi) / pow2(m) == hi,
{
    pow2_pos(m);

    assert((lo + pow2(m) * hi) % pow2(m) == lo) by (nonlinear_arith)
        requires lo < pow2(m), pow2(m) > 0;
    assert((lo + pow2(m) * hi) / pow2(m) == hi) by (nonlinear_arith)
        requires lo < pow2(m), pow2(m) > 0;
}

proof fn split_pack(x: nat, m: nat)
    ensures x == xor(x % pow2(m), pow2(m) * (x / pow2(m)))
{
    pow2_pos(m);
    lo_plus_hipart_is_xor(m, x % pow2(m), x / pow2(m));

    assert(x == x % pow2(m) + pow2(m) * (x / pow2(m))) by (nonlinear_arith)
        requires pow2(m) > 0;
}

proof fn xor_split(m: nat, x: nat, y: nat)
    ensures
        xor(x, y) % pow2(m) == xor(x % pow2(m), y % pow2(m)),
        xor(x, y) / pow2(m) == xor(x / pow2(m), y / pow2(m)),
{
    pow2_pos(m);
    split_pack(x, m);
    split_pack(y, m);

    let xlo = x % pow2(m);
    let xhi = x / pow2(m);
    let ylo = y % pow2(m);
    let yhi = y / pow2(m);

    xor_rearrange4(xlo, pow2(m) * xhi, ylo, pow2(m) * yhi);
    xor_mul_pow2(m, xhi, yhi);

    let ll = xor(xlo, ylo);
    let hh = xor(xhi, yhi);

    deg_lt_conv(xlo, m);
    deg_lt_conv(ylo, m);
    deg_xor_lt(xlo, ylo, m);
    deg_upper(ll, m);

    lo_plus_hipart_is_xor(m, ll, hh);
    pack_mod_div(ll, hh, m);
}

pub proof fn pow2_add(i: nat, j: nat)
    ensures pow2(i + j) == pow2(i) * pow2(j)
    decreases j
{
    if j == 0 {
        assert(pow2(0) == 1);
    } else {
        pow2_add(i, (j - 1) as nat);

        assert(pow2(j) == 2 * pow2((j - 1) as nat));
        assert(pow2(i + j) == 2 * pow2((i + j - 1) as nat));
        assert(pow2(i) * pow2(j) == 2 * (pow2(i) * pow2((j - 1) as nat))) by (nonlinear_arith)
            requires pow2(j) == 2 * pow2((j - 1) as nat);
    }
}

pub proof fn xor_lt_pow2(u: nat, v: nat, m: nat)
    requires u < pow2(m), v < pow2(m)
    ensures xor(u, v) < pow2(m)
{
    deg_lt_conv(u, m);
    deg_lt_conv(v, m);
    deg_xor_lt(u, v, m);
    deg_upper(xor(u, v), m);
}

proof fn xor_pack(l1: nat, h1: nat, l2: nat, h2: nat, m: nat)
    requires l1 < pow2(m), l2 < pow2(m)
    ensures xor(l1 + pow2(m) * h1, l2 + pow2(m) * h2) == xor(l1, l2) + pow2(m) * xor(h1, h2)
{
    lo_plus_hipart_is_xor(m, l1, h1);
    lo_plus_hipart_is_xor(m, l2, h2);

    xor_rearrange4(l1, pow2(m) * h1, l2, pow2(m) * h2);
    xor_mul_pow2(m, h1, h2);
    xor_lt_pow2(l1, l2, m);

    lo_plus_hipart_is_xor(m, xor(l1, l2), xor(h1, h2));
}

pub proof fn gf_mul_tower_bound(a: nat, b: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures gf_mul_tower(a, b, k) < pow2(k)
    decreases k
{
    if k == 8 {
        gf_mul_closed(a, b, 8);
        deg_upper(gf_mul(a, b, 8), 8);
    } else {
        let m = (k / 2) as nat;
        let a_lo = lo_half(a, k);
        let a_hi = hi_half(a, k);
        let b_lo = lo_half(b, k);
        let b_hi = hi_half(b, k);

        gf_mul_tower_bound(a_lo, b_lo, m);
        gf_mul_tower_bound(a_lo, b_hi, m);
        gf_mul_tower_bound(a_hi, b_lo, m);
        gf_mul_tower_bound(a_hi, b_hi, m);
        gf_mul_tower_bound(gf_mul_tower(a_hi, b_hi, m), tau_tower(m), m);

        let p_ll = gf_mul_tower(a_lo, b_lo, m);
        let p_lh = gf_mul_tower(a_lo, b_hi, m);
        let p_hl = gf_mul_tower(a_hi, b_lo, m);
        let p_hh = gf_mul_tower(a_hi, b_hi, m);
        let tpp = gf_mul_tower(p_hh, tau_tower(m), m);

        xor_lt_pow2(p_ll, tpp, m);
        xor_lt_pow2(p_lh, p_hl, m);
        xor_lt_pow2(xor(p_lh, p_hl), p_hh, m);

        let c_lo = xor(p_ll, tpp);
        let c_hi = xor(xor(p_lh, p_hl), p_hh);

        pow2_pos(m);
        pow2_add(m, m);

        assert(c_lo + pow2(m) * c_hi < pow2(k)) by (nonlinear_arith)
            requires c_lo < pow2(m), c_hi < pow2(m), pow2(k) == pow2(m) * pow2(m), pow2(m) > 0;
    }
}

pub proof fn gf_mul_tower_distrib_r(a: nat, b: nat, c: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures gf_mul_tower(a, xor(b, c), k) == xor(gf_mul_tower(a, b, k), gf_mul_tower(a, c, k))
    decreases k
{
    if k == 8 {
        gf_distrib(a, b, c, 8);
    } else {
        let m = (k / 2) as nat;
        let al = lo_half(a, k);
        let ah = hi_half(a, k);
        let bl = lo_half(b, k);
        let bh = hi_half(b, k);
        let cl = lo_half(c, k);
        let ch = hi_half(c, k);
        let t = tau_tower(m);

        xor_split(m, b, c);

        gf_mul_tower_distrib_r(al, bl, cl, m);
        gf_mul_tower_distrib_r(al, bh, ch, m);
        gf_mul_tower_distrib_r(ah, bl, cl, m);
        gf_mul_tower_distrib_r(ah, bh, ch, m);

        let hhb = gf_mul_tower(ah, bh, m);
        let hhc = gf_mul_tower(ah, ch, m);

        gf_mul_tower_comm(xor(hhb, hhc), t, m);
        gf_mul_tower_distrib_r(t, hhb, hhc, m);
        gf_mul_tower_comm(t, hhb, m);
        gf_mul_tower_comm(t, hhc, m);

        let llb = gf_mul_tower(al, bl, m);
        let llc = gf_mul_tower(al, cl, m);
        let tb = gf_mul_tower(hhb, t, m);
        let tc = gf_mul_tower(hhc, t, m);

        xor_rearrange4(llb, llc, tb, tc);

        let lhb = gf_mul_tower(al, bh, m);
        let lhc = gf_mul_tower(al, ch, m);
        let hlb = gf_mul_tower(ah, bl, m);
        let hlc = gf_mul_tower(ah, cl, m);

        xor_rearrange4(lhb, lhc, hlb, hlc);
        xor_rearrange4(xor(lhb, hlb), xor(lhc, hlc), hhb, hhc);

        gf_mul_tower_bound(al, bl, m);
        gf_mul_tower_bound(al, cl, m);
        gf_mul_tower_bound(hhb, t, m);
        gf_mul_tower_bound(hhc, t, m);

        let clob = xor(llb, tb);
        let cloc = xor(llc, tc);

        xor_lt_pow2(llb, tb, m);
        xor_lt_pow2(llc, tc, m);
        xor_pack(clob, xor(xor(lhb, hlb), hhb), cloc, xor(xor(lhc, hlc), hhc), m);
    }
}

pub proof fn gf_mul_tower_distrib_l(a: nat, b: nat, c: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures gf_mul_tower(xor(a, b), c, k) == xor(gf_mul_tower(a, c, k), gf_mul_tower(b, c, k))
{
    gf_mul_tower_comm(xor(a, b), c, k);
    gf_mul_tower_distrib_r(c, a, b, k);
    gf_mul_tower_comm(c, a, k);
    gf_mul_tower_comm(c, b, k);
}

proof fn gf_mul_tower_zero_l(b: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures gf_mul_tower(0, b, k) == 0
    decreases k
{
    if k == 8 {
        deg_modulus(8);
        assert(gf_mul_tower(0, b, 8) == gf_mul(0, b, 8));
        assert(clmul(0, b) == 0);
        assert(deg(0) == -1);
        assert(gf_mul(0, b, 8) == pmod(0, modulus(8)));
        assert(pmod(0, modulus(8)) == 0);
        assert(gf_mul_tower(0, b, k) == 0);
    } else {
        let m = (k / 2) as nat;
        pow2_pos(m);

        let bl = lo_half(b, k);
        let bh = hi_half(b, k);
        gf_mul_tower_zero_l(bl, m);
        gf_mul_tower_zero_l(bh, m);
        gf_mul_tower_zero_l(tau_tower(m), m);

        assert(lo_half(0, k) == 0);
        assert(hi_half(0, k) == 0);
        assert(gf_mul_tower(lo_half(0, k), bl, m) == 0);
        assert(gf_mul_tower(lo_half(0, k), bh, m) == 0);
        assert(gf_mul_tower(hi_half(0, k), bl, m) == 0);
        assert(gf_mul_tower(hi_half(0, k), bh, m) == 0);
        assert(gf_mul_tower(gf_mul_tower(hi_half(0, k), bh, m), tau_tower(m), m) == 0);

        xor_zero(0);

        assert(xor(gf_mul_tower(lo_half(0, k), bl, m),
            gf_mul_tower(gf_mul_tower(hi_half(0, k), bh, m), tau_tower(m), m)) == 0);
        assert(xor(xor(gf_mul_tower(lo_half(0, k), bh, m), gf_mul_tower(hi_half(0, k), bl, m)),
            gf_mul_tower(hi_half(0, k), bh, m)) == 0);
        assert(gf_mul_tower(0, b, k) == xor(gf_mul_tower(lo_half(0, k), bl, m),
            gf_mul_tower(gf_mul_tower(hi_half(0, k), bh, m), tau_tower(m), m))
            + pow2(m) * xor(xor(gf_mul_tower(lo_half(0, k), bh, m),
                gf_mul_tower(hi_half(0, k), bl, m)), gf_mul_tower(hi_half(0, k), bh, m)));
    }
}

proof fn gf_mul_tower_zero_r(a: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures gf_mul_tower(a, 0, k) == 0
{
    gf_mul_tower_comm(a, 0, k);
    gf_mul_tower_zero_l(a, k);
}

pub open spec fn tlo(a0: nat, a1: nat, b0: nat, b1: nat, m: nat) -> nat {
    xor(gf_mul_tower(a0, b0, m), gf_mul_tower(gf_mul_tower(a1, b1, m), tau_tower(m), m))
}

pub open spec fn thi(a0: nat, a1: nat, b0: nat, b1: nat, m: nat) -> nat {
    xor(xor(gf_mul_tower(a0, b1, m), gf_mul_tower(a1, b0, m)), gf_mul_tower(a1, b1, m))
}

pub proof fn gf_mul_tower_unfold(a: nat, b: nat, k: nat)
    requires k == 16 || k == 32 || k == 64 || k == 128 || k == 256,
    ensures
        gf_mul_tower(a, b, k) == tlo(lo_half(a, k), hi_half(a, k), lo_half(b, k), hi_half(b, k),
            (k / 2) as nat) + pow2((k / 2) as nat) * thi(lo_half(a, k), hi_half(a, k),
            lo_half(b, k), hi_half(b, k), (k / 2) as nat),
        tlo(lo_half(a, k), hi_half(a, k), lo_half(b, k), hi_half(b, k), (k / 2) as nat) < pow2((k / 2) as nat),
        thi(lo_half(a, k), hi_half(a, k), lo_half(b, k), hi_half(b, k), (k / 2) as nat) < pow2((k / 2) as nat),
{
    let m = (k / 2) as nat;
    let a0 = lo_half(a, k);
    let a1 = hi_half(a, k);
    let b0 = lo_half(b, k);
    let b1 = hi_half(b, k);

    gf_mul_tower_bound(a0, b0, m);
    gf_mul_tower_bound(a0, b1, m);
    gf_mul_tower_bound(a1, b0, m);
    gf_mul_tower_bound(a1, b1, m);
    gf_mul_tower_bound(gf_mul_tower(a1, b1, m), tau_tower(m), m);

    xor_lt_pow2(gf_mul_tower(a0, b0, m), gf_mul_tower(gf_mul_tower(a1, b1, m), tau_tower(m), m), m);
    xor_lt_pow2(gf_mul_tower(a0, b1, m), gf_mul_tower(a1, b0, m), m);
    xor_lt_pow2(xor(gf_mul_tower(a0, b1, m), gf_mul_tower(a1, b0, m)), gf_mul_tower(a1, b1, m), m);
}

// Level-m associativity is a triggered `forall` hypothesis, not proven here:
// gf_mul_tower_assoc calls this at k = 2m, re-invoking it at m would break the
// decreases. Discharged by explicit monomial expansion under hide(gf_mul_tower),
// the forall e-matches only on introduced terms (no AC blow-up).
proof fn tlo_assoc(a0: nat, a1: nat, b0: nat, b1: nat, c0: nat, c1: nat, m: nat)
    requires
        m == 8 || m == 16 || m == 32 || m == 64 || m == 128,
        forall|x: nat, y: nat, z: nat| #[trigger] gf_mul_tower(gf_mul_tower(x, y, m), z, m)
            == gf_mul_tower(x, gf_mul_tower(y, z, m), m),
    ensures
        tlo(tlo(a0, a1, b0, b1, m), thi(a0, a1, b0, b1, m), c0, c1, m)
            == tlo(a0, a1, tlo(b0, b1, c0, c1, m), thi(b0, b1, c0, c1, m), m)
{
    hide(gf_mul_tower);

    let t = tau_tower(m);

    let r1 = gf_mul_tower(a0, gf_mul_tower(b0, c0, m), m);
    let r2 = gf_mul_tower(a0, gf_mul_tower(gf_mul_tower(b1, c1, m), t, m), m);
    let r3 = gf_mul_tower(gf_mul_tower(a1, gf_mul_tower(b0, c1, m), m), t, m);
    let r4 = gf_mul_tower(gf_mul_tower(a1, gf_mul_tower(b1, c0, m), m), t, m);
    let r5 = gf_mul_tower(gf_mul_tower(a1, gf_mul_tower(b1, c1, m), m), t, m);

    let s1 = gf_mul_tower(gf_mul_tower(a0, b0, m), c0, m);
    let s2 = gf_mul_tower(gf_mul_tower(gf_mul_tower(a1, b1, m), t, m), c0, m);
    let s3 = gf_mul_tower(gf_mul_tower(gf_mul_tower(a0, b1, m), c1, m), t, m);
    let s4 = gf_mul_tower(gf_mul_tower(gf_mul_tower(a1, b0, m), c1, m), t, m);
    let s5 = gf_mul_tower(gf_mul_tower(gf_mul_tower(a1, b1, m), c1, m), t, m);

    assert(tlo(tlo(a0, a1, b0, b1, m), thi(a0, a1, b0, b1, m), c0, c1, m)
        == xor(xor(s1, s2), xor(xor(s3, s4), s5))) by {
        gf_mul_tower_distrib_l(gf_mul_tower(a0, b0, m),
            gf_mul_tower(gf_mul_tower(a1, b1, m), t, m), c0, m);
        gf_mul_tower_distrib_l(xor(gf_mul_tower(a0, b1, m), gf_mul_tower(a1, b0, m)),
            gf_mul_tower(a1, b1, m), c1, m);
        gf_mul_tower_distrib_l(gf_mul_tower(a0, b1, m), gf_mul_tower(a1, b0, m), c1, m);
        gf_mul_tower_distrib_l(
            xor(gf_mul_tower(gf_mul_tower(a0, b1, m), c1, m),
                gf_mul_tower(gf_mul_tower(a1, b0, m), c1, m)),
            gf_mul_tower(gf_mul_tower(a1, b1, m), c1, m), t, m);
        gf_mul_tower_distrib_l(gf_mul_tower(gf_mul_tower(a0, b1, m), c1, m),
            gf_mul_tower(gf_mul_tower(a1, b0, m), c1, m), t, m);
    }

    assert(tlo(a0, a1, tlo(b0, b1, c0, c1, m), thi(b0, b1, c0, c1, m), m)
        == xor(xor(r1, r2), xor(xor(r3, r4), r5))) by {
        gf_mul_tower_distrib_r(a0, gf_mul_tower(b0, c0, m),
            gf_mul_tower(gf_mul_tower(b1, c1, m), t, m), m);
        gf_mul_tower_distrib_r(a1, xor(gf_mul_tower(b0, c1, m), gf_mul_tower(b1, c0, m)),
            gf_mul_tower(b1, c1, m), m);
        gf_mul_tower_distrib_r(a1, gf_mul_tower(b0, c1, m), gf_mul_tower(b1, c0, m), m);
        gf_mul_tower_distrib_l(
            xor(gf_mul_tower(a1, gf_mul_tower(b0, c1, m), m),
                gf_mul_tower(a1, gf_mul_tower(b1, c0, m), m)),
            gf_mul_tower(a1, gf_mul_tower(b1, c1, m), m), t, m);
        gf_mul_tower_distrib_l(gf_mul_tower(a1, gf_mul_tower(b0, c1, m), m),
            gf_mul_tower(a1, gf_mul_tower(b1, c0, m), m), t, m);
    }

    assert(s1 == r1);

    assert(s2 == r4) by {
        gf_mul_tower_comm(t, c0, m);
        assert(gf_mul_tower(gf_mul_tower(gf_mul_tower(a1, b1, m), t, m), c0, m)
            == gf_mul_tower(gf_mul_tower(a1, b1, m), gf_mul_tower(t, c0, m), m));
        assert(gf_mul_tower(gf_mul_tower(a1, b1, m), gf_mul_tower(c0, t, m), m)
            == gf_mul_tower(a1, gf_mul_tower(b1, gf_mul_tower(c0, t, m), m), m));
        assert(gf_mul_tower(gf_mul_tower(a1, gf_mul_tower(b1, c0, m), m), t, m)
            == gf_mul_tower(a1, gf_mul_tower(gf_mul_tower(b1, c0, m), t, m), m));
        assert(gf_mul_tower(gf_mul_tower(b1, c0, m), t, m)
            == gf_mul_tower(b1, gf_mul_tower(c0, t, m), m));
    }

    assert(s3 == r2) by {
        assert(gf_mul_tower(gf_mul_tower(a0, b1, m), c1, m)
            == gf_mul_tower(a0, gf_mul_tower(b1, c1, m), m));
        assert(gf_mul_tower(gf_mul_tower(a0, gf_mul_tower(b1, c1, m), m), t, m)
            == gf_mul_tower(a0, gf_mul_tower(gf_mul_tower(b1, c1, m), t, m), m));
    }

    assert(s4 == r3) by {
        assert(gf_mul_tower(gf_mul_tower(a1, b0, m), c1, m)
            == gf_mul_tower(a1, gf_mul_tower(b0, c1, m), m));
    }

    assert(s5 == r5) by {
        assert(gf_mul_tower(gf_mul_tower(a1, b1, m), c1, m)
            == gf_mul_tower(a1, gf_mul_tower(b1, c1, m), m));
    }

    assert(xor(xor(r1, r4), xor(xor(r2, r3), r5))
        == xor(xor(r1, r2), xor(xor(r3, r4), r5))) by {
        xor_assoc(xor(r1, r4), xor(r2, r3), r5);
        xor_assoc(xor(r1, r2), xor(r3, r4), r5);
        xor_rearrange4(r1, r4, r2, r3);
        xor_comm(r4, r3);
    }
}

proof fn thi_assoc(a0: nat, a1: nat, b0: nat, b1: nat, c0: nat, c1: nat, m: nat)
    requires
        m == 8 || m == 16 || m == 32 || m == 64 || m == 128,
        forall|x: nat, y: nat, z: nat| #[trigger] gf_mul_tower(gf_mul_tower(x, y, m), z, m)
            == gf_mul_tower(x, gf_mul_tower(y, z, m), m),
    ensures
        thi(tlo(a0, a1, b0, b1, m), thi(a0, a1, b0, b1, m), c0, c1, m)
            == thi(a0, a1, tlo(b0, b1, c0, c1, m), thi(b0, b1, c0, c1, m), m)
{
    hide(gf_mul_tower);

    let t = tau_tower(m);

    let g1 = gf_mul_tower(a0, gf_mul_tower(b0, c1, m), m);
    let g2 = gf_mul_tower(a0, gf_mul_tower(b1, c0, m), m);
    let g3 = gf_mul_tower(a0, gf_mul_tower(b1, c1, m), m);
    let g4 = gf_mul_tower(a1, gf_mul_tower(b0, c0, m), m);
    let g5 = gf_mul_tower(a1, gf_mul_tower(gf_mul_tower(b1, c1, m), t, m), m);
    let g6 = gf_mul_tower(a1, gf_mul_tower(b0, c1, m), m);
    let g7 = gf_mul_tower(a1, gf_mul_tower(b1, c0, m), m);
    let g8 = gf_mul_tower(a1, gf_mul_tower(b1, c1, m), m);

    let h1 = gf_mul_tower(gf_mul_tower(a0, b0, m), c1, m);
    let h2 = gf_mul_tower(gf_mul_tower(gf_mul_tower(a1, b1, m), t, m), c1, m);
    let h3 = gf_mul_tower(gf_mul_tower(a0, b1, m), c0, m);
    let h4 = gf_mul_tower(gf_mul_tower(a1, b0, m), c0, m);
    let h5 = gf_mul_tower(gf_mul_tower(a1, b1, m), c0, m);
    let h6 = gf_mul_tower(gf_mul_tower(a0, b1, m), c1, m);
    let h7 = gf_mul_tower(gf_mul_tower(a1, b0, m), c1, m);
    let h8 = gf_mul_tower(gf_mul_tower(a1, b1, m), c1, m);

    assert(thi(tlo(a0, a1, b0, b1, m), thi(a0, a1, b0, b1, m), c0, c1, m)
        == xor(xor(xor(h1, h2), xor(xor(h3, h4), h5)), xor(xor(h6, h7), h8))) by {
        gf_mul_tower_distrib_l(gf_mul_tower(a0, b0, m),
            gf_mul_tower(gf_mul_tower(a1, b1, m), t, m), c1, m);
        gf_mul_tower_distrib_l(xor(gf_mul_tower(a0, b1, m), gf_mul_tower(a1, b0, m)),
            gf_mul_tower(a1, b1, m), c0, m);
        gf_mul_tower_distrib_l(gf_mul_tower(a0, b1, m), gf_mul_tower(a1, b0, m), c0, m);
        gf_mul_tower_distrib_l(xor(gf_mul_tower(a0, b1, m), gf_mul_tower(a1, b0, m)),
            gf_mul_tower(a1, b1, m), c1, m);
        gf_mul_tower_distrib_l(gf_mul_tower(a0, b1, m), gf_mul_tower(a1, b0, m), c1, m);
    }

    assert(thi(a0, a1, tlo(b0, b1, c0, c1, m), thi(b0, b1, c0, c1, m), m)
        == xor(xor(xor(xor(g1, g2), g3), xor(g4, g5)), xor(xor(g6, g7), g8))) by {
        gf_mul_tower_distrib_r(a0, xor(gf_mul_tower(b0, c1, m), gf_mul_tower(b1, c0, m)),
            gf_mul_tower(b1, c1, m), m);
        gf_mul_tower_distrib_r(a0, gf_mul_tower(b0, c1, m), gf_mul_tower(b1, c0, m), m);
        gf_mul_tower_distrib_r(a1, gf_mul_tower(b0, c0, m),
            gf_mul_tower(gf_mul_tower(b1, c1, m), t, m), m);
        gf_mul_tower_distrib_r(a1, xor(gf_mul_tower(b0, c1, m), gf_mul_tower(b1, c0, m)),
            gf_mul_tower(b1, c1, m), m);
        gf_mul_tower_distrib_r(a1, gf_mul_tower(b0, c1, m), gf_mul_tower(b1, c0, m), m);
    }

    assert(h1 == g1);
    assert(h3 == g2);
    assert(h4 == g4);
    assert(h5 == g7);
    assert(h6 == g3);
    assert(h7 == g6);
    assert(h8 == g8);

    assert(h2 == g5) by {
        gf_mul_tower_comm(t, c1, m);
        assert(gf_mul_tower(gf_mul_tower(gf_mul_tower(a1, b1, m), t, m), c1, m)
            == gf_mul_tower(gf_mul_tower(a1, b1, m), gf_mul_tower(t, c1, m), m));
        assert(gf_mul_tower(gf_mul_tower(a1, b1, m), gf_mul_tower(c1, t, m), m)
            == gf_mul_tower(a1, gf_mul_tower(b1, gf_mul_tower(c1, t, m), m), m));
        assert(gf_mul_tower(gf_mul_tower(b1, c1, m), t, m)
            == gf_mul_tower(b1, gf_mul_tower(c1, t, m), m));
    }

    assert(xor(xor(xor(g1, g5), xor(xor(g2, g4), g7)), xor(xor(g3, g6), g8))
        == xor(xor(xor(xor(g1, g2), g3), xor(g4, g5)), xor(xor(g6, g7), g8))) by {
        assert forall|x: nat, y: nat, z: nat| #[trigger] xor(xor(x, y), z)
            == xor(x, xor(y, z)) by { xor_assoc(x, y, z); }
        assert forall|x: nat, y: nat| #[trigger] xor(x, y) == xor(y, x) by { xor_comm(x, y); }
    }
}

pub proof fn gf_mul_tower_assoc(a: nat, b: nat, c: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures gf_mul_tower(gf_mul_tower(a, b, k), c, k) == gf_mul_tower(a, gf_mul_tower(b, c, k), k)
    decreases k
{
    if k == 8 {
        gf_mul_assoc(a, b, c, 8);

        assert(gf_mul_tower(a, b, 8) == gf_mul(a, b, 8));
        assert(gf_mul_tower(b, c, 8) == gf_mul(b, c, 8));
        assert(gf_mul_tower(gf_mul(a, b, 8), c, 8) == gf_mul(gf_mul(a, b, 8), c, 8));
        assert(gf_mul_tower(a, gf_mul(b, c, 8), 8) == gf_mul(a, gf_mul(b, c, 8), 8));
    } else {
        let m = (k / 2) as nat;
        let a0 = lo_half(a, k);
        let a1 = hi_half(a, k);
        let b0 = lo_half(b, k);
        let b1 = hi_half(b, k);
        let c0 = lo_half(c, k);
        let c1 = hi_half(c, k);

        assert forall|x: nat, y: nat, z: nat| #[trigger] gf_mul_tower(gf_mul_tower(x, y, m), z, m)
            == gf_mul_tower(x, gf_mul_tower(y, z, m), m) by {
            gf_mul_tower_assoc(x, y, z, m);
        }

        gf_mul_tower_unfold(a, b, k);
        gf_mul_tower_unfold(b, c, k);

        let p = tlo(a0, a1, b0, b1, m);
        let q = thi(a0, a1, b0, b1, m);
        let r = tlo(b0, b1, c0, c1, m);
        let s = thi(b0, b1, c0, c1, m);

        pack_mod_div(p, q, m);
        pack_mod_div(r, s, m);

        gf_mul_tower_unfold(gf_mul_tower(a, b, k), c, k);
        gf_mul_tower_unfold(a, gf_mul_tower(b, c, k), k);

        tlo_assoc(a0, a1, b0, b1, c0, c1, m);
        thi_assoc(a0, a1, b0, b1, c0, c1, m);
    }
}

// The 3-multiply Karatsuba refines the schoolbook c_hi.
// Proven for k=128 in block128.rs.
pub proof fn karatsuba_refines_schoolbook(a_lo: nat, a_hi: nat, b_lo: nat, b_hi: nat, m: nat)
    requires m == 8 || m == 16 || m == 32 || m == 64 || m == 128,
    ensures
        xor(gf_mul_tower(a_lo, b_lo, m), gf_mul_tower(xor(a_lo, a_hi), xor(b_lo, b_hi), m))
            == xor(xor(gf_mul_tower(a_lo, b_hi, m), gf_mul_tower(a_hi, b_lo, m)),
                   gf_mul_tower(a_hi, b_hi, m))
{
    gf_mul_tower_distrib_r(xor(a_lo, a_hi), b_lo, b_hi, m);
    gf_mul_tower_distrib_l(a_lo, a_hi, b_lo, m);
    gf_mul_tower_distrib_l(a_lo, a_hi, b_hi, m);

    let va = gf_mul_tower(a_lo, b_lo, m);
    let vb = gf_mul_tower(a_hi, b_lo, m);
    let vc = gf_mul_tower(a_lo, b_hi, m);
    let vd = gf_mul_tower(a_hi, b_hi, m);

    xor_assoc(va, vb, xor(vc, vd));
    xor_assoc(va, va, xor(vb, xor(vc, vd)));
    xor_self(va);
    xor_zero(xor(vb, xor(vc, vd)));
    xor_assoc(vb, vc, vd);
    xor_comm(vb, vc);
    xor_assoc(vc, vb, vd);
}

pub open spec fn ext_norm(lo: nat, hi: nat, m: nat) -> nat {
    xor(xor(gf_mul_tower(lo, lo, m), gf_mul_tower(lo, hi, m)),
        gf_mul_tower(gf_mul_tower(hi, hi, m), tau_tower(m), m))
}

// a^-1 = conj(a) * N(a)^-1, conj = (lo+hi, hi). block128.rs:69-81.
// The reduction a * (conj(a) * ninv) == N(a) * ninv is proven algebra (tau-generic);
// only N(a) != 0 for a != 0 is trusted (norm_nonzero).
pub proof fn quad_ext_inverse(a: nat, k: nat, ninv: nat)
    requires
        k == 16 || k == 32 || k == 64 || k == 128 || k == 256,
        in_field(a, k),
        is_correct_inverse(
            ext_norm(lo_half(a, k), hi_half(a, k), (k / 2) as nat),
            ninv,
            (k / 2) as nat,
        ),
    ensures ({
        let m = (k / 2) as nat;
        let res_lo = gf_mul_tower(xor(hi_half(a, k), lo_half(a, k)), ninv, m);
        let res_hi = gf_mul_tower(hi_half(a, k), ninv, m);

        is_correct_inverse(a, res_lo + pow2(m) * res_hi, k)
    })
{
    hide(gf_mul_tower);
    let m = (k / 2) as nat;
    let lo = lo_half(a, k);
    let hi = hi_half(a, k);
    let res_lo = gf_mul_tower(xor(hi, lo), ninv, m);
    let res_hi = gf_mul_tower(hi, ninv, m);
    let res = res_lo + pow2(m) * res_hi;
    let nrm = ext_norm(lo, hi, m);
    let t = tau_tower(m);

    assert(m == 8 || m == 16 || m == 32 || m == 64 || m == 128);

    gf_mul_tower_bound(xor(hi, lo), ninv, m);
    gf_mul_tower_bound(hi, ninv, m);

    pow2_pos(m);
    assert(k == m + m);

    pow2_add(m, m);
    assert(pow2(k) == pow2(m) * pow2(m));

    assert(res_lo + pow2(m) * res_hi < pow2(k)) by (nonlinear_arith)
        requires
            res_lo < pow2(m),
            res_hi < pow2(m),
            pow2(k) == pow2(m) * pow2(m),
            pow2(m) > 0;

    deg_lt_conv(res, k);
    assert(in_field(res, k));

    assert(gf_mul_tower(a, res, k) == gf_mul_tower(nrm, ninv, m)) by {
        pack_mod_div(res_lo, res_hi, m);

        assert(lo_half(res, k) == res_lo);
        assert(hi_half(res, k) == res_hi);

        gf_mul_tower_unfold(a, res, k);

        assert(thi(lo, hi, res_lo, res_hi, m) == 0) by {
            gf_mul_tower_distrib_l(hi, lo, ninv, m);
            gf_mul_tower_distrib_r(hi, gf_mul_tower(hi, ninv, m), gf_mul_tower(lo, ninv, m), m);

            let pp = gf_mul_tower(lo, gf_mul_tower(hi, ninv, m), m);
            let qq = gf_mul_tower(hi, gf_mul_tower(hi, ninv, m), m);
            let rr = gf_mul_tower(hi, gf_mul_tower(lo, ninv, m), m);

            gf_mul_tower_assoc(lo, hi, ninv, m);
            gf_mul_tower_assoc(hi, lo, ninv, m);
            gf_mul_tower_comm(lo, hi, m);

            assert(pp == rr);

            xor_comm(qq, rr);
            xor_assoc(rr, rr, qq);
            xor_self(rr);
            xor_zero(qq);
            xor_self(qq);
        }

        assert(tlo(lo, hi, res_lo, res_hi, m) == gf_mul_tower(nrm, ninv, m)) by {
            gf_mul_tower_distrib_l(hi, lo, ninv, m);
            gf_mul_tower_distrib_r(lo, gf_mul_tower(hi, ninv, m), gf_mul_tower(lo, ninv, m), m);
            gf_mul_tower_distrib_l(xor(gf_mul_tower(lo, lo, m), gf_mul_tower(lo, hi, m)),
                gf_mul_tower(gf_mul_tower(hi, hi, m), t, m), ninv, m);
            gf_mul_tower_distrib_l(gf_mul_tower(lo, lo, m), gf_mul_tower(lo, hi, m), ninv, m);

            let pp = gf_mul_tower(lo, gf_mul_tower(hi, ninv, m), m);
            let ss = gf_mul_tower(lo, gf_mul_tower(lo, ninv, m), m);

            gf_mul_tower_assoc(lo, lo, ninv, m);
            gf_mul_tower_assoc(lo, hi, ninv, m);
            gf_mul_tower_assoc(hi, hi, ninv, m);
            gf_mul_tower_assoc(gf_mul_tower(hi, hi, m), ninv, t, m);
            gf_mul_tower_comm(ninv, t, m);
            gf_mul_tower_assoc(gf_mul_tower(hi, hi, m), t, ninv, m);

            xor_comm(pp, ss);
        }

        assert(gf_mul_tower(a, res, k)
            == tlo(lo, hi, res_lo, res_hi, m) + pow2(m) * thi(lo, hi, res_lo, res_hi, m));
    }

    if a == 0 {
        assert(lo == a % pow2(m));
        assert(hi == a / pow2(m));
        assert(lo == 0 && hi == 0) by (nonlinear_arith)
            requires
                a == 0,
                lo == a % pow2(m),
                hi == a / pow2(m),
                pow2(m) > 0;

        gf_mul_tower_zero_l(ninv, m);

        assert(xor(hi, lo) == 0);
        assert(res_lo == 0);
        assert(res_hi == 0);
        assert(pow2(m) * res_hi == 0) by (nonlinear_arith)
            requires res_hi == 0;

        assert(res == 0);
    } else {
        norm_nonzero(a, k);
        assert(gf_mul_tower(a, res, k) == 1);
    }
}

// A GF(2)-linear map (over xor) on the field is fixed by its values on the
// power-of-two basis: two such maps agreeing on every pow2(i), i < k,
// agree on all field elements.
pub proof fn linear_determined_field(
    f: spec_fn(nat) -> nat,
    g: spec_fn(nat) -> nat,
    x: nat,
    k: nat,
)
    requires
        in_field(x, k),
        forall|u: nat, v: nat| in_field(u, k) && in_field(v, k)
            ==> #[trigger] f(xor(u, v)) == xor(f(u), f(v)),
        forall|u: nat, v: nat| in_field(u, k) && in_field(v, k)
            ==> #[trigger] g(xor(u, v)) == xor(g(u), g(v)),
        forall|i: nat| i < k ==> #[trigger] f(pow2(i)) == g(pow2(i)),
    ensures f(x) == g(x)
    decreases x
{
    assert(deg(0) == -1);

    if x == 0 {
        assert(in_field(0nat, k));

        xor_zero(0nat);

        assert(f(xor(0nat, 0nat)) == xor(f(0nat), f(0nat)));
        assert(g(xor(0nat, 0nat)) == xor(g(0nat), g(0nat)));

        xor_self(f(0nat));
        xor_self(g(0nat));
    } else {
        deg_ge_neg1(x);
        deg_zero_iff(x);

        assert(deg(x) >= 0);

        let d = deg(x) as nat;
        assert(d < k);

        deg_pow2(d);
        assert(in_field(pow2(d), k));

        let x2 = xor(x, pow2(d));
        deg_xor_cancel(x, pow2(d));
        assert(deg(x2) < d);
        assert(in_field(x2, k));

        deg_upper(x2, d);
        deg_lower(x);

        assert(x2 < x);

        xor_assoc(x, pow2(d), pow2(d));
        xor_self(pow2(d));
        xor_zero(x);

        assert(x == xor(x2, pow2(d)));

        linear_determined_field(f, g, x2, k);

        assert(f(pow2(d)) == g(pow2(d)));
        assert(f(xor(x2, pow2(d))) == xor(f(x2), f(pow2(d))));
        assert(g(xor(x2, pow2(d))) == xor(g(x2), g(pow2(d))));
    }
}

// ============================================================
// Squaring: additive in char 2
// (a+b)^2 == a^2 + b^2, cross terms cancel
// ============================================================

pub proof fn gf_sq_additive(a: nat, b: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures gf_mul(xor(a, b), xor(a, b), k) == xor(gf_mul(a, a, k), gf_mul(b, b, k))
{
    let s = xor(a, b);

    gf_distrib(s, a, b, k);
    gf_mul_comm(s, a, k);
    gf_distrib(a, a, b, k);
    gf_mul_comm(s, b, k);
    gf_distrib(b, a, b, k);

    let aa = gf_mul(a, a, k);
    let ab = gf_mul(a, b, k);
    let bb = gf_mul(b, b, k);

    gf_mul_comm(a, b, k);

    assert(gf_mul(s, s, k) == xor(xor(aa, ab), xor(ab, bb)));

    xor_comm(ab, bb);
    xor_rearrange4(aa, ab, bb, ab);
    xor_self(ab);
    xor_zero(xor(aa, bb));
}

pub proof fn gf_mul_tower_sq_additive(a: nat, b: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures
        gf_mul_tower(xor(a, b), xor(a, b), k)
            == xor(gf_mul_tower(a, a, k), gf_mul_tower(b, b, k))
{
    let s = xor(a, b);

    gf_mul_tower_distrib_r(s, a, b, k);
    gf_mul_tower_distrib_l(a, b, a, k);
    gf_mul_tower_distrib_l(a, b, b, k);

    let aa = gf_mul_tower(a, a, k);
    let ab = gf_mul_tower(a, b, k);
    let bb = gf_mul_tower(b, b, k);

    gf_mul_tower_comm(a, b, k);

    assert(gf_mul_tower(s, s, k) == xor(xor(aa, ab), xor(ab, bb)));

    xor_comm(ab, bb);
    xor_rearrange4(aa, ab, bb, ab);
    xor_self(ab);
    xor_zero(xor(aa, bb));
}

// Diagonal of the tower unfold: the cross terms are
// equal and cancel, squaring never mixes the halves.
pub proof fn gf_mul_tower_square_unfold(a: nat, k: nat)
    requires k == 16 || k == 32 || k == 64 || k == 128 || k == 256,
    ensures ({
        let m = (k / 2) as nat;
        let a0 = lo_half(a, k);
        let a1 = hi_half(a, k);
        let sq1 = gf_mul_tower(a1, a1, m);

        gf_mul_tower(a, a, k)
            == xor(gf_mul_tower(a0, a0, m), gf_mul_tower(sq1, tau_tower(m), m))
                + pow2(m) * sq1
    })
{
    let m = (k / 2) as nat;
    let a0 = lo_half(a, k);
    let a1 = hi_half(a, k);

    gf_mul_tower_unfold(a, a, k);
    gf_mul_tower_comm(a0, a1, m);

    let cross = gf_mul_tower(a0, a1, m);
    let sq1 = gf_mul_tower(a1, a1, m);

    xor_self(cross);
    xor_zero(sq1);

    assert(thi(a0, a1, a0, a1, m) == sq1);
}

// ============================================================
// Frobenius order and trace
// x^(2^k) == x on GF(2^k); Tr(x)^2 == Tr(x)
// ============================================================

// e-fold tower squaring: x^(2^e).
pub open spec fn pow_2exp(x: nat, e: nat, k: nat) -> nat
    decreases e
{
    if e == 0 {
        x
    } else {
        let p = pow_2exp(x, (e - 1) as nat, k);
        gf_mul_tower(p, p, k)
    }
}

// Absolute trace over GF(2): sum of the first n
// Frobenius iterates, Tr = trace_spec(x, k, k).
pub open spec fn trace_spec(x: nat, n: nat, k: nat) -> nat
    decreases n
{
    if n == 0 {
        0
    } else {
        xor(trace_spec(x, (n - 1) as nat, k), pow_2exp(x, (n - 1) as nat, k))
    }
}

pub proof fn pow_2exp_additive(u: nat, v: nat, e: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures pow_2exp(xor(u, v), e, k) == xor(pow_2exp(u, e, k), pow_2exp(v, e, k))
    decreases e
{
    if e == 0 {
    } else {
        pow_2exp_additive(u, v, (e - 1) as nat, k);
        gf_mul_tower_sq_additive(
            pow_2exp(u, (e - 1) as nat, k),
            pow_2exp(v, (e - 1) as nat, k),
            k,
        );
    }
}

pub proof fn pow_2exp_add(x: nat, e1: nat, e2: nat, k: nat)
    ensures pow_2exp(x, e1 + e2, k) == pow_2exp(pow_2exp(x, e1, k), e2, k)
    decreases e2
{
    if e2 == 0 {
    } else {
        pow_2exp_add(x, e1, (e2 - 1) as nat, k);
        assert(e1 + e2 - 1 == e1 + (e2 - 1));
    }
}

// x^(2^k) == x for every field element: the generator axiom
// extends over GF(2)-linearity (squaring is additive).
pub proof fn frobenius_order(x: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        in_field(x, k),
    ensures pow_2exp(x, k, k) == x
{
    let f = |y: nat| pow_2exp(y, k, k);
    let g = |y: nat| y;

    assert forall|u: nat, v: nat| in_field(u, k) && in_field(v, k)
        implies #[trigger] f(xor(u, v)) == xor(f(u), f(v)) by {
        pow_2exp_additive(u, v, k, k);
    }

    assert forall|u: nat, v: nat| in_field(u, k) && in_field(v, k)
        implies #[trigger] g(xor(u, v)) == xor(g(u), g(v)) by {
    }

    assert forall|i: nat| i < k implies #[trigger] f(pow2(i)) == g(pow2(i)) by {
        frobenius_order_gen(i, k);
    }

    linear_determined_field(f, g, x, k);
}

// Justifies production frobenius's `k % BITS` reduction.
pub proof fn frobenius_mod_cycle(x: nat, e: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        in_field(x, k),
    ensures pow_2exp(x, e, k) == pow_2exp(x, (e % k) as nat, k)
    decreases e
{
    if e < k {
        assert(e % k == e);
    } else {
        pow_2exp_add(x, k, (e - k) as nat, k);
        frobenius_order(x, k);
        frobenius_mod_cycle(x, (e - k) as nat, k);

        assert(((e - k) as nat) % k == e % k) by (nonlinear_arith)
            requires e >= k, k > 0;
    }
}

proof fn trace_sq_shift(x: nat, n: nat, k: nat)
    requires k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
    ensures ({
        let t = trace_spec(x, n, k);
        gf_mul_tower(t, t, k) == xor(trace_spec(x, n + 1, k), x)
    })
    decreases n
{
    if n == 0 {
        gf_mul_tower_zero_l(0, k);
        xor_zero(x);
        xor_self(x);
        xor_comm(0, x);

        assert(trace_spec(x, 0, k) == 0);
        assert(trace_spec(x, 1, k) == xor(0, pow_2exp(x, 0, k)));
    } else {
        trace_sq_shift(x, (n - 1) as nat, k);

        let t = trace_spec(x, (n - 1) as nat, k);
        let p = pow_2exp(x, (n - 1) as nat, k);

        gf_mul_tower_sq_additive(t, p, k);

        let sq_t = gf_mul_tower(t, t, k);
        let sq_p = gf_mul_tower(p, p, k);

        assert(sq_p == pow_2exp(x, n, k));
        assert(sq_t == xor(trace_spec(x, n, k), x));

        xor_comm(trace_spec(x, n, k), x);
        xor_assoc(x, trace_spec(x, n, k), sq_p);
        xor_comm(x, xor(trace_spec(x, n, k), sq_p));

        assert(trace_spec(x, n + 1, k) == xor(trace_spec(x, n, k), sq_p));
    }
}

// Tr(x)^2 == Tr(x): the trace lands in the
// Frobenius-fixed subfield GF(2).
pub proof fn trace_idempotent(x: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        in_field(x, k),
    ensures ({
        let t = trace_spec(x, k, k);
        gf_mul_tower(t, t, k) == t
    })
{
    trace_sq_shift(x, k, k);
    frobenius_order(x, k);

    let t = trace_spec(x, k, k);

    assert(trace_spec(x, k + 1, k) == xor(t, x));

    xor_assoc(t, x, x);
    xor_self(x);
    xor_zero(t);
}

// ============================================================
// Basis isomorphism  phi : tower <-> flat
// ============================================================

// The 128-bit multiplicative query is not SMT-dischargeable;
// roundtrip and the generator homomorphism are proven
// exhaustively at build time (build/main.rs::verify_isomorphism_128:
// mutual inverse + homomorphism on all 128x128 generators) and carried
// as axioms about the uninterpreted basis columns in axioms_t.rs.
pub uninterp spec fn phi_basis(i: nat, k: nat) -> nat;

// φ is the column map of the tower->flat matrix: the XOR of
// basis columns over the set bits, the same shape as the
// production map_ct kernels (verus/neon/convert.rs::bit_comb).
// Additivity is therefore a theorem, not an axiom.
pub closed spec fn phi_fold(x: nat, n: nat, k: nat) -> nat
    decreases n
{
    if n == 0 {
        0
    } else {
        xor(
            phi_fold(x, (n - 1) as nat, k),
            if (x / pow2((n - 1) as nat)) % 2 == 1 { phi_basis((n - 1) as nat, k) } else { 0 },
        )
    }
}

pub closed spec fn phi(x: nat, k: nat) -> nat {
    phi_fold(x, k, k)
}

pub uninterp spec fn phi_inv(x: nat, k: nat) -> nat;

// Bit i of an xor is the xor of the bits.
proof fn xor_bit_at(a: nat, b: nat, i: nat)
    ensures (xor(a, b) / pow2(i)) % 2 == ((a / pow2(i)) % 2 + (b / pow2(i)) % 2) % 2
    decreases i
{
    if i == 0 {
        assert(pow2(0) == 1);

        xor_bits(a, b);
    } else {
        xor_bits(a, b);
        xor_bit_at(a / 2, b / 2, (i - 1) as nat);

        let h = pow2((i - 1) as nat);

        pow2_pos((i - 1) as nat);

        assert(pow2(i) == 2 * h);

        vstd::arithmetic::div_mod::lemma_div_denominator(xor(a, b) as int, 2, h as int);
        vstd::arithmetic::div_mod::lemma_div_denominator(a as int, 2, h as int);
        vstd::arithmetic::div_mod::lemma_div_denominator(b as int, 2, h as int);
    }
}

proof fn phi_fold_additive(a: nat, b: nat, n: nat, k: nat)
    ensures phi_fold(xor(a, b), n, k) == xor(phi_fold(a, n, k), phi_fold(b, n, k))
    decreases n
{
    if n == 0 {
    } else {
        let m = (n - 1) as nat;
        let e = phi_basis(m, k);
        let ba = (a / pow2(m)) % 2;
        let bb = (b / pow2(m)) % 2;
        let sa: nat = if ba == 1 { e } else { 0 };
        let sb: nat = if bb == 1 { e } else { 0 };

        phi_fold_additive(a, b, m, k);
        xor_bit_at(a, b, m);

        assert(xor(sa, sb) == (if (xor(a, b) / pow2(m)) % 2 == 1 { e } else { 0nat })) by {
            if ba == 1 && bb == 1 {
                xor_self(e);
            } else {
                xor_zero(sa);
                xor_zero(sb);
                xor_comm(sa, sb);
            }
        }

        xor_rearrange4(phi_fold(a, m, k), sa, phi_fold(b, m, k), sb);
        xor_comm(sa, phi_fold(b, m, k));
        xor_rearrange4(phi_fold(a, m, k), phi_fold(b, m, k), sa, sb);
    }
}

// Retired axiom:
// XOR-linearity of the column map is structural.
pub proof fn phi_additive(a: nat, b: nat, k: nat)
    requires in_field(a, k), in_field(b, k)
    ensures phi(gf_add(a, b), k) == gf_add(phi(a, k), phi(b, k))
{
    phi_fold_additive(a, b, k, k);
}

// Generator times any field element, by bilinear extension over the 2nd operand.
proof fn phi_mult_row(i: nat, b: nat)
    requires i < 128, in_field(b, 128)
    ensures
        phi(gf_mul_tower(pow2(i), b, 128), 128)
            == gf_mul(phi(pow2(i), 128), phi(b, 128), 128)
{
    let p = pow2(i);
    let f = |y: nat| phi(gf_mul_tower(p, y, 128), 128);
    let g = |y: nat| gf_mul(phi(p, 128), phi(y, 128), 128);

    assert forall|u: nat, v: nat| in_field(u, 128) && in_field(v, 128)
        implies #[trigger] f(xor(u, v)) == xor(f(u), f(v)) by {
        gf_mul_tower_distrib_r(p, u, v, 128);
        gf_mul_tower_bound(p, u, 128);
        gf_mul_tower_bound(p, v, 128);

        deg_lt_conv(gf_mul_tower(p, u, 128), 128);
        deg_lt_conv(gf_mul_tower(p, v, 128), 128);

        phi_additive(gf_mul_tower(p, u, 128), gf_mul_tower(p, v, 128), 128);
    }

    assert forall|u: nat, v: nat| in_field(u, 128) && in_field(v, 128)
        implies #[trigger] g(xor(u, v)) == xor(g(u), g(v)) by {
        phi_additive(u, v, 128);
        gf_distrib(phi(p, 128), phi(u, 128), phi(v, 128), 128);
    }

    assert forall|j: nat| j < 128 implies #[trigger] f(pow2(j)) == g(pow2(j)) by {
        phi_mult_gen(i, j);
    }

    linear_determined_field(f, g, b, 128);
}

// Full multiplicative homomorphism of the tower->flat map, derived from the
// generator axiom phi_mult_gen by bilinear extension over the first operand.
// Scoped to k = 128, the level build/main.rs::verify_isomorphism_128 checks.
pub proof fn phi_multiplicative(a: nat, b: nat, k: nat)
    requires k == 128, in_field(a, k), in_field(b, k)
    ensures phi(gf_mul_tower(a, b, k), k) == gf_mul(phi(a, k), phi(b, k), k)
{
    let f = |y: nat| phi(gf_mul_tower(y, b, 128), 128);
    let g = |y: nat| gf_mul(phi(y, 128), phi(b, 128), 128);

    assert forall|u: nat, v: nat| in_field(u, 128) && in_field(v, 128)
        implies #[trigger] f(xor(u, v)) == xor(f(u), f(v)) by {
        gf_mul_tower_distrib_l(u, v, b, 128);
        gf_mul_tower_bound(u, b, 128);
        gf_mul_tower_bound(v, b, 128);

        deg_lt_conv(gf_mul_tower(u, b, 128), 128);
        deg_lt_conv(gf_mul_tower(v, b, 128), 128);

        phi_additive(gf_mul_tower(u, b, 128), gf_mul_tower(v, b, 128), 128);
    }

    assert forall|u: nat, v: nat| in_field(u, 128) && in_field(v, 128)
        implies #[trigger] g(xor(u, v)) == xor(g(u), g(v)) by {
        phi_additive(u, v, 128);
        gf_mul_comm(xor(phi(u, 128), phi(v, 128)), phi(b, 128), 128);
        gf_distrib(phi(b, 128), phi(u, 128), phi(v, 128), 128);
        gf_mul_comm(phi(b, 128), phi(u, 128), 128);
        gf_mul_comm(phi(b, 128), phi(v, 128), 128);
    }

    assert forall|i: nat| i < 128 implies #[trigger] f(pow2(i)) == g(pow2(i)) by {
        phi_mult_row(i, b);
    }

    linear_determined_field(f, g, a, 128);
}

pub proof fn phi_is_field_iso(a: nat, b: nat, k: nat)
    requires k == 128, in_field(a, k), in_field(b, k)
    ensures
        phi_inv(phi(a, k), k) == a,
        phi(gf_add(a, b), k) == gf_add(phi(a, k), phi(b, k)),
        phi(gf_mul_tower(a, b, k), k) == gf_mul(phi(a, k), phi(b, k), k),
{
    phi_roundtrip(a, k);
    phi_additive(a, b, k);
    phi_multiplicative(a, b, k);
}

fn main() {}

}
