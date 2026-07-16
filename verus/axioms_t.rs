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

//! The trusted base, in one file: the `external_body`
//! axioms every theorem in the tree is relative to. Each
//! is discharged exhaustively at build time on the real
//! constants (TRUSTED_AXIOMS.md). Nothing here is proven;
//! `#[path]`-child of `gf_model.rs`, not a standalone unit.

use vstd::prelude::*;

use super::{
    ext_norm, gf_mul, gf_mul_tower, hi_half, in_field, lo_half, phi, phi_inv, pow_2exp, pow2,
};

verus! {

// Mutual inverse of the basis maps on the field:
// build/main.rs::verify_isomorphism_128 checks it on the real
// 128-bit matrices each cargo build. Trusted axiom.
#[verifier::external_body]
pub proof fn phi_roundtrip(x: nat, k: nat)
    requires in_field(x, k)
    ensures phi_inv(phi(x, k), k) == x
{}

// Homomorphism on the single-bit generators, build-discharged at k = 128 by
// build/main.rs::verify_isomorphism_128 (all 128x128 e_i, e_j on the real matrices).
#[verifier::external_body]
pub proof fn phi_mult_gen(i: nat, j: nat)
    requires i < 128, j < 128
    ensures
        phi(gf_mul_tower(pow2(i), pow2(j), 128), 128)
            == gf_mul(phi(pow2(i), 128), phi(pow2(j), 128), 128)
{}

// N(a) = 0 iff a = 0: anisotropy of the norm form, i.e. X^2 + X + tau_tower(m)
// is irreducible over the level-m field (Artin-Schreier: Tr(tau) = 1).
// build/main.rs::verify_norm_anisotropy checks Tr(tau) = 1 for each generated
// EXTENSION_TAU; the trace over GF(2^k) is out of Z3's reach. Trusted axiom.
#[verifier::external_body]
pub proof fn norm_nonzero(a: nat, k: nat)
    requires
        k == 16 || k == 32 || k == 64 || k == 128 || k == 256,
        in_field(a, k),
        a != 0,
    ensures ext_norm(lo_half(a, k), hi_half(a, k), (k / 2) as nat) != 0,
{}

// The 2^k-power map fixes every single-bit generator: out of
// Z3's reach (Lagrange over GF(2^k)), discharged exhaustively
// on the real field by build/main.rs::verify_frobenius_order
// at every cargo build. Trusted axiom.
#[verifier::external_body]
pub proof fn frobenius_order_gen(i: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        i < k,
    ensures pow_2exp(pow2(i), k, k) == pow2(i)
{}

} // verus!
