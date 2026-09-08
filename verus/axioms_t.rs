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

#[verifier::external_body]
pub proof fn phi_roundtrip(x: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        in_field(x, k),
    ensures phi_inv(phi(x, k), k) == x
{}

#[verifier::external_body]
pub proof fn phi_mult_gen(i: nat, j: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        i < k,
        j < k,
    ensures
        phi(gf_mul_tower(pow2(i), pow2(j), k), k)
            == gf_mul(phi(pow2(i), k), phi(pow2(j), k), k)
{}

#[verifier::external_body]
pub proof fn norm_nonzero(a: nat, k: nat)
    requires
        k == 16 || k == 32 || k == 64 || k == 128 || k == 256,
        in_field(a, k),
        a != 0,
    ensures ext_norm(lo_half(a, k), hi_half(a, k), (k / 2) as nat) != 0,
{}

#[verifier::external_body]
pub proof fn frobenius_order_gen(i: nat, k: nat)
    requires
        k == 8 || k == 16 || k == 32 || k == 64 || k == 128,
        i < k,
    ensures pow_2exp(pow2(i), k, k) == pow2(i)
{}

} // verus!
