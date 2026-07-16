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

use hekate_math::{BinaryFieldExtras, Bit, Block16, Block32, Block64, Block128, TowerField};
use rand::{RngExt, SeedableRng, rngs::StdRng};

// Independent trace oracle:
// the squaring-chain definition.
fn trace_via_squaring<F: BinaryFieldExtras>(x: F) -> Bit {
    let mut acc = F::ZERO;
    let mut p = x;

    for _ in 0..F::BITS {
        acc += p;
        p = p.square();
    }

    Bit::new((acc == F::ONE) as u8)
}

fn wide_field_laws<F: BinaryFieldExtras>(mut mk: impl FnMut() -> F) {
    let mut seen_trace_one = false;
    for _ in 0..4096 {
        let x = mk();

        assert_eq!(x.square(), x * x, "square != mul");
        assert_eq!(x.square(), x.frobenius(1), "square != frobenius(1)");
        assert_eq!(
            x.trace(),
            trace_via_squaring(x),
            "mask trace != squaring chain"
        );
        assert_eq!(
            x.square().trace(),
            x.trace(),
            "trace not Frobenius-invariant"
        );

        let c = x.square() + x;
        assert_eq!(c.trace(), Bit::ZERO, "Tr(x^2 + x) != 0");

        let r = F::solve_quadratic(c).expect("Tr = 0 must be solvable");

        assert!(r == x || r == x + F::ONE, "root outside {{x, x + 1}}");
        assert_eq!(r.square() + r, c, "solve round-trip failed");

        if x.trace() == Bit::ONE {
            seen_trace_one = true;

            assert!(F::solve_quadratic(x).is_none(), "solved c with Tr = 1");
        }
    }

    assert!(
        seen_trace_one,
        "trace never 1 in 4096 samples: mask is broken"
    );
}

#[test]
fn block16_square_eq_mul() {
    for v in 0u16..=u16::MAX {
        let x = Block16(v);
        assert_eq!(x.square(), x * x, "square != mul at {v:#06x}");
    }
}

#[test]
fn block16_square_eq_frobenius() {
    for v in 0u16..=u16::MAX {
        let x = Block16(v);
        assert_eq!(
            x.square(),
            x.frobenius(1),
            "square != frobenius(1) at {v:#06x}"
        );
    }
}

#[test]
fn block16_frobenius_periodicity() {
    for v in 0u16..=u16::MAX {
        let x = Block16(v);

        assert_eq!(x.frobenius(0), x);
        assert_eq!(x.frobenius(16), x);
        assert_eq!(x.frobenius(17), x.square());

        let mut p = x;
        for _ in 0..16 {
            p = p.square();
        }

        assert_eq!(p, x, "16-fold square must be identity at {v:#06x}");
    }
}

#[test]
fn block16_frobenius_homomorphism() {
    for a in (0u16..=u16::MAX).step_by(37) {
        for b in (0u16..=u16::MAX).step_by(149) {
            let x = Block16(a);
            let y = Block16(b);

            assert_eq!((x + y).frobenius(3), x.frobenius(3) + y.frobenius(3));
            assert_eq!((x * y).frobenius(3), x.frobenius(3) * y.frobenius(3));
        }
    }
}

#[test]
fn block16_trace_in_gf2_and_additive() {
    for v in 0u16..=u16::MAX {
        let t = Block16(v).trace();
        assert!(
            t == Bit::ZERO || t == Bit::ONE,
            "trace escaped GF(2) at {v:#06x}"
        );
    }

    for a in (0u16..=u16::MAX).step_by(29) {
        for b in (0u16..=u16::MAX).step_by(127) {
            let x = Block16(a);
            let y = Block16(b);

            assert_eq!((x + y).trace(), Bit::new(x.trace().get() ^ y.trace().get()));
        }
    }
}

#[test]
fn block16_trace_frobenius_invariant() {
    for v in 0u16..=u16::MAX {
        let x = Block16(v);
        assert_eq!(
            x.square().trace(),
            x.trace(),
            "Tr(x^2) != Tr(x) at {v:#06x}"
        );
    }

    assert_eq!(
        Block16::ONE.trace(),
        Bit::ZERO,
        "Tr(1) must vanish for GF(2^16)"
    );
}

#[test]
fn block16_trace_mask_eq_squaring_chain() {
    for v in 0u16..=u16::MAX {
        let x = Block16(v);
        assert_eq!(
            x.trace(),
            trace_via_squaring(x),
            "trace mismatch at {v:#06x}"
        );
    }
}

#[test]
fn block16_solve_quadratic_roundtrip() {
    for v in 0u16..=u16::MAX {
        let c = Block16(v);
        match Block16::solve_quadratic(c) {
            Some(r) => {
                assert_eq!(r * r + r, c, "root invalid at {v:#06x}");

                let other = r + Block16::ONE;
                assert_eq!(other * other + other, c, "second root invalid at {v:#06x}");
                assert_eq!(c.trace(), Bit::ZERO, "solved c with Tr != 0 at {v:#06x}");
            }
            None => assert_eq!(c.trace(), Bit::ONE, "rejected solvable c at {v:#06x}"),
        }
    }
}

#[test]
fn block16_solve_quadratic_iff_trace_zero() {
    let mut solvable = 0u32;
    for v in 0u16..=u16::MAX {
        let c = Block16(v);
        let ok = Block16::solve_quadratic(c).is_some();

        assert_eq!(
            ok,
            c.trace() == Bit::ZERO,
            "solvability != (Tr == 0) at {v:#06x}"
        );

        if ok {
            solvable += 1;
        }
    }

    assert_eq!(solvable, 32768, "exactly half of GF(2^16) must be solvable");
}

#[test]
fn block32_field_laws() {
    let mut r = StdRng::seed_from_u64(0x5eed_a15e_0b7a_0032);
    wide_field_laws(|| Block32(r.random()));
}

#[test]
fn block64_field_laws() {
    let mut r = StdRng::seed_from_u64(0x5eed_a15e_0b7a_0064);
    wide_field_laws(|| Block64(r.random()));
}

#[test]
fn block128_field_laws() {
    let mut r = StdRng::seed_from_u64(0x5eed_a15e_0b7a_0128);
    wide_field_laws(|| Block128(r.random()));
}
