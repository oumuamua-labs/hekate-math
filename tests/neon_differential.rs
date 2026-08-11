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

//! Differential tie for the flat-path kernels: multiplies,
//! packed kernels, and batch promotes against references that
//! share no code with them. The `verus/` proofs model the ISA;
//! this suite is what ties that model to real silicon.
//! Exhaustive where cheaply total (8/16-bit pairs, single-bit
//! products, nibble bases). Heavy cases are release-only.

use hekate_math::{
    Block8, Block16, Block32, Block64, Block128, Block256, Flat, FlatPromote, HardwareField,
    PackableField,
};
use rand::{RngExt, SeedableRng, rngs::StdRng};

#[cfg(feature = "parallel")]
use rayon::prelude::*;

#[allow(dead_code)]
mod gf_oracle {
    include!(concat!(env!("CARGO_MANIFEST_DIR"), "/build/gf_oracle.rs"));
}

use gf_oracle::schoolbook16;

// ============================================================
// Soft flat oracle: shift-and-xor carry-less multiply, then
// top-down reduction mod x^k + poly. Plain Rust, no NEON, no
// production code — an independent transcription of gf_model's
// gf_mul = pmod(clmul(a, b), modulus(k)).
// ============================================================

fn gf_soft(a: u128, b: u128, k: u32, poly: u128) -> u128 {
    let mut lo = 0u128;
    let mut hi = 0u128;

    for i in 0..k {
        if (b >> i) & 1 == 1 {
            lo ^= a << i;

            if i > 0 {
                hi ^= a >> (128 - i);
            }
        }
    }

    for i in (0..128u32).rev() {
        if (hi >> i) & 1 == 1 {
            hi ^= 1u128 << i;
            lo ^= poly << i;

            if i > 0 {
                hi ^= poly >> (128 - i);
            }
        }
    }

    for i in (k..128).rev() {
        if (lo >> i) & 1 == 1 {
            lo ^= (1u128 << i) ^ (poly << (i - k));
        }
    }

    lo
}

fn gf_soft8(a: u8, b: u8) -> u8 {
    gf_soft(a as u128, b as u128, 8, 0x1b) as u8
}

fn gf_soft16(a: u16, b: u16) -> u16 {
    gf_soft(a as u128, b as u128, 16, 0x2b) as u16
}

fn gf_soft32(a: u32, b: u32) -> u32 {
    gf_soft(a as u128, b as u128, 32, 0x8d) as u32
}

fn gf_soft64(a: u64, b: u64) -> u64 {
    gf_soft(a as u128, b as u128, 64, 0x1b) as u64
}

fn gf_soft128(a: u128, b: u128) -> u128 {
    gf_soft(a, b, 128, 0x87)
}

// Wrong-oracle guard: FIPS-197 §4.2 pins the 8-bit field;
// x^k mod (x^k + poly) = poly pins every reduction width.
#[test]
fn soft_oracle_pins() {
    assert_eq!(gf_soft8(0x57, 0x83), 0xc1, "AES worked example");

    assert_eq!(gf_soft(1 << 7, 2, 8, 0x1b), 0x1b);
    assert_eq!(gf_soft(1 << 15, 2, 16, 0x2b), 0x2b);
    assert_eq!(gf_soft(1 << 31, 2, 32, 0x8d), 0x8d);
    assert_eq!(gf_soft(1 << 63, 2, 64, 0x1b), 0x1b);
    assert_eq!(gf_soft(1 << 127, 2, 128, 0x87), 0x87);

    let mut r = StdRng::seed_from_u64(0xD1FF);
    for _ in 0..64 {
        let x: u128 = r.random();
        assert_eq!(gf_soft128(x, 1), x);
        assert_eq!(gf_soft128(1, x), x);
    }
}

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
// Scalar flat multiply vs the soft oracle
// ============================================================

#[test]
fn flat_mul_8_exhaustive_vs_soft() {
    for a in 0u16..=255 {
        for b in 0u16..=255 {
            let (a, b) = (a as u8, b as u8);
            let fa = Flat::from_raw(Block8(a));
            let fb = Flat::from_raw(Block8(b));

            assert_eq!(
                Block8::mul_hardware(fa, fb).into_raw().0,
                gf_soft8(a, b),
                "flat mul 8: {a:#04x} * {b:#04x}",
            );
        }
    }
}

fn check_flat16(a: u16) {
    let fa = Flat::from_raw(Block16(a));

    for b in 0u16..=0xffff {
        let fb = Flat::from_raw(Block16(b));

        assert_eq!(
            Block16::mul_hardware(fa, fb).into_raw().0,
            gf_soft16(a, b),
            "flat mul 16: {a:#06x} * {b:#06x}",
        );
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore = "heavy; release only")]
fn flat_mul_16_exhaustive_vs_soft() {
    #[cfg(feature = "parallel")]
    (0u32..0x1_0000)
        .into_par_iter()
        .for_each(|a| check_flat16(a as u16));

    #[cfg(not(feature = "parallel"))]
    for a in 0u16..=0xffff {
        check_flat16(a);
    }
}

// Single-bit × single-bit products are the bilinear map's basis:
// a wrong limb recombination, lane swap, or fold wiring is
// input-oblivious, generator coverage exercises every wire.
// Bilinearity itself is the `verus/` theorems' claim, not this test's.
#[test]
fn flat_single_bit_exhaustive_32_64_128() {
    for i in 0..32 {
        for j in 0..32 {
            let (a, b) = (1u32 << i, 1u32 << j);
            let fa = Flat::from_raw(Block32(a));
            let fb = Flat::from_raw(Block32(b));

            assert_eq!(
                Block32::mul_hardware(fa, fb).into_raw().0,
                gf_soft32(a, b),
                "flat mul 32: bit {i} * bit {j}",
            );
        }
    }

    for i in 0..64 {
        for j in 0..64 {
            let (a, b) = (1u64 << i, 1u64 << j);
            let fa = Flat::from_raw(Block64(a));
            let fb = Flat::from_raw(Block64(b));

            assert_eq!(
                Block64::mul_hardware(fa, fb).into_raw().0,
                gf_soft64(a, b),
                "flat mul 64: bit {i} * bit {j}",
            );
        }
    }

    for i in 0..128 {
        for j in 0..128 {
            let (a, b) = (1u128 << i, 1u128 << j);
            let fa = Flat::from_raw(Block128(a));
            let fb = Flat::from_raw(Block128(b));

            assert_eq!(
                Block128::mul_hardware(fa, fb).into_raw().0,
                gf_soft128(a, b),
                "flat mul 128: bit {i} * bit {j}",
            );
        }
    }
}

// Random sampling does not reach the fold chain's carry lanes.
#[test]
fn flat_reduction_edges_64_128() {
    const E64: [u64; 8] = [
        0,
        1,
        0x1b,
        u64::MAX,
        1 << 63,
        (1 << 63) | 1,
        u32::MAX as u64,
        (u32::MAX as u64) << 32,
    ];

    const E128: [u128; 8] = [
        0,
        1,
        0x87,
        u128::MAX,
        1 << 127,
        (1 << 127) | 1,
        u64::MAX as u128,
        (u64::MAX as u128) << 64,
    ];

    for (i, &x0) in E64.iter().enumerate() {
        for (j, &y0) in E64.iter().enumerate() {
            let (x1, y1) = (E64[7 - i], E64[7 - j]);

            let a = [Flat::from_raw(Block64(x0)), Flat::from_raw(Block64(x1))];
            let b = [Flat::from_raw(Block64(y0)), Flat::from_raw(Block64(y1))];

            assert_eq!(
                Block64::mul_hardware(a[0], b[0]).into_raw().0,
                gf_soft64(x0, y0),
                "flat mul 64: {x0:#018x} * {y0:#018x}",
            );

            let pc = Block64::mul_hardware_packed(
                <Flat<Block64> as PackableField>::pack(&a),
                <Flat<Block64> as PackableField>::pack(&b),
            );

            let mut out = [Flat::<Block64>::default(); 2];
            <Flat<Block64> as PackableField>::unpack(pc, &mut out);

            assert_eq!(
                out[0].into_raw().0,
                gf_soft64(x0, y0),
                "packed mul 64 lane 0: {x0:#018x} * {y0:#018x}",
            );
            assert_eq!(
                out[1].into_raw().0,
                gf_soft64(x1, y1),
                "packed mul 64 lane 1: {x1:#018x} * {y1:#018x}",
            );
        }
    }

    for &x in &E128 {
        for &y in &E128 {
            let fa = Flat::from_raw(Block128(x));
            let fb = Flat::from_raw(Block128(y));

            assert_eq!(
                Block128::mul_hardware(fa, fb).into_raw().0,
                gf_soft128(x, y),
                "flat mul 128: {x:#034x} * {y:#034x}",
            );
        }
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore = "heavy; release only")]
fn flat_randomized_32_64_128_vs_soft() {
    par_differential(2_000_000, 0x32f1a7, |r| {
        let (a, b): (u32, u32) = (r.random(), r.random());

        assert_eq!(
            Block32::mul_hardware(Flat::from_raw(Block32(a)), Flat::from_raw(Block32(b)))
                .into_raw()
                .0,
            gf_soft32(a, b),
            "flat mul 32: {a:#010x} * {b:#010x}",
        );
    });

    par_differential(2_000_000, 0x64f1a7, |r| {
        let (a, b): (u64, u64) = (r.random(), r.random());

        assert_eq!(
            Block64::mul_hardware(Flat::from_raw(Block64(a)), Flat::from_raw(Block64(b)))
                .into_raw()
                .0,
            gf_soft64(a, b),
            "flat mul 64: {a:#018x} * {b:#018x}",
        );
    });

    par_differential(500_000, 0x128f1a7, |r| {
        let (a, b): (u128, u128) = (r.random(), r.random());

        assert_eq!(
            Block128::mul_hardware(Flat::from_raw(Block128(a)), Flat::from_raw(Block128(b)))
                .into_raw()
                .0,
            gf_soft128(a, b),
            "flat mul 128: {a:#034x} * {b:#034x}",
        );
    });
}

// ============================================================
// The commuting square on silicon:
// mul_flat(φa, φb) == φ(a ·tower b), oracle-side tower product
// ============================================================

#[test]
fn flat_vs_tower_via_phi_8_exhaustive() {
    for a in 0u16..=255 {
        for b in 0u16..=255 {
            let (a, b) = (Block8(a as u8), Block8(b as u8));

            assert_eq!(
                Block8::mul_hardware(a.to_hardware(), b.to_hardware()),
                (a * b).to_hardware(),
                "phi square 8: {:#04x} * {:#04x}",
                a.0,
                b.0,
            );
        }
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore = "heavy; release only")]
fn flat_vs_tower_via_phi_16_exhaustive() {
    let to_hw: Vec<u16> = (0..=u16::MAX)
        .map(|x| Block16(x).to_hardware().into_raw().0)
        .collect();

    let check = |a: u16| {
        let fa = Flat::from_raw(Block16(to_hw[a as usize]));

        for b in 0u16..=0xffff {
            let fb = Flat::from_raw(Block16(to_hw[b as usize]));
            let prod = schoolbook16(a, b);

            assert_eq!(
                Block16::mul_hardware(fa, fb).into_raw().0,
                to_hw[prod as usize],
                "phi square 16: {a:#06x} * {b:#06x}",
            );
        }
    };

    #[cfg(feature = "parallel")]
    (0u32..0x1_0000)
        .into_par_iter()
        .for_each(|a| check(a as u16));

    #[cfg(not(feature = "parallel"))]
    for a in 0u16..=0xffff {
        check(a);
    }
}

// ============================================================
// Packed kernels vs the scalar kernel, lane by lane
// ============================================================

// Every (a, b) pair passes through every lane position: the
// rotation moves each pair across all 16 lanes, so a lane swap
// or a wrong TBL half in the packed fold cannot hide.
#[test]
fn packed_vs_scalar_8_exhaustive_all_lanes() {
    for rot in 0..16u16 {
        for a_hi in 0..16u16 {
            for b in 0u16..=255 {
                let lanes_a: [Flat<Block8>; 16] = core::array::from_fn(|l| {
                    Flat::from_raw(Block8((a_hi * 16 + ((l as u16 + rot) % 16)) as u8))
                });

                // A lane-uniform operand cannot see same-side crosstalk
                let lanes_b: [Flat<Block8>; 16] = core::array::from_fn(|l| {
                    Flat::from_raw(Block8((b as u8).wrapping_add(l as u8)))
                });

                let pa = <Flat<Block8> as PackableField>::pack(&lanes_a);
                let pb = <Flat<Block8> as PackableField>::pack(&lanes_b);
                let pc = Block8::mul_hardware_packed(pa, pb);

                let mut out = [Flat::<Block8>::default(); 16];
                <Flat<Block8> as PackableField>::unpack(pc, &mut out);

                for (l, got) in out.iter().enumerate() {
                    assert_eq!(
                        *got,
                        Block8::mul_hardware(lanes_a[l], lanes_b[l]),
                        "packed 8: rot={rot} a_hi={a_hi} b={b:#04x} lane={l}",
                    );
                }
            }
        }
    }
}

// Lane l sees pair (a + l·0x2001, b_block·8 + l):
// all 2^32 pairs are covered, each in the lane fixed
// by b mod 8 (2^29 pairs per lane), and both operands
// stay lane-distinct, same-side crosstalk cannot hide.
fn check_packed16(a: u16) {
    let lanes_a: [Flat<Block16>; 8] =
        core::array::from_fn(|l| Flat::from_raw(Block16(a.wrapping_add(l as u16 * 0x2001))));
    let pa = <Flat<Block16> as PackableField>::pack(&lanes_a);

    for b_block in 0u32..(0x1_0000 / 8) {
        let lanes_b: [Flat<Block16>; 8] =
            core::array::from_fn(|l| Flat::from_raw(Block16((b_block * 8) as u16 + l as u16)));
        let pb = <Flat<Block16> as PackableField>::pack(&lanes_b);
        let pc = Block16::mul_hardware_packed(pa, pb);

        let mut out = [Flat::<Block16>::default(); 8];
        <Flat<Block16> as PackableField>::unpack(pc, &mut out);

        for (l, got) in out.iter().enumerate() {
            assert_eq!(
                *got,
                Block16::mul_hardware(lanes_a[l], lanes_b[l]),
                "packed 16: a={a:#06x} lane={l}",
            );
        }
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore = "heavy; release only")]
fn packed_vs_scalar_16_exhaustive() {
    #[cfg(feature = "parallel")]
    (0u32..0x1_0000)
        .into_par_iter()
        .for_each(|a| check_packed16(a as u16));

    #[cfg(not(feature = "parallel"))]
    for a in 0u16..=0xffff {
        check_packed16(a);
    }
}

// The FFT butterfly's element kernel (additive.rs routes
// mul_hardware_scalar_packed here): all (lane value, scalar)
// pairs, scalar swept exhaustively.
fn check_scalar_packed16(s: u16) {
    let fs = Flat::from_raw(Block16(s));

    for a_block in 0u32..(0x1_0000 / 8) {
        let lanes_a: [Flat<Block16>; 8] =
            core::array::from_fn(|l| Flat::from_raw(Block16((a_block * 8) as u16 + l as u16)));
        let pa = <Flat<Block16> as PackableField>::pack(&lanes_a);
        let pc = Block16::mul_hardware_scalar_packed(pa, fs);

        let mut out = [Flat::<Block16>::default(); 8];
        <Flat<Block16> as PackableField>::unpack(pc, &mut out);

        for (l, got) in out.iter().enumerate() {
            assert_eq!(
                *got,
                Block16::mul_hardware(lanes_a[l], fs),
                "scalar-packed 16: s={s:#06x} lane={l}",
            );
        }
    }
}

#[test]
#[cfg_attr(debug_assertions, ignore = "heavy; release only")]
fn scalar_packed_vs_scalar_16_exhaustive() {
    #[cfg(feature = "parallel")]
    (0u32..0x1_0000)
        .into_par_iter()
        .for_each(|s| check_scalar_packed16(s as u16));

    #[cfg(not(feature = "parallel"))]
    for s in 0u16..=0xffff {
        check_scalar_packed16(s);
    }
}

fn packed_vs_scalar_random<F: HardwareField>(
    sample: impl Fn(&mut StdRng) -> F + Sync,
    batches: usize,
    seed: u64,
    label: &str,
) {
    let w = <Flat<F> as PackableField>::WIDTH;

    par_differential(batches, seed, |r| {
        let a: Vec<Flat<F>> = (0..w).map(|_| sample(r).to_hardware()).collect();
        let b: Vec<Flat<F>> = (0..w).map(|_| sample(r).to_hardware()).collect();

        let pa = <Flat<F> as PackableField>::pack(&a);
        let pb = <Flat<F> as PackableField>::pack(&b);
        let pc = F::mul_hardware_packed(pa, pb);

        let mut out = vec![Flat::<F>::default(); w];
        <Flat<F> as PackableField>::unpack(pc, &mut out);

        for (l, got) in out.iter().enumerate() {
            assert_eq!(*got, F::mul_hardware(a[l], b[l]), "{label}: lane {l}");
        }
    });
}

#[test]
#[cfg_attr(debug_assertions, ignore = "heavy; release only")]
fn packed_vs_scalar_32_64_128_randomized() {
    packed_vs_scalar_random(|r| Block32(r.random()), 500_000, 0x32aa, "packed 32");
    packed_vs_scalar_random(|r| Block64(r.random()), 500_000, 0x64aa, "packed 64");
    packed_vs_scalar_random(|r| Block128(r.random()), 250_000, 0x128aa, "packed 128");
}

// ============================================================
// Batch promotes vs the scalar promote, lane by lane.
//
// The batch kernel is a fixed-dataflow GF(2)-linear map (TBL
// nibble lookups XORed, then a constant TRN transpose): its
// dataflow does not depend on input values, routing errors
// (a wrong table index, a swapped TRN pair) are input-oblivious
// and single-nibble coverage at every lane position exercises
// every wire. Random batches cover the XOR-combine.
// ============================================================

fn promote_basis_exhaustive<Src, const NIBBLES: usize>(make: impl Fn(u8, usize) -> Src, label: &str)
where
    Src: HardwareField,
    Block128: FlatPromote<Src>,
{
    for lane in 0..16 {
        for pos in 0..NIBBLES {
            for v in 1u8..16 {
                let mut input = [Flat::<Src>::default(); 16];
                input[lane] = make(v, pos).to_hardware();

                let mut out = [Flat::<Block128>::default(); 16];
                <Block128 as FlatPromote<Src>>::promote_flat_batch(&input, &mut out);

                for (l, got) in out.iter().enumerate() {
                    assert_eq!(
                        *got,
                        <Block128 as FlatPromote<Src>>::promote_flat(input[l]),
                        "{label}: lane={lane} pos={pos} v={v:#x} out-lane={l}",
                    );
                }
            }
        }
    }
}

fn promote_random_batches<Src>(sample: impl Fn(&mut StdRng) -> Src, seed: u64, label: &str)
where
    Src: HardwareField,
    Block128: FlatPromote<Src>,
{
    let mut r = StdRng::seed_from_u64(seed);

    // Length 40 = two NEON chunks of 16 + a scalar tail of 8.
    for _ in 0..2_000 {
        let input: Vec<Flat<Src>> = (0..40).map(|_| sample(&mut r).to_hardware()).collect();
        let mut out = vec![Flat::<Block128>::default(); 40];

        <Block128 as FlatPromote<Src>>::promote_flat_batch(&input, &mut out);

        for (l, got) in out.iter().enumerate() {
            assert_eq!(
                *got,
                <Block128 as FlatPromote<Src>>::promote_flat(input[l]),
                "{label}: random batch, lane {l}",
            );
        }
    }
}

#[test]
fn promote_batch_8_to_128_basis_exhaustive() {
    promote_basis_exhaustive::<Block8, 2>(|v, pos| Block8(v << (4 * pos)), "promote 8→128");
    promote_random_batches(|r| Block8(r.random()), 0x08128, "promote 8→128");
}

#[test]
fn promote_batch_16_to_128_basis_exhaustive() {
    promote_basis_exhaustive::<Block16, 4>(
        |v, pos| Block16((v as u16) << (4 * pos)),
        "promote 16→128",
    );
    promote_random_batches(|r| Block16(r.random()), 0x16128, "promote 16→128");
}

#[test]
fn promote_batch_32_to_128_basis_exhaustive() {
    promote_basis_exhaustive::<Block32, 8>(
        |v, pos| Block32((v as u32) << (4 * pos)),
        "promote 32→128",
    );
    promote_random_batches(|r| Block32(r.random()), 0x32128, "promote 32→128");
}

// Block256 promotes delegate to the 128 kernels plus a zero
// high half; check the delegation and chunking plumbing.
#[test]
fn promote_to_256_batch_vs_scalar() {
    let mut r = StdRng::seed_from_u64(0x256);

    for _ in 0..500 {
        let input: Vec<Flat<Block8>> = (0..40).map(|_| Block8(r.random()).to_hardware()).collect();
        let mut out = vec![Flat::<Block256>::default(); 40];

        <Block256 as FlatPromote<Block8>>::promote_flat_batch(&input, &mut out);

        for (l, got) in out.iter().enumerate() {
            assert_eq!(
                *got,
                <Block256 as FlatPromote<Block8>>::promote_flat(input[l]),
                "promote 8→256: lane {l}",
            );
        }
    }
}
