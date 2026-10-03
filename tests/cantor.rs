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

mod common;

use common::cantor_oracle::CANTOR_TOWER;
use common::{eval_point, horner_eval};
use hekate_math::fft::vanish_eval;
use hekate_math::{
    AdditiveFft, BinaryFieldExtras, Bit, Block16, Block32, Block64, Block128, Block256,
    CantorBasis, CantorError, Flat, HardwareField, TowerField,
};
use rand::{RngExt, SeedableRng, rngs::StdRng};

fn cantor_pinned<F: BinaryFieldExtras + HardwareField>() {
    let dim = F::BITS.min(64);
    let basis = CantorBasis::<F>::new(dim).unwrap();

    assert_eq!(basis.betas().len(), dim);

    for (i, beta) in basis.betas().iter().enumerate() {
        assert_eq!(
            beta.to_tower(),
            F::from(CANTOR_TOWER[i]),
            "{}-bit beta_{i}",
            F::BITS
        );
    }
}

fn cantor_chain_laws<F: BinaryFieldExtras + HardwareField>() {
    let dim = F::BITS.min(64);
    let basis = CantorBasis::<F>::new(dim).unwrap();

    let betas: Vec<F> = basis.betas().iter().map(|b| b.to_tower()).collect();
    assert_eq!(betas[0], F::ONE);

    for (i, &b) in betas.iter().enumerate() {
        assert_eq!(vanish_eval(i, b), F::ONE, "{}-bit s_{i}(beta_{i})", F::BITS);
        assert_eq!(
            b.trace() == Bit::ONE,
            i == F::BITS - 1,
            "{}-bit Tr(beta_{i})",
            F::BITS
        );

        if i >= 1 {
            assert_eq!(
                b.square() + b,
                betas[i - 1],
                "{}-bit sigma(beta_{i})",
                F::BITS
            );
        }
    }
}

fn cantor_point_is_forward_of_x<F: BinaryFieldExtras + HardwareField>(log_n: u32, offset: Flat<F>) {
    let n = 1usize << log_n;
    let fft = AdditiveFft::<F>::new(log_n).unwrap();
    let basis = CantorBasis::<F>::new(log_n as usize).unwrap();

    let mut data = vec![Flat::from_raw(F::ZERO); n];
    data[1] = F::ONE.to_hardware();

    fft.forward_coset_scalar(&mut data, offset).unwrap();

    for (j, &v) in data.iter().enumerate() {
        assert_eq!(
            v,
            offset + basis.point(j).unwrap(),
            "{}-bit point({j})",
            F::BITS
        );
    }
}

fn evaluate_at_eq_forward<F: BinaryFieldExtras + HardwareField>(
    seed: u64,
    mut mk: impl FnMut(&mut StdRng) -> F,
) {
    let mut r = StdRng::seed_from_u64(seed);
    for log_k in [0u32, 1, 2, 5, 8] {
        for m in log_k.max(1)..=log_k + 4 {
            let n = 1usize << m;
            let k = 1usize << log_k;

            let fft = AdditiveFft::<F>::new(m).unwrap();
            let basis = CantorBasis::<F>::new(m as usize + 1).unwrap();

            let coeffs: Vec<Flat<F>> = (0..k).map(|_| mk(&mut r).to_hardware()).collect();

            let mut scratch = vec![Flat::from_raw(F::ZERO); k - 1];
            let mut picks: Vec<usize> = (0..17).map(|_| r.random_range(0..n)).collect();

            picks.push(picks[0]);
            picks.sort_unstable();

            let sets = [vec![], vec![0], vec![n - 1], picks, (0..n).collect()];

            let shifts = [
                Flat::from_raw(F::ZERO),
                mk(&mut r).to_hardware(),
                basis.betas()[m as usize],
            ];

            for shift in shifts {
                let mut full = vec![Flat::from_raw(F::ZERO); n];
                full[..k].copy_from_slice(&coeffs);

                fft.forward_coset_scalar(&mut full, shift).unwrap();

                for indices in &sets {
                    let mut out = vec![Flat::from_raw(F::ZERO); indices.len()];

                    basis
                        .evaluate_at(&coeffs, shift, indices, &mut scratch, &mut out)
                        .unwrap();

                    for (&j, v) in indices.iter().zip(&out) {
                        assert_eq!(*v, full[j], "{}-bit log_k={log_k} m={m} j={j}", F::BITS);
                    }
                }
            }
        }
    }
}

fn evaluate_at_eq_horner<F: BinaryFieldExtras + HardwareField>(
    seed: u64,
    log_k: u32,
    clusters: usize,
    mut mk: impl FnMut(&mut StdRng) -> F,
) {
    let mut r = StdRng::seed_from_u64(seed);

    let dim = F::BITS.min(usize::BITS as usize);
    let top = usize::MAX >> (usize::BITS as usize - dim);
    let k = 1usize << log_k;

    let basis = CantorBasis::<F>::new(dim).unwrap();
    let coeffs: Vec<F> = (0..k).map(|_| mk(&mut r)).collect();
    let flat: Vec<Flat<F>> = coeffs.iter().map(|c| c.to_hardware()).collect();

    let mut indices = vec![0, top];
    for _ in 0..clusters {
        let base = r.random_range(0..=top) & !(k - 1);
        indices.extend([base, base + r.random_range(0..k), base + (k - 1)]);
    }

    indices.sort_unstable();

    let shift = mk(&mut r);

    let mut scratch = vec![Flat::from_raw(F::ZERO); k - 1];
    let mut out = vec![Flat::from_raw(F::ZERO); indices.len()];

    basis
        .evaluate_at(&flat, shift.to_hardware(), &indices, &mut scratch, &mut out)
        .unwrap();

    for (&j, v) in indices.iter().zip(&out) {
        assert_eq!(
            v.to_tower(),
            horner_eval(&coeffs, shift + eval_point(j), log_k),
            "{}-bit log_k={log_k} j={j:#x}",
            F::BITS
        );
    }
}

#[test]
fn cantor_basis_pinned() {
    cantor_pinned::<Block16>();
    cantor_pinned::<Block32>();
    cantor_pinned::<Block64>();
    cantor_pinned::<Block128>();
    cantor_pinned::<Block256>();
}

#[test]
fn cantor_basis_chain_laws() {
    cantor_chain_laws::<Block16>();
    cantor_chain_laws::<Block32>();
    cantor_chain_laws::<Block64>();
    cantor_chain_laws::<Block128>();
    cantor_chain_laws::<Block256>();
}

#[test]
fn cantor_basis_rejects_bad_dim() {
    assert_eq!(
        CantorBasis::<Block16>::new(0).err(),
        Some(CantorError::BadDim { dim: 0, max: 16 })
    );
    assert_eq!(
        CantorBasis::<Block16>::new(17).err(),
        Some(CantorError::BadDim { dim: 17, max: 16 })
    );
    assert_eq!(
        CantorBasis::<Block128>::new(65).err(),
        Some(CantorError::BadDim { dim: 65, max: 64 })
    );
}

#[test]
fn cantor_point_is_forward_of_x_all_fields() {
    let mut r = StdRng::seed_from_u64(0x5eed_ca07_0001);
    for log_n in [1u32, 10] {
        cantor_point_is_forward_of_x::<Block16>(log_n, Flat::from_raw(Block16::ZERO));
        cantor_point_is_forward_of_x::<Block16>(log_n, Block16(r.random()).to_hardware());

        cantor_point_is_forward_of_x::<Block32>(log_n, Flat::from_raw(Block32::ZERO));
        cantor_point_is_forward_of_x::<Block32>(log_n, Block32(r.random()).to_hardware());

        cantor_point_is_forward_of_x::<Block64>(log_n, Flat::from_raw(Block64::ZERO));
        cantor_point_is_forward_of_x::<Block64>(log_n, Block64(r.random()).to_hardware());

        cantor_point_is_forward_of_x::<Block128>(log_n, Flat::from_raw(Block128::ZERO));
        cantor_point_is_forward_of_x::<Block128>(log_n, Block128(r.random()).to_hardware());

        cantor_point_is_forward_of_x::<Block256>(log_n, Flat::from_raw(Block256::ZERO));
        cantor_point_is_forward_of_x::<Block256>(
            log_n,
            Block256([r.random(), r.random()]).to_hardware(),
        );
    }
}

#[test]
fn cantor_point_rejects_out_of_range() {
    let basis = CantorBasis::<Block16>::new(4).unwrap();

    assert!(basis.point(15).is_ok());
    assert_eq!(
        basis.point(16).err(),
        Some(CantorError::IndexOutOfRange { index: 16, dim: 4 })
    );

    let wide = CantorBasis::<Block128>::new(64).unwrap();
    assert!(wide.point(usize::MAX).is_ok());
}

#[test]
fn evaluate_at_eq_forward_all_fields() {
    evaluate_at_eq_forward::<Block16>(0x5eed_ca07_0016, |r| Block16(r.random()));
    evaluate_at_eq_forward::<Block32>(0x5eed_ca07_0032, |r| Block32(r.random()));
    evaluate_at_eq_forward::<Block64>(0x5eed_ca07_0064, |r| Block64(r.random()));
    evaluate_at_eq_forward::<Block128>(0x5eed_ca07_0128, |r| Block128(r.random()));
    evaluate_at_eq_forward::<Block256>(0x5eed_ca07_0256, |r| Block256([r.random(), r.random()]));
}

#[test]
fn evaluate_at_eq_horner_all_fields() {
    for log_k in [0u32, 1, 4, 8] {
        let s = u64::from(log_k);

        evaluate_at_eq_horner::<Block16>(0x5eed_ca07_e016 + s, log_k, 16, |r| Block16(r.random()));
        evaluate_at_eq_horner::<Block32>(0x5eed_ca07_e032 + s, log_k, 16, |r| Block32(r.random()));
        evaluate_at_eq_horner::<Block64>(0x5eed_ca07_e064 + s, log_k, 16, |r| Block64(r.random()));
        evaluate_at_eq_horner::<Block128>(0x5eed_ca07_e128 + s, log_k, 16, |r| {
            Block128(r.random())
        });
        evaluate_at_eq_horner::<Block256>(0x5eed_ca07_e256 + s, log_k, 16, |r| {
            Block256([r.random(), r.random()])
        });
    }
}

#[test]
fn evaluate_at_outer_geometry_block128() {
    let mut r = StdRng::seed_from_u64(0x5eed_ca07_1216);

    let (log_k, log_n) = (12u32, 16u32);
    let (k, n) = (1usize << log_k, 1usize << log_n);

    let fft = AdditiveFft::<Block128>::new(log_n).unwrap();
    let basis = CantorBasis::<Block128>::new(log_n as usize + 1).unwrap();
    let shift = basis.betas()[log_n as usize];

    let coeffs: Vec<Flat<Block128>> = (0..k).map(|_| Block128(r.random()).to_hardware()).collect();

    let mut full = vec![Flat::from_raw(Block128::ZERO); n];
    full[..k].copy_from_slice(&coeffs);

    fft.forward_coset_scalar(&mut full, shift).unwrap();

    let mut indices: Vec<usize> = (0..121).map(|_| r.random_range(0..n)).collect();
    indices.sort_unstable();

    let mut scratch = vec![Flat::from_raw(Block128::ZERO); k - 1];
    let mut out = vec![Flat::from_raw(Block128::ZERO); indices.len()];

    basis
        .evaluate_at(&coeffs, shift, &indices, &mut scratch, &mut out)
        .unwrap();

    for (&j, v) in indices.iter().zip(&out) {
        assert_eq!(*v, full[j], "j={j}");
    }
}

#[test]
fn evaluate_at_rejects_bad_input() {
    let basis = CantorBasis::<Block16>::new(6).unwrap();
    let zero = Flat::from_raw(Block16::ZERO);
    let coeffs = [zero; 8];

    let mut scratch = [zero; 7];
    let mut out = [zero; 2];

    assert_eq!(
        basis.evaluate_at(&coeffs[..3], zero, &[0, 1], &mut scratch, &mut out),
        Err(CantorError::BadCoeffLength { got: 3 })
    );
    assert_eq!(
        basis.evaluate_at(&coeffs[..0], zero, &[0, 1], &mut scratch, &mut out),
        Err(CantorError::BadCoeffLength { got: 0 })
    );
    assert_eq!(
        basis.evaluate_at(&coeffs, zero, &[0], &mut scratch, &mut out),
        Err(CantorError::BadOutLength {
            expected: 1,
            got: 2,
        })
    );
    assert_eq!(
        basis.evaluate_at(&coeffs, zero, &[0, 1], &mut scratch[..6], &mut out),
        Err(CantorError::ShortScratch { need: 7, got: 6 })
    );
    assert_eq!(
        basis.evaluate_at(&coeffs, zero, &[5, 4], &mut scratch, &mut out),
        Err(CantorError::UnsortedIndices { at: 1 })
    );
    assert_eq!(
        basis.evaluate_at(&coeffs, zero, &[3, 64], &mut scratch, &mut out),
        Err(CantorError::IndexOutOfRange { index: 64, dim: 6 })
    );
}

#[test]
fn cantor_error_display_carries_values() {
    let cases: [(CantorError, &[&str]); 7] = [
        (CantorError::BadDim { dim: 65, max: 64 }, &["65", "64"]),
        (CantorError::ChainEnds { at: 17 }, &["17"]),
        (CantorError::BadCoeffLength { got: 3 }, &["3"]),
        (
            CantorError::IndexOutOfRange { index: 99, dim: 6 },
            &["99", "6"],
        ),
        (CantorError::UnsortedIndices { at: 5 }, &["5"]),
        (CantorError::ShortScratch { need: 7, got: 2 }, &["7", "2"]),
        (
            CantorError::BadOutLength {
                expected: 4,
                got: 9,
            },
            &["4", "9"],
        ),
    ];

    for (err, needles) in cases {
        let msg = format!("{err}");
        for needle in needles {
            assert!(msg.contains(needle), "uninformative: {msg}");
        }
    }
}

#[test]
#[ignore = "release-scale: 2^12 Block128 coefficients at 3074 points"]
fn evaluate_at_eq_horner_block128_volume() {
    evaluate_at_eq_horner::<Block128>(0x5eed_ca07_e1fe, 12, 1024, |r| Block128(r.random()));
}
