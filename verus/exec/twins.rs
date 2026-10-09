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

use super::block8::mul8;
use super::constants;
use super::convert::{
    lift_ct_16_twin, lift_ct_32_twin, lift_ct_64_twin, lift_ct_twin, map_ct_8_twin, map_ct_16_twin,
    map_ct_32_twin, map_ct_64_twin, map_ct_128_split_twin, tower_bit_8_twin, tower_bit_16_twin,
    tower_bit_32_twin, tower_bit_64_twin, tower_bit_128_twin,
};
use super::fft::{CantorTwin, FftTwin};
use hekate_math::{
    AdditiveFft, Block8, Block16, Block32, Block64, Block128, CantorBasis, Flat, FlatPromote,
    HardwareField,
};
use rand::{RngExt, SeedableRng, rngs::StdRng};

const RANDOM: usize = 4096;

const MAX_LOG_N: u32 = 10;

macro_rules! conversion_case {
    (
        $block:ident,
        $int:ty,
        $to:expr,
        $from:expr,
        $map:ident,
        $tower_bit:ident,
        $inputs:expr
    ) => {{
        let bits = <$int>::BITS as usize;

        let to: [$int; <$int>::BITS as usize] = $to;
        let from: [$int; <$int>::BITS as usize] = $from;

        let masks: Vec<$int> = (0..bits)
            .map(|k| (0..bits).fold(0, |m, j| m | (((from[j] >> k) & 1) << j)))
            .collect();

        for x in $inputs {
            let flat = Flat::from_raw($block(x));

            assert_eq!(
                $map(x, &to),
                $block(x).to_hardware().into_raw().0,
                "to_hardware {} {x:#x}",
                stringify!($block)
            );
            assert_eq!(
                $map(x, &from),
                $block::from_hardware(flat).0,
                "from_hardware {} {x:#x}",
                stringify!($block)
            );

            for (k, &mask) in masks.iter().enumerate() {
                assert_eq!(
                    $tower_bit(x, mask),
                    $block::tower_bit_from_hardware(flat, k),
                    "tower_bit_from_hardware {} {x:#x} bit {k}",
                    stringify!($block)
                );
            }
        }
    }};
}

macro_rules! promote_case {
    ($from:ident, $to:ident, $cols:expr, $lift:ident, $inputs:expr) => {{
        for x in $inputs {
            let want = <$to as FlatPromote<$from>>::promote_flat(Flat::from_raw($from(x)))
                .into_raw()
                .0;

            assert_eq!(
                $lift(x.into(), &$cols),
                want,
                "promote {} to {} {x:#x}",
                stringify!($from),
                stringify!($to)
            );
        }
    }};
}

fn flat128(x: u128) -> Flat<Block128> {
    Flat::from_raw(Block128(x))
}

fn raw128(xs: &[Flat<Block128>]) -> Vec<u128> {
    xs.iter().map(|x| x.into_raw().0).collect()
}

#[test]
fn mul8_twin_matches_block8_mul() {
    for a in 0..=u8::MAX {
        for b in 0..=u8::MAX {
            assert_eq!(mul8(a, b), (Block8(a) * Block8(b)).0, "{a:#x} * {b:#x}");
        }
    }
}

#[test]
fn conversion_twins_match_production() {
    let mut rng = StdRng::seed_from_u64(0x636f_6e76);

    conversion_case!(
        Block8,
        u8,
        constants::RAW_TOWER_TO_FLAT_8,
        constants::RAW_FLAT_TO_TOWER_8,
        map_ct_8_twin,
        tower_bit_8_twin,
        0..=u8::MAX
    );
    conversion_case!(
        Block16,
        u16,
        constants::RAW_TOWER_TO_FLAT_16,
        constants::RAW_FLAT_TO_TOWER_16,
        map_ct_16_twin,
        tower_bit_16_twin,
        0..=u16::MAX
    );
    conversion_case!(
        Block32,
        u32,
        constants::RAW_TOWER_TO_FLAT_32,
        constants::RAW_FLAT_TO_TOWER_32,
        map_ct_32_twin,
        tower_bit_32_twin,
        (0..RANDOM).map(|_| rng.random::<u32>())
    );
    conversion_case!(
        Block64,
        u64,
        constants::RAW_TOWER_TO_FLAT_64,
        constants::RAW_FLAT_TO_TOWER_64,
        map_ct_64_twin,
        tower_bit_64_twin,
        (0..RANDOM).map(|_| rng.random::<u64>())
    );
    conversion_case!(
        Block128,
        u128,
        constants::RAW_TOWER_TO_FLAT_128,
        constants::RAW_FLAT_TO_TOWER_128,
        map_ct_128_split_twin,
        tower_bit_128_twin,
        (0..RANDOM).map(|_| rng.random::<u128>())
    );
}

#[test]
fn lift_twins_match_promote_flat() {
    let mut rng = StdRng::seed_from_u64(0x6c69_6674);

    promote_case!(
        Block8,
        Block16,
        constants::LIFT_BASIS_8_TO_16,
        lift_ct_16_twin,
        0..=u8::MAX
    );
    promote_case!(
        Block8,
        Block32,
        constants::LIFT_BASIS_8_TO_32,
        lift_ct_32_twin,
        0..=u8::MAX
    );
    promote_case!(
        Block16,
        Block32,
        constants::LIFT_BASIS_16_TO_32,
        lift_ct_32_twin,
        0..=u16::MAX
    );
    promote_case!(
        Block8,
        Block64,
        constants::LIFT_BASIS_8_TO_64,
        lift_ct_64_twin,
        0..=u8::MAX
    );
    promote_case!(
        Block16,
        Block64,
        constants::LIFT_BASIS_16_TO_64,
        lift_ct_64_twin,
        0..=u16::MAX
    );
    promote_case!(
        Block32,
        Block64,
        constants::LIFT_BASIS_32_TO_64,
        lift_ct_64_twin,
        (0..RANDOM).map(|_| rng.random::<u32>())
    );
    promote_case!(
        Block8,
        Block128,
        constants::LIFT_BASIS_8_TO_128,
        lift_ct_twin,
        0..=u8::MAX
    );
    promote_case!(
        Block16,
        Block128,
        constants::LIFT_BASIS_16_TO_128,
        lift_ct_twin,
        0..=u16::MAX
    );
    promote_case!(
        Block32,
        Block128,
        constants::LIFT_BASIS_32_TO_128,
        lift_ct_twin,
        (0..RANDOM).map(|_| rng.random::<u32>())
    );
    promote_case!(
        Block64,
        Block128,
        constants::LIFT_BASIS_64_TO_128,
        lift_ct_twin,
        (0..RANDOM).map(|_| rng.random::<u64>())
    );
}

#[test]
fn fft_twin_matches_scalar_transforms() {
    let mut rng = StdRng::seed_from_u64(0x6666_7474);
    for log_n in 1..=MAX_LOG_N {
        let basis = CantorBasis::<Block128>::new(log_n as usize).expect("Cantor basis");
        let lift: Vec<u128> = basis.betas()[1..].iter().map(|b| b.into_raw().0).collect();
        let twin = FftTwin::new(log_n, lift);
        let fft = AdditiveFft::<Block128>::new(log_n).expect("transform plan");

        for offset in [0, rng.random::<u128>()] {
            let input: Vec<u128> = (0..1usize << log_n).map(|_| rng.random()).collect();
            let mut flat: Vec<Flat<Block128>> = input.iter().map(|&x| flat128(x)).collect();
            let mut mine = input.clone();

            match offset {
                0 => fft.forward_scalar(&mut flat).expect("forward"),
                _ => fft
                    .forward_coset_scalar(&mut flat, flat128(offset))
                    .expect("forward coset"),
            }

            twin.forward_coset(&mut mine, offset).expect("twin forward");

            assert_eq!(
                mine,
                raw128(&flat),
                "forward log_n {log_n} offset {offset:#x}"
            );

            match offset {
                0 => fft.inverse_scalar(&mut flat).expect("inverse"),
                _ => fft
                    .inverse_coset_scalar(&mut flat, flat128(offset))
                    .expect("inverse coset"),
            }

            twin.inverse_coset(&mut mine, offset).expect("twin inverse");

            assert_eq!(
                mine,
                raw128(&flat),
                "inverse log_n {log_n} offset {offset:#x}"
            );
            assert_eq!(mine, input, "round trip log_n {log_n} offset {offset:#x}");
        }
    }
}

#[test]
fn cantor_twin_matches_point_and_evaluate_at() {
    let mut rng = StdRng::seed_from_u64(0x6361_6e74);
    for dim in 1..=MAX_LOG_N as usize {
        let basis = CantorBasis::<Block128>::new(dim).expect("Cantor basis");
        let twin = CantorTwin {
            betas: basis.betas().iter().map(|b| b.into_raw().0).collect(),
        };

        for index in 0..(1usize << dim) + 2 {
            assert_eq!(
                twin.point(index as u64).ok(),
                basis.point(index).ok().map(|p| p.into_raw().0),
                "point dim {dim} index {index}"
            );
        }

        for k in (0..=dim).map(|log_k| 1usize << log_k).chain([3]) {
            let coeffs: Vec<u128> = (0..k).map(|_| rng.random()).collect();
            let shift = rng.random::<u128>();

            let mut indices: Vec<usize> = (0..16)
                .map(|_| rng.random_range(0..1usize << dim))
                .collect();

            indices.sort_unstable();

            let flat_coeffs: Vec<Flat<Block128>> = coeffs.iter().map(|&c| flat128(c)).collect();

            let mut scratch = vec![flat128(0); k.saturating_sub(1)];
            let mut out = vec![flat128(0); indices.len()];

            let want = basis
                .evaluate_at(
                    &flat_coeffs,
                    flat128(shift),
                    &indices,
                    &mut scratch,
                    &mut out,
                )
                .map(|()| raw128(&out));

            assert_eq!(
                want.is_ok(),
                k.is_power_of_two(),
                "evaluate_at dim {dim} k {k} acceptance"
            );

            let twin_indices: Vec<u64> = indices.iter().map(|&i| i as u64).collect();

            let mut twin_scratch = vec![0u128; k.saturating_sub(1)];
            let mut twin_out = vec![0u128; indices.len()];

            let got = twin
                .evaluate_at(
                    &coeffs,
                    shift,
                    &twin_indices,
                    &mut twin_scratch,
                    &mut twin_out,
                )
                .map(|()| twin_out);

            assert_eq!(got.ok(), want.ok(), "evaluate_at dim {dim} k {k}");
        }
    }
}
