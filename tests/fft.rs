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

use hekate_math::fft::vanish_eval;
use hekate_math::{
    AdditiveFft, BinaryFieldExtras, Block16, Block32, Block64, Block128, CantorBasis, FftError,
    Flat, HardwareField, PackableField, PackedFlat, TowerField,
};
use rand::{RngExt, SeedableRng, rng, rngs::StdRng};

fn eval_point(j: usize) -> Block16 {
    let mut acc = Block16::ZERO;
    let mut bits = j;

    while bits != 0 {
        let i = bits.trailing_zeros() as usize;
        acc += CantorBasis::beta_tower(i);
        bits &= bits - 1;
    }

    acc
}

// Independent O(n^2) oracle:
// f(x) = Σ a_t X_t(x),
// X_t = ∏_{bit i of t} s_i,
// s_i the i-fold σ(t)=t^2+t.
fn horner_eval(coeffs: &[Block16], x: Block16, log_n: u32) -> Block16 {
    let mut s = [Block16::ZERO; 16];
    s[0] = x;

    for i in 1..log_n as usize {
        s[i] = s[i - 1].square() + s[i - 1];
    }

    let mut acc = Block16::ZERO;

    for (t, &a) in coeffs.iter().enumerate() {
        let mut xt = Block16::ONE;
        let mut bits = t;

        while bits != 0 {
            let i = bits.trailing_zeros() as usize;
            xt *= s[i];
            bits &= bits - 1;
        }

        acc += a * xt;
    }

    acc
}

fn lanewise_differential(
    seed: u64,
    packed_op: impl Fn(&AdditiveFft<Block16>, &mut [PackedFlat<Block16>]) -> Result<(), FftError>,
    scalar_op: impl Fn(&AdditiveFft<Block16>, &mut [Flat<Block16>]) -> Result<(), FftError>,
    label: &str,
) {
    const WIDTH: usize = 8;
    assert_eq!(<Flat<Block16> as PackableField>::WIDTH, WIDTH);

    // 16: packed crosses PARALLEL_THRESHOLD_BYTES, the rayon
    // schedule is differentially pinned to serial scalar.
    for log_n in [1u32, 3, 6, 10, 16] {
        let n = 1usize << log_n;
        let fft = AdditiveFft::<Block16>::new(log_n);

        let mut r = StdRng::seed_from_u64(seed ^ u64::from(log_n));

        let cols: Vec<Vec<Flat<Block16>>> = (0..WIDTH)
            .map(|_| {
                (0..n)
                    .map(|_| Flat::from_raw(Block16(r.random())))
                    .collect()
            })
            .collect();

        let mut packed: Vec<PackedFlat<Block16>> = (0..n)
            .map(|k| {
                let lanes: [Flat<Block16>; WIDTH] = core::array::from_fn(|l| cols[l][k]);
                <Flat<Block16> as PackableField>::pack(&lanes)
            })
            .collect();

        packed_op(&fft, &mut packed).unwrap();

        let mut cols_ref = cols;
        for col in cols_ref.iter_mut() {
            scalar_op(&fft, col).unwrap();
        }

        for (k, pk) in packed.iter().enumerate() {
            let mut out = [Flat::<Block16>::default(); WIDTH];
            <Flat<Block16> as PackableField>::unpack(*pk, &mut out);

            for (l, lane) in out.iter().enumerate() {
                assert_eq!(
                    *lane, cols_ref[l][k],
                    "{label}: packed != scalar at log_n={log_n}, k={k}, lane={l}"
                );
            }
        }
    }
}

fn roundtrip_scalar<F: BinaryFieldExtras + HardwareField>(log_n: u32, mut mk: impl FnMut() -> F) {
    let n = 1usize << log_n;
    let fft = AdditiveFft::<F>::new(log_n);

    let orig: Vec<Flat<F>> = (0..n).map(|_| mk().to_hardware()).collect();

    let mut data = orig.clone();
    fft.forward_scalar(&mut data).unwrap();
    fft.inverse_scalar(&mut data).unwrap();

    assert_eq!(data, orig, "inverse∘forward != id");

    let mut data2 = orig.clone();
    fft.inverse_scalar(&mut data2).unwrap();
    fft.forward_scalar(&mut data2).unwrap();

    assert_eq!(data2, orig, "forward∘inverse != id");
}

#[test]
fn cantor_self_check() {
    assert!(CantorBasis::self_check());
}

#[test]
fn vanish_eval_linearity_and_recurrence() {
    let mut r = rng();

    for i in 0..=16usize {
        for _ in 0..256 {
            let u = Block16(r.random());
            let v = Block16(r.random());

            assert_eq!(
                vanish_eval(i, u + v),
                vanish_eval(i, u) + vanish_eval(i, v),
                "vanish_eval not GF(2)-linear at i={i}"
            );

            if i >= 1 {
                let prev = vanish_eval(i - 1, u);
                assert_eq!(
                    vanish_eval(i, u),
                    prev.square() + prev,
                    "s_i recurrence at i={i}"
                );
            }
        }
    }
}

#[test]
fn additive_fft_eq_horner() {
    let log_n = 8u32;
    let n = 1usize << log_n;
    let fft = AdditiveFft::<Block16>::new(log_n);

    let mut r = rng();

    let coeffs: Vec<Block16> = (0..n).map(|_| Block16(r.random())).collect();

    let mut data: Vec<Flat<Block16>> = coeffs.iter().map(|c| c.to_hardware()).collect();
    fft.forward_scalar(&mut data).unwrap();

    for (j, slot) in data.iter().enumerate() {
        let expected = horner_eval(&coeffs, eval_point(j), log_n);
        assert_eq!(slot.to_tower(), expected, "FFT != Horner at j={j}");
    }
}

// Packed at the max Block16 size hits 2^16 · 16 B = 1 MiB
// = PARALLEL_THRESHOLD_BYTES, the rayon schedule runs;
#[test]
fn additive_fft_eq_horner_above_parallel_threshold() {
    const WIDTH: usize = 8;
    assert_eq!(<Flat<Block16> as PackableField>::WIDTH, WIDTH);

    let log_n = Block16::BITS as u32;
    let n = 1usize << log_n;

    let bytes = n * size_of::<PackedFlat<Block16>>();
    assert!(
        bytes >= 1 << 20,
        "packed buffer must reach the 1 MiB parallel threshold; got {bytes} B"
    );

    let fft = AdditiveFft::<Block16>::new(log_n);

    let mut r = StdRng::seed_from_u64(0x5eed_ff70_8000);

    let cols: Vec<Vec<Block16>> = (0..WIDTH)
        .map(|_| (0..n).map(|_| Block16(r.random())).collect())
        .collect();

    let mut packed: Vec<PackedFlat<Block16>> = (0..n)
        .map(|k| {
            let lanes: [Flat<Block16>; WIDTH] = core::array::from_fn(|l| cols[l][k].to_hardware());
            <Flat<Block16> as PackableField>::pack(&lanes)
        })
        .collect();

    fft.forward(&mut packed).unwrap();

    for _ in 0..8 {
        let j = r.random::<u32>() as usize % n;
        let x = eval_point(j);

        let mut out = [Flat::<Block16>::default(); WIDTH];
        <Flat<Block16> as PackableField>::unpack(packed[j], &mut out);

        for (l, lane) in out.iter().enumerate() {
            let expected = horner_eval(&cols[l], x, log_n);
            assert_eq!(
                lane.to_tower(),
                expected,
                "FFT != Horner at j={j}, lane={l}"
            );
        }
    }
}

#[test]
fn additive_fft_roundtrip_scalar() {
    let mut r = StdRng::seed_from_u64(0x5eed_ff70_0016);
    roundtrip_scalar(10, || Block16(r.random()));
}

#[test]
fn additive_fft_roundtrip_packed() {
    let log_n = 9u32;
    let n = 1usize << log_n;
    let fft = AdditiveFft::<Block16>::new(log_n);

    let mut r = rng();

    let orig: Vec<PackedFlat<Block16>> = (0..n)
        .map(|_| {
            let lanes: [Flat<Block16>; 8] =
                core::array::from_fn(|_| Flat::from_raw(Block16(r.random())));
            <Flat<Block16> as PackableField>::pack(&lanes)
        })
        .collect();

    let mut data = orig.clone();
    fft.forward(&mut data).unwrap();
    fft.inverse(&mut data).unwrap();

    assert_eq!(data, orig, "packed inverse∘forward != id");
}

#[test]
fn additive_fft_packed_eq_scalar() {
    let log_n = 6u32;
    let n = 1usize << log_n;
    let fft = AdditiveFft::<Block16>::new(log_n);

    let mut r = rng();

    let mut cols: Vec<Vec<Flat<Block16>>> = (0..8)
        .map(|_| {
            (0..n)
                .map(|_| Flat::from_raw(Block16(r.random())))
                .collect()
        })
        .collect();

    let mut packed: Vec<PackedFlat<Block16>> = (0..n)
        .map(|k| {
            let lanes: [Flat<Block16>; 8] = core::array::from_fn(|l| cols[l][k]);
            <Flat<Block16> as PackableField>::pack(&lanes)
        })
        .collect();

    fft.forward(&mut packed).unwrap();

    for col in cols.iter_mut() {
        fft.forward_scalar(col).unwrap();
    }

    for (k, pk) in packed.iter().enumerate() {
        let mut out = [Flat::<Block16>::default(); 8];
        <Flat<Block16> as PackableField>::unpack(*pk, &mut out);

        for (l, lane) in out.iter().enumerate() {
            assert_eq!(*lane, cols[l][k], "packed != scalar at k={k}, lane={l}");
        }
    }
}

#[test]
fn additive_fft_coset_eq_horner() {
    let log_n = 7u32;
    let n = 1usize << log_n;
    let fft = AdditiveFft::<Block16>::new(log_n);

    let mut r = rng();

    let offset = Block16(r.random());
    let coeffs: Vec<Block16> = (0..n).map(|_| Block16(r.random())).collect();

    let mut data: Vec<Flat<Block16>> = coeffs.iter().map(|c| c.to_hardware()).collect();
    fft.forward_coset_scalar(&mut data, offset.to_hardware())
        .unwrap();

    for (j, slot) in data.iter().enumerate() {
        let expected = horner_eval(&coeffs, offset + eval_point(j), log_n);
        assert_eq!(slot.to_tower(), expected, "coset FFT != Horner at j={j}");
    }
}

#[test]
fn additive_fft_deterministic() {
    let log_n = 9u32;
    let n = 1usize << log_n;

    let mut r = rng();

    let input: Vec<Flat<Block16>> = (0..n)
        .map(|_| Flat::from_raw(Block16(r.random())))
        .collect();

    let fft1 = AdditiveFft::<Block16>::new(log_n);
    let fft2 = AdditiveFft::<Block16>::new(log_n);

    let mut a = input.clone();
    let mut b = input.clone();

    fft1.forward_scalar(&mut a).unwrap();
    fft2.forward_scalar(&mut b).unwrap();

    assert_eq!(a, b, "forward not deterministic across instances");
}

#[test]
fn additive_fft_rejects_bad_length() {
    let fft = AdditiveFft::<Block16>::new(8);
    let mut data = vec![Flat::from_raw(Block16::ZERO); 100];

    assert!(matches!(
        fft.forward_scalar(&mut data),
        Err(FftError::BadLength { .. })
    ));
}

#[test]
fn additive_fft_coset_roundtrip_scalar() {
    let log_n = 8u32;
    let n = 1usize << log_n;
    let fft = AdditiveFft::<Block16>::new(log_n);

    let mut r = rng();

    let offset = Flat::from_raw(Block16(r.random()));
    let orig: Vec<Flat<Block16>> = (0..n)
        .map(|_| Flat::from_raw(Block16(r.random())))
        .collect();

    let mut data = orig.clone();
    fft.forward_coset_scalar(&mut data, offset).unwrap();
    fft.inverse_coset_scalar(&mut data, offset).unwrap();

    assert_eq!(data, orig, "coset inverse∘forward != id");

    let mut data2 = orig.clone();
    fft.inverse_coset_scalar(&mut data2, offset).unwrap();
    fft.forward_coset_scalar(&mut data2, offset).unwrap();

    assert_eq!(data2, orig, "coset forward∘inverse != id");
}

#[test]
fn additive_fft_coset_packed_eq_scalar() {
    let log_n = 6u32;
    let n = 1usize << log_n;
    let fft = AdditiveFft::<Block16>::new(log_n);

    let mut r = rng();

    let offset = Flat::from_raw(Block16(r.random()));

    let cols: Vec<Vec<Flat<Block16>>> = (0..8)
        .map(|_| {
            (0..n)
                .map(|_| Flat::from_raw(Block16(r.random())))
                .collect()
        })
        .collect();

    let mut packed: Vec<PackedFlat<Block16>> = (0..n)
        .map(|k| {
            let lanes: [Flat<Block16>; 8] = core::array::from_fn(|l| cols[l][k]);
            <Flat<Block16> as PackableField>::pack(&lanes)
        })
        .collect();

    let orig_packed = packed.clone();

    fft.forward_coset(&mut packed, offset).unwrap();

    let mut cols_fwd = cols.clone();
    for col in cols_fwd.iter_mut() {
        fft.forward_coset_scalar(col, offset).unwrap();
    }

    for (k, pk) in packed.iter().enumerate() {
        let mut out = [Flat::<Block16>::default(); 8];
        <Flat<Block16> as PackableField>::unpack(*pk, &mut out);

        for (l, lane) in out.iter().enumerate() {
            assert_eq!(
                *lane, cols_fwd[l][k],
                "packed coset != scalar coset at k={k}, lane={l}"
            );
        }
    }

    fft.inverse_coset(&mut packed, offset).unwrap();

    assert_eq!(packed, orig_packed, "packed coset inverse∘forward != id");
}

// log_n = 1:
// recursion base case and
// the empty-lift path in new().
#[test]
fn additive_fft_eq_horner_min() {
    let log_n = 1u32;
    let fft = AdditiveFft::<Block16>::new(log_n);

    let mut r = rng();

    let coeffs: Vec<Block16> = (0..2).map(|_| Block16(r.random())).collect();

    let mut data: Vec<Flat<Block16>> = coeffs.iter().map(|c| c.to_hardware()).collect();
    fft.forward_scalar(&mut data).unwrap();

    for (j, slot) in data.iter().enumerate() {
        let expected = horner_eval(&coeffs, eval_point(j), log_n);
        assert_eq!(slot.to_tower(), expected, "min FFT != Horner at j={j}");
    }
}

// log_n = F::BITS:
// full Cantor basis, deepest recursion,
// and the only size that derives β_15
// (the lone Tr = 1 element) in new().
#[test]
fn additive_fft_roundtrip_field_max() {
    let log_n = Block16::BITS as u32;
    let n = 1usize << log_n;
    let fft = AdditiveFft::<Block16>::new(log_n);

    let mut r = rng();

    let orig: Vec<Flat<Block16>> = (0..n)
        .map(|_| Flat::from_raw(Block16(r.random())))
        .collect();

    let mut data = orig.clone();
    fft.forward_scalar(&mut data).unwrap();
    fft.inverse_scalar(&mut data).unwrap();

    assert_eq!(data, orig, "field-max inverse∘forward != id");
}

#[test]
fn additive_fft_roundtrip_field_max_packed() {
    let log_n = Block16::BITS as u32;
    let n = 1usize << log_n;
    let fft = AdditiveFft::<Block16>::new(log_n);

    let mut r = rng();

    let orig: Vec<PackedFlat<Block16>> = (0..n)
        .map(|_| {
            let lanes: [Flat<Block16>; 8] =
                core::array::from_fn(|_| Flat::from_raw(Block16(r.random())));
            <Flat<Block16> as PackableField>::pack(&lanes)
        })
        .collect();

    let mut data = orig.clone();
    fft.forward(&mut data).unwrap();
    fft.inverse(&mut data).unwrap();

    assert_eq!(data, orig, "field-max packed inverse∘forward != id");
}

#[test]
#[should_panic(expected = "log_n must be in")]
fn additive_fft_new_rejects_zero() {
    let _ = AdditiveFft::<Block16>::new(0);
}

#[test]
#[should_panic(expected = "log_n must be in")]
fn additive_fft_new_rejects_above_field_bits() {
    let _ = AdditiveFft::<Block16>::new(Block16::BITS as u32 + 1);
}

#[test]
#[should_panic]
fn cantor_beta_tower_out_of_range_panics() {
    let _ = CantorBasis::beta_tower(CantorBasis::DIM);
}

#[test]
fn additive_fft_lanewise_forward() {
    lanewise_differential(
        0x5eed_f0f0_0001,
        |fft, data| fft.forward(data),
        |fft, col| fft.forward_scalar(col),
        "forward",
    );
}

#[test]
fn additive_fft_lanewise_inverse() {
    lanewise_differential(
        0x5eed_f0f0_0002,
        |fft, data| fft.inverse(data),
        |fft, col| fft.inverse_scalar(col),
        "inverse",
    );
}

#[test]
fn additive_fft_lanewise_forward_coset() {
    let offset = Flat::from_raw(Block16(0xB2C7));

    lanewise_differential(
        0x5eed_f0f0_0003,
        move |fft, data| fft.forward_coset(data, offset),
        move |fft, col| fft.forward_coset_scalar(col, offset),
        "forward_coset",
    );
}

#[test]
fn additive_fft_lanewise_inverse_coset() {
    let offset = Flat::from_raw(Block16(0x39D4));

    lanewise_differential(
        0x5eed_f0f0_0004,
        move |fft, data| fft.inverse_coset(data, offset),
        move |fft, col| fft.inverse_coset_scalar(col, offset),
        "inverse_coset",
    );
}

#[test]
fn fft_error_display_carries_lengths() {
    let fft = AdditiveFft::<Block16>::new(8);
    let mut data = vec![Flat::from_raw(Block16::ZERO); 7];

    let err = fft.forward_scalar(&mut data).unwrap_err();
    assert_eq!(
        err,
        FftError::BadLength {
            expected: 256,
            got: 7,
        }
    );

    let msg = format!("{err}");
    assert!(
        msg.contains("256") && msg.contains('7'),
        "uninformative: {msg}"
    );
}

#[test]
fn additive_fft_roundtrip_block32() {
    let mut r = StdRng::seed_from_u64(0x5eed_ff70_0032);
    roundtrip_scalar(8, || Block32(r.random()));
}

#[test]
fn additive_fft_roundtrip_block64() {
    let mut r = StdRng::seed_from_u64(0x5eed_ff70_0064);
    roundtrip_scalar(8, || Block64(r.random()));
}

#[test]
fn additive_fft_roundtrip_block128() {
    let mut r = StdRng::seed_from_u64(0x5eed_ff70_0128);
    roundtrip_scalar(10, || Block128(r.random()));
}

#[test]
fn additive_fft_coset_roundtrip_block128() {
    let log_n = 8u32;
    let n = 1usize << log_n;
    let fft = AdditiveFft::<Block128>::new(log_n);

    let mut r = StdRng::seed_from_u64(0x5eed_ff70_c128);

    let offset = Flat::from_raw(Block128(r.random()));
    let orig: Vec<Flat<Block128>> = (0..n)
        .map(|_| Flat::from_raw(Block128(r.random())))
        .collect();

    let mut data = orig.clone();
    fft.forward_coset_scalar(&mut data, offset).unwrap();
    fft.inverse_coset_scalar(&mut data, offset).unwrap();

    assert_eq!(data, orig, "coset inverse∘forward != id");
}

#[test]
fn additive_fft_roundtrip_block128_packed() {
    const WIDTH: usize = 4;
    assert_eq!(<Flat<Block128> as PackableField>::WIDTH, WIDTH);

    let log_n = 8u32;
    let n = 1usize << log_n;
    let fft = AdditiveFft::<Block128>::new(log_n);

    let mut r = StdRng::seed_from_u64(0x5eed_ff70_a128);

    let orig: Vec<PackedFlat<Block128>> = (0..n)
        .map(|_| {
            let lanes: [Flat<Block128>; WIDTH] =
                core::array::from_fn(|_| Flat::from_raw(Block128(r.random())));
            <Flat<Block128> as PackableField>::pack(&lanes)
        })
        .collect();

    let mut data = orig.clone();
    fft.forward(&mut data).unwrap();
    fft.inverse(&mut data).unwrap();

    assert_eq!(data, orig, "packed inverse∘forward != id");
}

#[test]
#[ignore = "release-scale: 2^20 Block128 elements"]
fn additive_fft_roundtrip_block128_2p20() {
    let mut r = StdRng::seed_from_u64(0x5eed_ff70_2020);
    roundtrip_scalar(20, || Block128(r.random()));
}
