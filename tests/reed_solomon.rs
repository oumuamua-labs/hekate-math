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

use hekate_math::{
    BinaryFieldExtras, Block16, Block32, Block128, Flat, HardwareField, PackableField, PackedFlat,
    ReedSolomon, RsError, TowerField,
};
use rand::{RngExt, SeedableRng, rngs::StdRng};

fn weight<F: HardwareField>(cw: &[Flat<F>]) -> usize {
    cw.iter().filter(|&&s| s != Flat::from_raw(F::ZERO)).count()
}

fn systematic_and_mds<F: BinaryFieldExtras + HardwareField>(
    log_k: u32,
    log_n: u32,
    mut mk: impl FnMut() -> F,
) {
    let rs = ReedSolomon::<F>::new(log_k, log_n).unwrap();
    let (k, n) = (rs.message_len(), rs.codeword_len());

    let mut out = vec![Flat::from_raw(F::ZERO); n];

    for _ in 0..16 {
        let msg: Vec<Flat<F>> = (0..k).map(|_| mk().to_hardware()).collect();
        rs.encode_scalar(&msg, &mut out).unwrap();

        assert_eq!(&out[..k], &msg[..], "not systematic at k={k}, n={n}");
    }

    // Every nonzero codeword of an MDS [n, k] code
    // has weight >= n - k + 1; the old sparse row code
    // capped at the generator column weight (~16).
    let mut msg = vec![Flat::from_raw(F::ZERO); k];
    for i in 0..k {
        msg[i] = F::ONE.to_hardware();
        rs.encode_scalar(&msg, &mut out).unwrap();

        let w = weight(&out);
        assert!(
            w > n - k,
            "e_{i} encodes to weight {w} < {} at k={k}, n={n}",
            n - k + 1
        );

        msg[i] = Flat::from_raw(F::ZERO);
    }
}

#[test]
fn rs_block128_systematic_and_mds() {
    let mut r = StdRng::seed_from_u64(0x5eed_7273_0128);
    for (log_k, log_n) in [(1u32, 2u32), (3, 5), (6, 8), (7, 8)] {
        systematic_and_mds(log_k, log_n, || Block128(r.random()));
    }
}

#[test]
fn rs_block16_systematic_and_mds() {
    let mut r = StdRng::seed_from_u64(0x5eed_7273_0016);
    for (log_k, log_n) in [(3u32, 4u32), (4, 6)] {
        systematic_and_mds(log_k, log_n, || Block16(r.random()));
    }
}

#[test]
fn rs_block32_systematic_and_mds() {
    let mut r = StdRng::seed_from_u64(0x5eed_7273_0032);
    systematic_and_mds(3, 6, || Block32(r.random()));
}

#[test]
fn rs_linearity_block128() {
    let mut r = StdRng::seed_from_u64(0x5eed_7273_11ea);

    let rs = ReedSolomon::<Block128>::new(5, 7).unwrap();
    let (k, n) = (rs.message_len(), rs.codeword_len());

    let x: Vec<Flat<Block128>> = (0..k).map(|_| Block128(r.random()).to_hardware()).collect();
    let y: Vec<Flat<Block128>> = (0..k).map(|_| Block128(r.random()).to_hardware()).collect();
    let a = Block128(r.random()).to_hardware();

    let sum: Vec<Flat<Block128>> = x.iter().zip(y.iter()).map(|(&u, &v)| u + v).collect();
    let scaled: Vec<Flat<Block128>> = x.iter().map(|&u| u * a).collect();

    let mut cx = vec![Flat::from_raw(Block128::ZERO); n];
    let mut cy = cx.clone();
    let mut csum = cx.clone();
    let mut cscaled = cx.clone();

    rs.encode_scalar(&x, &mut cx).unwrap();
    rs.encode_scalar(&y, &mut cy).unwrap();
    rs.encode_scalar(&sum, &mut csum).unwrap();
    rs.encode_scalar(&scaled, &mut cscaled).unwrap();

    for j in 0..n {
        assert_eq!(csum[j], cx[j] + cy[j], "not additive at {j}");
        assert_eq!(cscaled[j], cx[j] * a, "not F-homogeneous at {j}");
    }
}

#[test]
fn rs_packed_eq_scalar_block128() {
    const WIDTH: usize = 4;
    assert_eq!(<Flat<Block128> as PackableField>::WIDTH, WIDTH);

    let mut r = StdRng::seed_from_u64(0x5eed_7273_ac4e);

    let rs = ReedSolomon::<Block128>::new(4, 6).unwrap();
    let (k, n) = (rs.message_len(), rs.codeword_len());

    let cols: Vec<Vec<Flat<Block128>>> = (0..WIDTH)
        .map(|_| (0..k).map(|_| Block128(r.random()).to_hardware()).collect())
        .collect();

    let msg: Vec<PackedFlat<Block128>> = (0..k)
        .map(|t| {
            let lanes: [Flat<Block128>; WIDTH] = core::array::from_fn(|l| cols[l][t]);
            <Flat<Block128> as PackableField>::pack(&lanes)
        })
        .collect();

    let mut packed_out = vec![PackedFlat::<Block128>::default(); n];
    rs.encode(&msg, &mut packed_out).unwrap();

    let mut scalar_out = vec![Flat::from_raw(Block128::ZERO); n];

    for (l, col) in cols.iter().enumerate() {
        rs.encode_scalar(col, &mut scalar_out).unwrap();

        for (t, pk) in packed_out.iter().enumerate() {
            let mut lanes = [Flat::<Block128>::default(); WIDTH];
            <Flat<Block128> as PackableField>::unpack(*pk, &mut lanes);

            assert_eq!(
                lanes[l], scalar_out[t],
                "packed != scalar at t={t}, lane={l}"
            );
        }
    }
}

#[test]
fn rs_rejects_bad_params() {
    assert!(matches!(
        ReedSolomon::<Block128>::new(0, 4),
        Err(RsError::BadRate { .. })
    ));
    assert!(matches!(
        ReedSolomon::<Block128>::new(4, 4),
        Err(RsError::BadRate { .. })
    ));
    assert!(matches!(
        ReedSolomon::<Block128>::new(5, 4),
        Err(RsError::BadRate { .. })
    ));
    assert!(matches!(
        ReedSolomon::<Block16>::new(4, 17),
        Err(RsError::FieldTooSmall { .. })
    ));

    // 64 <= F::BITS = 128;
    // rejected by the usize::BITS - 1 cap.
    assert!(matches!(
        ReedSolomon::<Block128>::new(10, 64),
        Err(RsError::FieldTooSmall { .. })
    ));
}

#[test]
fn rs_rejects_bad_lengths() {
    let rs = ReedSolomon::<Block128>::new(2, 3).unwrap();

    let msg = vec![Flat::from_raw(Block128::ZERO); 3];
    let mut out = vec![Flat::from_raw(Block128::ZERO); 8];

    assert_eq!(
        rs.encode_scalar(&msg, &mut out),
        Err(RsError::BadLength {
            expected: 4,
            got: 3,
        })
    );

    let msg = vec![Flat::from_raw(Block128::ZERO); 4];
    let mut short = vec![Flat::from_raw(Block128::ZERO); 7];

    assert_eq!(
        rs.encode_scalar(&msg, &mut short),
        Err(RsError::BadLength {
            expected: 8,
            got: 7,
        })
    );
}

#[test]
fn rs_error_display_carries_values() {
    let Err(err) = ReedSolomon::<Block128>::new(4, 4) else {
        panic!("rate 1 must be rejected");
    };
    let msg = format!("{err}");

    assert!(msg.contains('4'), "uninformative: {msg}");
}

#[test]
#[ignore = "release-scale: k=2^19, n=2^20 over Block128"]
fn rs_encode_block128_full_scale() {
    let mut r = StdRng::seed_from_u64(0x5eed_7273_2020);

    let rs = ReedSolomon::<Block128>::new(19, 20).unwrap();
    let (k, n) = (rs.message_len(), rs.codeword_len());

    let msg: Vec<Flat<Block128>> = (0..k).map(|_| Block128(r.random()).to_hardware()).collect();
    let mut out = vec![Flat::from_raw(Block128::ZERO); n];

    rs.encode_scalar(&msg, &mut out).unwrap();

    assert_eq!(&out[..k], &msg[..], "not systematic at full scale");
    assert!(weight(&out[k..]) > 0, "parity half is identically zero");
}
