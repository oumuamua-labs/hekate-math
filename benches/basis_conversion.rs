// SPDX-License-Identifier: Apache-2.0
// This file is part of the hekate-math project.
// Copyright (C) 2026 Andrei Kochergin <zeek@tuta.com>
// Copyright (C) 2026 Oumuamua Labs. All rights reserved.
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

use criterion::{
    BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main, measurement::WallTime,
};
use hekate_math::{
    Bit, Block8, Block16, Block32, Block64, Block128, CanonicalSerialize, Flat, HardwareField,
    PackableField, PackedFlat, TowerField,
};
use rand::{RngExt, rng};

fn bench_basis_conversion(c: &mut Criterion) {
    let mut group = c.benchmark_group("basis_conversion");

    // Configure for 1M elements
    // to stress memory bandwidth.
    let size = 1_000_000;

    run_conversion_bench::<Bit>(&mut group, "Bit", size);
    run_conversion_bench::<Block8>(&mut group, "Block8", size);
    run_conversion_bench::<Block16>(&mut group, "Block16", size);
    run_conversion_bench::<Block32>(&mut group, "Block32", size);
    run_conversion_bench::<Block64>(&mut group, "Block64", size);
    run_conversion_bench::<Block128>(&mut group, "Block128", size);

    group.finish();
}

fn run_conversion_bench<F>(group: &mut BenchmarkGroup<WallTime>, name: &str, size: usize)
where
    F: HardwareField + TowerField + CanonicalSerialize,
{
    let mut rng = rng();
    let input: Vec<F> = (0..size).map(|_| F::from(rng.random::<u128>())).collect();
    let bytes_per_elem = input[0].serialized_size() as u64;

    group.throughput(Throughput::Bytes(size as u64 * bytes_per_elem));

    // 1. Scalar:
    // Tower -> Flat
    // The baseline conversion cost per element.
    group.bench_function(format!("{}/scalar_pack", name), |bencher| {
        let mut output = vec![F::ZERO.to_hardware(); size];
        bencher.iter(|| {
            for (out, &val) in output.iter_mut().zip(input.iter()) {
                *out = val.to_hardware();
            }
        })
    });

    // 2. Scalar:
    // Flat -> Tower
    // Inverse operation.
    let input_flat: Vec<Flat<F>> = input.iter().map(|x| x.to_hardware()).collect();
    group.bench_function(format!("{}/scalar_unpack", name), |bencher| {
        let mut output = vec![F::ZERO; size];
        bencher.iter(|| {
            for (out, &val) in output.iter_mut().zip(input_flat.iter()) {
                *out = val.to_tower();
            }
        })
    });

    // 3. Packed:
    // Tower -> Packed<Flat> (Ingest)
    // Measures:
    // Convert scalar elements -> Write to scratch -> Pack -> Store SIMD
    group.bench_function(format!("{}/simd_ingest", name), |bencher| {
        let width = F::WIDTH;
        let chunks_count = input.len() / width;

        let mut output = vec![PackedFlat::<F>::default(); chunks_count];
        let mut scratch = vec![F::ZERO.to_hardware(); width];

        bencher.iter(|| {
            for (out_packed, chunk) in output.iter_mut().zip(input.chunks(width)) {
                // Convert to hardware basis into scratch buffer
                for (i, &val) in chunk.iter().enumerate() {
                    scratch[i] = val.to_hardware();
                }

                // Pack from scratch and write to output
                *out_packed = Flat::<F>::pack(&scratch);
            }
        })
    });

    // 4. Packed:
    // Packed<Flat> -> Tower (Egest)
    // Measures extracting results back to standard form.
    let packed_input: Vec<PackedFlat<F>> = input_flat
        .chunks(F::WIDTH)
        .map(|c| {
            let mut buf = vec![F::ZERO.to_hardware(); F::WIDTH];
            for (i, v) in c.iter().enumerate() {
                buf[i] = *v;
            }

            Flat::<F>::pack(&buf)
        })
        .collect();

    group.bench_function(format!("{}/simd_egest", name), |bencher| {
        let width = F::WIDTH;

        let mut output = vec![F::ZERO; size];
        let mut scratch = vec![F::ZERO.to_hardware(); width];

        bencher.iter(|| {
            for (packed_val, out_chunk) in packed_input.iter().zip(output.chunks_mut(width)) {
                // Unpack to scratch
                Flat::<F>::unpack(*packed_val, &mut scratch);

                // Convert back to tower and write to output
                for (out, &val_flat) in out_chunk.iter_mut().zip(scratch.iter()) {
                    *out = val_flat.to_tower();
                }
            }
        })
    });
}

criterion_group!(benches, bench_basis_conversion);
criterion_main!(benches);
