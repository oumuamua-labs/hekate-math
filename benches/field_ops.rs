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

use core::hint::black_box;
use criterion::{
    BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main, measurement::WallTime,
};
use hekate_math::{Bit, Block8, Block16, Block32, Block64, Block128, Flat, HardwareField};
use rand::{RngExt, rng};

fn bench_mul_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("field_ops/mul_latency");

    run_mul_bench::<Bit>(&mut group, "Bit");
    run_mul_bench::<Block8>(&mut group, "Block8");
    run_mul_bench::<Block16>(&mut group, "Block16");
    run_mul_bench::<Block32>(&mut group, "Block32");
    run_mul_bench::<Block64>(&mut group, "Block64");
    run_mul_bench::<Block128>(&mut group, "Block128");

    group.finish();
}

fn run_mul_bench<F>(group: &mut BenchmarkGroup<WallTime>, name: &str)
where
    F: HardwareField,
{
    // Setup:
    // Generate random field elements
    let mut rng = rng();
    let a: F = rng.random::<u128>().into();
    let b: F = rng.random::<u128>().into();

    // 1. Baseline:
    // Tower Basis Multiplication (Recursive Karatsuba)
    group.bench_function(format!("{}/tower_basis", name), |bencher| {
        bencher.iter(|| black_box(a) * black_box(b))
    });

    // 2. Target:
    // Hardware Basis Multiplication (SIMD / PCMUL)
    // NOTE: Inputs must be converted to hardware basis first.
    let a_hw = a.to_hardware();
    let b_hw = b.to_hardware();

    // Using explicit hardware multiply function
    group.bench_function(format!("{}/hardware_basis", name), |bencher| {
        bencher.iter(|| a_hw * black_box(b_hw))
    });
}

fn bench_square_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("field_ops/square_latency");

    run_square_bench::<Bit>(&mut group, "Bit");
    run_square_bench::<Block8>(&mut group, "Block8");
    run_square_bench::<Block16>(&mut group, "Block16");
    run_square_bench::<Block32>(&mut group, "Block32");
    run_square_bench::<Block64>(&mut group, "Block64");
    run_square_bench::<Block128>(&mut group, "Block128");

    group.finish();
}

fn run_square_bench<F>(group: &mut BenchmarkGroup<WallTime>, name: &str)
where
    F: HardwareField,
{
    // Setup
    let mut rng = rng();
    let a: F = rng.random::<u128>().into();

    // 1. Tower Basis Squaring
    group.bench_function(format!("{}/tower_basis", name), |bencher| {
        bencher.iter(|| black_box(a) * black_box(a))
    });

    // 2. Hardware Basis Squaring
    let a_hw = a.to_hardware();
    group.bench_function(format!("{}/hardware_basis", name), |bencher| {
        bencher.iter(|| a_hw * black_box(a_hw))
    });
}

fn bench_inv_latency(c: &mut Criterion) {
    let mut group = c.benchmark_group("field_ops/inv_latency");

    run_inv_bench::<Bit>(&mut group, "Bit");
    run_inv_bench::<Block8>(&mut group, "Block8");
    run_inv_bench::<Block16>(&mut group, "Block16");
    run_inv_bench::<Block32>(&mut group, "Block32");
    run_inv_bench::<Block64>(&mut group, "Block64");
    run_inv_bench::<Block128>(&mut group, "Block128");

    group.finish();
}

fn run_inv_bench<F>(group: &mut BenchmarkGroup<WallTime>, name: &str)
where
    F: HardwareField,
{
    let batch_size = 1000;
    let mut rng = rng();

    let inputs: Vec<F> = (0..batch_size)
        .map(|_| {
            let mut x;
            loop {
                x = rng.random::<u128>().into();
                if x != F::ZERO {
                    break;
                }
            }

            x
        })
        .collect();

    // 1. Single Inversion (Baseline - Tower Basis)
    // Measures latency of one invert() call.
    group.bench_function(format!("{}/single", name), |bencher| {
        let mut iter = inputs.iter().cycle();
        bencher.iter(|| black_box(iter.next().unwrap()).invert())
    });

    // 2. Batch Inversion (Baseline - Tower Basis)
    // Measures amortized cost:
    // Total Time / Batch Size
    let inputs_hw: Vec<Flat<F>> = inputs.iter().map(|&x| x.to_hardware()).collect();

    let mut results = vec![F::ZERO.to_hardware(); batch_size];
    let mut scratch = vec![F::ZERO.to_hardware(); batch_size];

    group.throughput(Throughput::Elements(batch_size as u64));
    group.bench_function(format!("{}/batch", name), |bencher| {
        bencher.iter(|| {
            batch_invert_hardware(
                black_box(&inputs_hw),
                black_box(&mut results),
                black_box(&mut scratch),
            )
        })
    });
}

fn bench_add_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("field_ops/add_throughput");

    run_add_bench::<Bit>(&mut group, "Bit");
    run_add_bench::<Block8>(&mut group, "Block8");
    run_add_bench::<Block16>(&mut group, "Block16");
    run_add_bench::<Block32>(&mut group, "Block32");
    run_add_bench::<Block64>(&mut group, "Block64");
    run_add_bench::<Block128>(&mut group, "Block128");

    group.finish();
}

fn run_add_bench<F>(group: &mut BenchmarkGroup<WallTime>, name: &str)
where
    F: HardwareField,
{
    // Test with a reasonably large vector
    // to stress memory bandwidth (L3/RAM).
    let size = 100_000; // ~1.6 MB data
    group.throughput(Throughput::Elements(size as u64));

    let mut rng = rng();
    let a: Vec<F> = (0..size).map(|_| rng.random::<u128>().into()).collect();
    let b: Vec<F> = (0..size).map(|_| rng.random::<u128>().into()).collect();

    let mut out = vec![F::ZERO; size];

    // XOR is extremely fast;
    // this benchmark effectively measures
    // how fast we can stream data from memory.
    group.bench_function(format!("{}/vec_add_xor", name), |bencher| {
        bencher.iter(|| {
            for i in 0..size {
                out[i] = black_box(a[i]) + black_box(b[i]);
            }
        })
    });
}

fn batch_invert_hardware<F: HardwareField>(
    inputs: &[Flat<F>],
    results: &mut [Flat<F>],
    scratch_products: &mut [Flat<F>],
) {
    let n = inputs.len();
    let one_hw = F::ONE.to_hardware();

    let mut acc = one_hw;

    // 1. Prefix products
    for (p, &x) in scratch_products.iter_mut().zip(inputs) {
        *p = acc;
        acc *= x;
    }

    // 2. Global Inversion
    // Must convert to tower to invert, then back.
    let acc_tower = acc.to_tower();
    let inv_tower = acc_tower.invert();

    let mut acc_inv = inv_tower.to_hardware();

    // 3. Backtrack
    for i in (0..n).rev() {
        results[i] = acc_inv * scratch_products[i];
        acc_inv *= inputs[i];
    }
}

criterion_group!(
    benches,
    bench_mul_latency,
    bench_square_latency,
    bench_inv_latency,
    bench_add_throughput
);
criterion_main!(benches);
