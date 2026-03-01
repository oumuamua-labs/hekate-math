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
use criterion::{BenchmarkId, Criterion, Throughput, criterion_group, criterion_main};
use hekate_math::matrix::ByteSparseMatrix;
use hekate_math::{Block128, HardwareField};
use rand::{RngExt, SeedableRng, rngs::StdRng};

/// Benchmark for Sparse Matrix-Vector Multiplication (SpMV).
fn bench_spmv_block128(c: &mut Criterion) {
    let mut group = c.benchmark_group("spmv/block128");

    let sizes = vec![
        (16, "64K"),  // L3 cache fit
        (18, "256K"), // L3/RAM boundary
        (20, "1M"),   // RAM bound
    ];

    let degree = 16;
    let seed = [42u8; 32];

    for (num_vars, label) in sizes {
        let size = 1 << num_vars;
        let ops = (size * degree) as u64;
        let data_size_bytes = (size * 16) + (size * degree * 5);

        group.throughput(Throughput::Elements(ops));

        // Pre-generate matrix outside the benchmark loop
        let matrix = ByteSparseMatrix::generate_random(size, size, degree, seed);

        // Pre-generate input vector
        let mut rng = StdRng::seed_from_u64(42);
        let input: Vec<Block128> = (0..size)
            .map(|_| {
                let val = Block128::from(rng.random::<u8>());
                val.to_hardware()
            })
            .collect();

        group.bench_with_input(
            BenchmarkId::new("hardware_basis", label),
            &num_vars,
            |b, &_| {
                b.iter(|| {
                    // Measure pure SpMV performance
                    let output = matrix.spmv(black_box(input.as_slice()));
                    black_box(output)
                })
            },
        );

        println!(
            "SpMV {}: {} rows, {} ops, {:.2} MB data",
            label,
            size,
            ops,
            data_size_bytes as f64 / (1024.0 * 1024.0)
        );
    }

    group.finish();
}

/// Benchmark SpMV with different sparsity
/// patterns. Tests cache sensitivity based
/// on degree (non-zeros per row).
fn bench_spmv_sparsity(c: &mut Criterion) {
    let mut group = c.benchmark_group("spmv/sparsity");

    let num_vars = 18;
    let size = 1 << num_vars;
    let seed = [42u8; 32];

    // degree=4:  Very sparse (cache-friendly, less work)
    // degree=16: Standard Brakedown (balanced)
    // degree=64: Dense (more work, worse cache behavior)
    let degrees = vec![4, 16, 64];

    for degree in degrees {
        let ops = (size * degree) as u64;
        group.throughput(Throughput::Elements(ops));

        let matrix = ByteSparseMatrix::generate_random(size, size, degree, seed);

        let mut rng = StdRng::seed_from_u64(42);
        let input: Vec<Block128> = (0..size)
            .map(|_| Block128::from(rng.random::<u8>()).to_hardware())
            .collect();

        group.bench_with_input(BenchmarkId::from_parameter(degree), &degree, |b, &_| {
            b.iter(|| {
                let output = matrix.spmv(black_box(input.as_slice()));
                black_box(output)
            })
        });
    }

    group.finish();
}

/// Benchmark to measure conversion
/// overhead vs pure hardware ops.
fn bench_spmv_conversion_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("spmv/conversion_overhead");

    let num_vars = 16;
    let size = 1 << num_vars;
    let degree = 16;
    let seed = [42u8; 32];

    let matrix = ByteSparseMatrix::generate_random(size, size, degree, seed);
    let ops = (size * degree) as u64;
    group.throughput(Throughput::Elements(ops));

    // Scenario A:
    // Input in Tower basis (requires conversion)
    let mut rng = StdRng::seed_from_u64(42);
    let input_tower: Vec<Block128> = (0..size)
        .map(|_| Block128::from(rng.random::<u8>()))
        .collect();

    group.bench_function("tower_to_hardware_inline", |b| {
        b.iter(|| {
            let input_hw: Vec<Block128> = input_tower.iter().map(|x| x.to_hardware()).collect();
            let output = matrix.spmv(black_box(input_hw.as_slice()));

            black_box(output)
        })
    });

    // Scenario B:
    // Input already in Hardware basis (target)
    let input_hardware: Vec<Block128> = input_tower.iter().map(|x| x.to_hardware()).collect();

    group.bench_function("hardware_direct", |b| {
        b.iter(|| {
            let output = matrix.spmv(black_box(input_hardware.as_slice()));
            black_box(output)
        })
    });

    group.finish();
}

/// Parallel vs Sequential SpMV comparison.
/// Validates Rayon scaling on large matrices.
#[cfg(feature = "parallel")]
fn bench_spmv_parallel(c: &mut Criterion) {
    let mut group = c.benchmark_group("spmv/parallel");

    let num_vars = 20;
    let size = 1 << num_vars;
    let degree = 16;
    let seed = [42u8; 32];

    let matrix = ByteSparseMatrix::generate_random(size, size, degree, seed);
    let ops = (size * degree) as u64;
    group.throughput(Throughput::Elements(ops));

    let mut rng = StdRng::seed_from_u64(42);
    let input: Vec<Block128> = (0..size)
        .map(|_| Block128::from(rng.random::<u8>()).to_hardware())
        .collect();

    group.bench_function("rayon_enabled", |b| {
        b.iter(|| {
            let output = matrix.spmv(black_box(input.as_slice()));
            black_box(output)
        })
    });

    group.finish();

    println!("Rayon threads: {}", rayon::current_num_threads());
}

#[cfg(feature = "parallel")]
criterion_group!(
    benches,
    bench_spmv_block128,
    bench_spmv_sparsity,
    bench_spmv_conversion_overhead,
    bench_spmv_parallel
);

#[cfg(not(feature = "parallel"))]
criterion_group!(
    benches,
    bench_spmv_block128,
    bench_spmv_sparsity,
    bench_spmv_conversion_overhead
);

criterion_main!(benches);
