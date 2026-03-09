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
use core::mem::size_of;
use criterion::{
    BenchmarkGroup, Criterion, Throughput, criterion_group, criterion_main, measurement::WallTime,
};
use hekate_math::{Block128, Flat, HardwareField, PackableField, PackedBlock128, PackedFlat};
use rand::{RngExt, rng};
use std::time::Duration;

fn bench_poly_arithmetic(c: &mut Criterion) {
    let mut group = c.benchmark_group("poly_arithmetic");
    group.measurement_time(Duration::from_secs(10));

    // 1. Poly Eval Dense (Horner) - Single Point Latency
    // Degree 2^20 (1M coefficients).
    let degree_dense = 1 << 20;
    bench_eval_dense::<Block128>(&mut group, "Block128", degree_dense);

    // 2. Poly Eval Batch (SIMD) - Throughput Focus
    // Points: 2^14 (16k).
    // Total ops per iter:
    // 256 * 16384 = ~4.1M ops.
    bench_eval_batch_block128(&mut group, 1 << 8, 1 << 14);

    // 3. FFT Additive (Mock/Butterfly)
    // Scenario A:
    // RAM Bound (Large size, large stride)
    // 1M elements, Stride 1024 (jumps around memory)
    bench_fft_additive::<Block128>(&mut group, "Block128/ram_bound", 1 << 20, 1024);

    // Scenario B:
    // L1 Bound (Small size, contiguous)
    // 256 elements, Stride 1 (packed).
    // Shows peak compute power.
    bench_fft_additive::<Block128>(&mut group, "Block128/l1_bound", 1 << 8, 1);

    // 4. Interpolate (Lagrange Subset)
    // MSM-like workload
    bench_interpolate::<Block128>(&mut group, "Block128", 1 << 16);

    // 5. Multilinear Eval (Binius-style)
    // 2^20 coefficients (1M size), 20 variables.
    bench_eval_multilinear::<Block128>(&mut group, "Block128", 20);

    group.finish();
}

// 1. Dense Horner Evaluation
fn bench_eval_dense<F>(group: &mut BenchmarkGroup<WallTime>, name: &str, degree: usize)
where
    F: HardwareField,
{
    let mut rng = rng();
    let z: F = F::from(rng.random::<u128>());
    let coeffs: Vec<F> = (0..degree).map(|_| F::from(rng.random::<u128>())).collect();

    // Input size in bytes
    group.throughput(Throughput::Bytes((degree * size_of::<F>()) as u64));

    // Baseline:
    // Tower Basis
    group.bench_function(format!("{}/eval_dense/tower_{}", name, degree), |bencher| {
        bencher.iter(|| {
            let mut acc = F::ZERO;
            for &c in coeffs.iter().rev() {
                acc = acc * z + c;
            }

            black_box(acc)
        })
    });

    // Target:
    // Hardware Basis
    let coeffs_hw: Vec<Flat<F>> = coeffs.iter().map(|x| x.to_hardware()).collect();
    let z_hw = z.to_hardware();

    group.bench_function(
        format!("{}/eval_dense/hardware_{}", name, degree),
        |bencher| {
            bencher.iter(|| {
                let mut acc = F::ZERO.to_hardware();
                for &c in coeffs_hw.iter().rev() {
                    acc = acc * z_hw + c;
                }

                black_box(acc)
            })
        },
    );
}

// 2. Batch Evaluation (SIMD Optimized)
// Optimized using "Strip Mining" to minimize broadcast overhead.
// Loop order: Coefficients (Outer) -> Points (Inner).
fn bench_eval_batch_block128(
    group: &mut BenchmarkGroup<WallTime>,
    degree: usize,
    num_points: usize,
) {
    let mut rng = rng();

    // Polynomial coefficients (Hardware Basis)
    let coeffs: Vec<Flat<Block128>> = (0..degree)
        .map(|_| Block128::from(rng.random::<u128>()).to_hardware())
        .collect();

    // Points to evaluate at (Hardware Basis), packed
    let packed_count = num_points / 4;
    let points: Vec<PackedFlat<Block128>> = (0..packed_count)
        .map(|_| {
            let chunk = [
                Block128::from(rng.random::<u128>()).to_hardware(),
                Block128::from(rng.random::<u128>()).to_hardware(),
                Block128::from(rng.random::<u128>()).to_hardware(),
                Block128::from(rng.random::<u128>()).to_hardware(),
            ];
            Flat::<Block128>::pack(&chunk)
        })
        .collect();

    // Accumulators for results.
    // Size:
    // 16k points * 16 bytes = 256 KB.
    // Fits in L2 Cache.
    let mut results = vec![PackedFlat::<Block128>::default(); packed_count];

    group.throughput(Throughput::Elements((degree * num_points) as u64));
    group.bench_function(
        format!("Block128/eval_batch/simd_{}x{}", degree, num_points),
        |bencher| {
            bencher.iter(|| {
                // Initialize accumulators to zero
                for acc in results.iter_mut() {
                    *acc = PackedFlat::from_raw(PackedBlock128::zero());
                }

                // Outer loop:
                // Coefficients
                for &c in coeffs.iter().rev() {
                    let c_vec = PackedFlat::from_raw(PackedBlock128::broadcast(c.into_raw()));

                    // Inner loop:
                    // Points (Stream through L1/L2)
                    for (acc, &z_vec) in results.iter_mut().zip(&points) {
                        // acc = acc * z + c
                        let prod = Block128::mul_hardware_packed(*acc, z_vec);
                        *acc = Block128::add_hardware_packed(prod, c_vec);
                    }
                }

                black_box(&results);
            })
        },
    );
}

// 3. Additive FFT (Mock Butterfly)
fn bench_fft_additive<F>(
    group: &mut BenchmarkGroup<WallTime>,
    name: &str,
    size: usize,
    stride: usize,
) where
    F: HardwareField,
{
    let mut rng = rng();
    let mut data: Vec<Flat<F>> = (0..size)
        .map(|_| F::from(rng.random::<u128>()).to_hardware())
        .collect();
    let twiddle = F::from(rng.random::<u128>()).to_hardware();

    group.throughput(Throughput::Elements(size as u64));
    group.bench_function(
        format!("{}/fft_layer_{}_stride_{}", name, size, stride),
        |bencher| {
            bencher.iter(|| {
                let mut i = 0;
                while i < size {
                    for j in 0..stride {
                        if i + j + stride >= size {
                            break;
                        }

                        // Unsafe get for max speed
                        let u = unsafe { *data.get_unchecked(i + j) };
                        let v = unsafe { *data.get_unchecked(i + j + stride) };

                        // Butterfly operations
                        let sum = u + v;
                        let twisted = u + v * twiddle;

                        unsafe {
                            *data.get_unchecked_mut(i + j) = sum;
                            *data.get_unchecked_mut(i + j + stride) = twisted;
                        }
                    }

                    i += 2 * stride;
                }

                black_box(&data[0]);
            })
        },
    );
}

// 4. Interpolate (Linear Combination subset)
fn bench_interpolate<F>(group: &mut BenchmarkGroup<WallTime>, name: &str, size: usize)
where
    F: HardwareField,
{
    let mut rng = rng();
    let coeffs: Vec<Flat<F>> = (0..size)
        .map(|_| F::from(rng.random::<u128>()).to_hardware())
        .collect();
    let y_vals: Vec<Flat<F>> = (0..size)
        .map(|_| F::from(rng.random::<u128>()).to_hardware())
        .collect();

    group.throughput(Throughput::Elements(size as u64));
    group.bench_function(format!("{}/interpolate_msm_{}", name, size), |bencher| {
        bencher.iter(|| {
            let mut acc = F::ZERO.to_hardware();
            for (c, y) in coeffs.iter().zip(y_vals.iter()) {
                acc += *c * *y;
            }

            black_box(acc)
        })
    });
}

// 5. Multilinear Evaluation (Folding).
// Simulates the core operation of Binius:
// folding a hypercube in all directions.
// Formula for binary fields:
// result = A + r * (A + B)
fn bench_eval_multilinear<F>(group: &mut BenchmarkGroup<WallTime>, name: &str, num_vars: usize)
where
    F: HardwareField,
{
    let size = 1 << num_vars;
    let mut rng = rng();

    // Random multilinear polynomial coefficients
    let mut data: Vec<Flat<F>> = (0..size)
        .map(|_| F::from(rng.random::<u128>()).to_hardware())
        .collect();

    // Evaluation point (r_0, ..., r_k-1)
    let point: Vec<Flat<F>> = (0..num_vars)
        .map(|_| F::from(rng.random::<u128>()).to_hardware())
        .collect();

    group.throughput(Throughput::Elements(size as u64));

    // Benchmark the full evaluation
    // (collapsing all variables).
    group.bench_function(format!("{}/eval_mle_{}_vars", name, num_vars), |bencher| {
        bencher.iter(|| {
            // Simulate in-place folding
            let mut current_size = size;

            // Iterate through each variable to fold the hypercube
            for &r in &point {
                let next_size = current_size / 2;

                // Process the current layer
                for i in 0..next_size {
                    unsafe {
                        // Access pairs:
                        // data[2*i] and data[2*i+1]
                        let u = *data.get_unchecked(2 * i);
                        let v = *data.get_unchecked(2 * i + 1);

                        // Fold logic:
                        // u' = u + r * (u + v)
                        let sum = u + v;
                        let folded = u + sum * r;

                        *data.get_unchecked_mut(i) = folded;
                    }
                }

                // Logically shrink the buffer for the next round
                current_size = next_size;
            }

            black_box(unsafe { *data.get_unchecked(0) });
        })
    });
}

criterion_group!(benches, bench_poly_arithmetic);
criterion_main!(benches);
