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

use hekate_math::matrix::ByteSparseMatrix;
use hekate_math::{Block128, HardwareField};
use rand::{RngExt, rng};
use std::time::Instant;

/// Benchmark for Sparse Matrix-Vector Multiplication (SpMV).
/// Simulates the encoding step in Brakedown.
#[ignore]
#[test]
fn bench_spmv_block128() {
    // Parameters similar to a real ZK proof
    let num_vars = 20;
    let size = 1 << num_vars; // 1M elements
    let degree = 16; // Standard expansion factor

    println!("=== SpMV Benchmark (ByteMatrix + Block128) ===");
    println!("Rows: {}, Cols: {}, Degree: {}", size, size, degree);

    // Generate Matrix
    let seed = [42u8; 32];

    println!("Generating matrix (Byte weights)...");

    let start_gen = Instant::now();

    // Note: No generic type parameter
    // <Block128> needed for generation
    let matrix = ByteSparseMatrix::generate_random(size, size, degree, seed);

    println!("Matrix gen time: {:.2?}", start_gen.elapsed());

    // Prepare Input Vector (Random data)
    println!("Generating input vector...");

    let mut rng = rng();
    let mut input = Vec::with_capacity(size);

    for _ in 0..size {
        // Input is still Block128
        let val = Block128::from(rng.random::<u8>()).to_hardware();
        input.push(val);
    }

    // Run Benchmark
    println!("Running SpMV (Single Thread)...");

    let start_spmv = Instant::now();

    // spmv is generic, it infers <Block128> from input vector type
    let output = matrix.spmv(input.as_slice());
    let duration = start_spmv.elapsed();

    assert_eq!(output.len(), size);

    // Report Results
    let seconds = duration.as_secs_f64();
    let ops = (size * degree) as f64; // Total multiplications
    let throughput_melem = (ops / seconds) / 1_000_000.0;

    // Data processed = Input Vec Size + Matrix Size (Weights + Indices)
    // Input: size * 16 bytes
    // Matrix: size * degree * (1 byte weight + 4 bytes index)
    let data_size_bytes = (size * 16) + (size * degree * 5);
    let throughput_mb = (data_size_bytes as f64 / seconds) / (1024.0 * 1024.0);

    println!("Time: {:.2?}", duration);
    println!(
        "Throughput: {:.2} MOps/s (Multiplications)",
        throughput_melem
    );
    println!(
        "Throughput: {:.2} MB/s (Effective Memory Bandwidth)",
        throughput_mb
    );
}
