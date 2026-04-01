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
use criterion::{Criterion, Throughput, criterion_group, criterion_main};
use hekate_math::{
    Block8, Block16, Block32, Block64, Block128, Flat, FlatPromote, HardwareField, TowerField,
};
use rand::{RngExt, rng};

// ==========================================
// SCALAR PROMOTE (single element)
// ==========================================

fn bench_promote_scalar(c: &mut Criterion) {
    let mut group = c.benchmark_group("promote_scalar");
    group.throughput(Throughput::Elements(1));

    let mut rng = rng();

    let val8 = Block8(rng.random::<u8>()).to_hardware();
    let val16 = Block16(rng.random::<u16>()).to_hardware();
    let val32 = Block32(rng.random::<u32>()).to_hardware();
    let val64 = Block64(rng.random::<u64>()).to_hardware();

    group.bench_function("Block8_to_Block128", |b| {
        b.iter(|| Block128::promote_flat(black_box(val8)))
    });

    group.bench_function("Block16_to_Block128", |b| {
        b.iter(|| Block128::promote_flat(black_box(val16)))
    });

    group.bench_function("Block32_to_Block128", |b| {
        b.iter(|| Block128::promote_flat(black_box(val32)))
    });

    group.bench_function("Block64_to_Block128", |b| {
        b.iter(|| Block128::promote_flat(black_box(val64)))
    });

    group.finish();
}

// ==========================================
// BATCH PROMOTE (promote_flat_batch)
// ==========================================

fn bench_promote_batch(c: &mut Criterion) {
    let mut group = c.benchmark_group("promote_batch");

    let mut rng = rng();

    // Block8 to Block128:
    // 16 elements
    let input_8: Vec<Flat<Block8>> = (0..16)
        .map(|_| Block8(rng.random::<u8>()).to_hardware())
        .collect();
    let mut output_128_from_8 = vec![Flat::from_raw(Block128::ZERO); 16];

    group.throughput(Throughput::Elements(16));
    group.bench_function("Block8_to_Block128_x16", |b| {
        b.iter(|| {
            Block128::promote_flat_batch(black_box(&input_8), &mut output_128_from_8);
        })
    });

    // Block16 to Block128:
    // 16 elements (fills NEON chunk)
    let input_16: Vec<Flat<Block16>> = (0..16)
        .map(|_| Block16(rng.random::<u16>()).to_hardware())
        .collect();
    let mut output_128_from_16 = vec![Flat::from_raw(Block128::ZERO); 16];

    group.throughput(Throughput::Elements(16));
    group.bench_function("Block16_to_Block128_x16", |b| {
        b.iter(|| {
            Block128::promote_flat_batch(black_box(&input_16), &mut output_128_from_16);
        })
    });

    // Block32 to Block128:
    // 16 elements (fills NEON chunk)
    let input_32: Vec<Flat<Block32>> = (0..16)
        .map(|_| Block32(rng.random::<u32>()).to_hardware())
        .collect();
    let mut output_128_from_32 = vec![Flat::from_raw(Block128::ZERO); 16];

    group.throughput(Throughput::Elements(16));
    group.bench_function("Block32_to_Block128_x16", |b| {
        b.iter(|| {
            Block128::promote_flat_batch(black_box(&input_32), &mut output_128_from_32);
        })
    });

    group.finish();
}

// ==========================================
// THROUGHPUT SCALING
// ==========================================

fn bench_promote_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("promote_throughput");

    let mut rng = rng();

    for &size in &[1024, 65536, 1_048_576] {
        let input: Vec<Flat<Block8>> = (0..size)
            .map(|_| Block8(rng.random::<u8>()).to_hardware())
            .collect();
        let mut output = vec![Flat::from_raw(Block128::ZERO); size];

        group.throughput(Throughput::Elements(size as u64));
        group.bench_function(format!("Block8_to_Block128_{}", size), |b| {
            b.iter(|| {
                Block128::promote_flat_batch(black_box(&input), &mut output);
            })
        });
    }

    group.finish();
}

criterion_group!(
    benches,
    bench_promote_scalar,
    bench_promote_batch,
    bench_promote_throughput
);
criterion_main!(benches);
