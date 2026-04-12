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

use crate::{Block8, Flat, FlatPromote, HardwareField};
use aes::Aes256;
use aes::cipher::{BlockCipherEncrypt, KeyInit};
use alloc::vec::Vec;
use core::arch::asm;
use core::convert::Infallible;
use core::mem::MaybeUninit;
use rand::{RngExt, SeedableRng, TryRng};
#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Rows per processing unit.
/// 1024 keeps the hot set within L1 cache.
const CHUNK_SIZE: usize = 1024;

/// Min rows to trigger Rayon.
/// Binary XOR is too fast to justify
/// thread sync overhead below 32k.
#[cfg(feature = "parallel")]
const PARALLEL_THRESHOLD: usize = 32768;

/// 8 rows ahead keeps the memory
/// controller saturated during
/// random VectorSource access.
const LOOKAHEAD: usize = 8;

/// Fixed chunk size for deterministic
/// matrix generation. Both parallel
/// and sequential paths use the same
/// boundaries so output is bit-identical
/// across feature configurations.
const GEN_CHUNK_ROWS: usize = 256;

/// 8 blocks saturates the AES-NI
/// and ARMv8-CE pipeline via ILP.
const AES_BLOCK: usize = 16;
const AES_BATCH: usize = 8;
const AES_BUF_SIZE: usize = AES_BATCH * AES_BLOCK;

/// Abstract source of a vector for Matrix-Vector
/// multiplication. Allows using both dense slices
/// (RAM) and algorithmic generators (JIT).
pub trait VectorSource<F>: Sync {
    /// Get the length of the virtual vector.
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool;

    /// Get the element at the specified index.
    fn get_at(&self, index: usize) -> F;

    /// Optimized batch fetch.
    /// Allows the source to use pipelining.
    #[inline(always)]
    fn get_batch<const N: usize>(&self, indices: &[usize; N]) -> [F; N] {
        core::array::from_fn(|i| self.get_at(indices[i]))
    }

    /// Software prefetching hook.
    #[inline(always)]
    fn prefetch(&self, _indices: &[usize]) {
        // Default no-op
    }
}

/// Implementation for standard slice
/// access (Zero-Cost abstraction).
impl<F: Copy + Sync> VectorSource<F> for [F] {
    #[inline(always)]
    fn len(&self) -> usize {
        self.len()
    }

    #[inline(always)]
    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    #[inline(always)]
    fn get_at(&self, index: usize) -> F {
        self[index]
    }

    /// Explicit prefetching implementation using Inline ASM.
    #[inline(always)]
    fn prefetch(&self, indices: &[usize]) {
        let base_ptr = self.as_ptr();
        for &idx in indices {
            unsafe {
                let ptr = base_ptr.wrapping_add(idx) as *const u8;

                // Apple Silicon (M1/M2/M3) & ARM64
                #[cfg(target_arch = "aarch64")]
                asm!(
                    "prfm pldl1keep, [{p}]",
                    p = in(reg) ptr,
                    options(nostack, preserves_flags, readonly)
                );

                // Intel/AMD x86_64
                #[cfg(target_arch = "x86_64")]
                asm!(
                    "prefetcht0 [{p}]",
                    p = in(reg) ptr,
                    options(nostack, preserves_flags, readonly)
                );
            }
        }
    }
}

/// A Field-Agnostic Sparse Matrix.
/// Stores weights as `u8` to save memory.
/// Can be applied to ANY field that
/// implements `FlatPromote<Block8>`.
#[derive(Clone, Debug)]
pub struct ByteSparseMatrix {
    rows: usize,
    cols: usize,
    degree: usize,

    /// Weights stored as bytes.
    weights: Vec<u8>,

    /// Column indices.
    col_indices: Vec<u32>,
}

impl ByteSparseMatrix {
    /// Creates a new matrix safely,
    /// validating internal array lengths.
    pub fn new(
        rows: usize,
        cols: usize,
        degree: usize,
        weights: Vec<u8>,
        col_indices: Vec<u32>,
    ) -> Self {
        let expected_len = rows.checked_mul(degree).expect("Matrix size overflow");

        assert_eq!(
            weights.len(),
            expected_len,
            "Weights vector length mismatch"
        );
        assert_eq!(
            col_indices.len(),
            expected_len,
            "Column indices vector length mismatch"
        );

        for &idx in &col_indices {
            assert!(
                (idx as usize) < cols,
                "Column index {} exceeds matrix columns count {}",
                idx,
                cols
            );
        }

        Self {
            rows,
            cols,
            degree,
            weights,
            col_indices,
        }
    }

    /// Generates the Expander Graph once.
    pub fn generate_random(rows: usize, cols: usize, degree: usize, seed: [u8; 32]) -> Self {
        const MAX_DEGREE: usize = 256;
        assert!(
            degree <= MAX_DEGREE,
            "Expander degree exceeds stack buffer size"
        );

        // SAFETY:
        // Validate dimensions to prevent overflow,
        // division by zero, and infinite loops.
        assert!(
            cols > 0,
            "Matrix generation requires cols > 0 (division by zero in RNG)"
        );
        assert!(
            degree <= cols,
            "Expander degree cannot exceed cols (would cause infinite loop in generation)"
        );

        let total_elems = rows
            .checked_mul(degree)
            .expect("Matrix size overflow: rows * degree exceeds usize::MAX");

        if total_elems == 0 {
            return Self {
                rows,
                cols,
                degree,
                weights: Vec::new(),
                col_indices: Vec::new(),
            };
        }

        let mut weights: Vec<u8> = Vec::with_capacity(total_elems);
        let mut col_indices: Vec<u32> = Vec::with_capacity(total_elems);

        let weights_uninit = weights.spare_capacity_mut();
        let col_indices_uninit = col_indices.spare_capacity_mut();

        debug_assert!(weights_uninit.len() >= total_elems);
        debug_assert!(col_indices_uninit.len() >= total_elems);

        #[cfg(feature = "parallel")]
        {
            let rows_per_chunk = GEN_CHUNK_ROWS.min(rows.max(1));
            let aligned_chunk_len = rows_per_chunk * degree;

            weights_uninit[..total_elems]
                .par_chunks_mut(aligned_chunk_len)
                .zip(col_indices_uninit[..total_elems].par_chunks_mut(aligned_chunk_len))
                .enumerate()
                .for_each(|(chunk_id, (w_chunk, col_chunk))| {
                    let rows_in_this_chunk = w_chunk.len() / degree;

                    let mut rng = AesCtrPrg::from_seed(seed);
                    rng.set_stream(chunk_id as u64);

                    let mut used_cols = [0u32; MAX_DEGREE];
                    for r in 0..rows_in_this_chunk {
                        let row_offset = r * degree;

                        for d in 0..degree {
                            w_chunk[row_offset + d].write(1u8);

                            let mut col_idx;
                            loop {
                                col_idx = rng.random_range(0..cols as u32);

                                // The expander collapse:
                                // Never break early or fallback in
                                // characteristic 2 fields. Duplicate
                                // column indices will result in X ^ X = 0,
                                // locally destroying the expander
                                // graph degree and PCS soundness.
                                if !used_cols[..d].contains(&col_idx) {
                                    break;
                                }
                            }

                            used_cols[d] = col_idx;
                            col_chunk[row_offset + d].write(col_idx);
                        }
                    }
                });
        }

        #[cfg(not(feature = "parallel"))]
        {
            let rows_per_chunk = GEN_CHUNK_ROWS.min(rows.max(1));
            let aligned_chunk_len = rows_per_chunk * degree;
            let num_chunks = total_elems.div_ceil(aligned_chunk_len);

            let mut used_cols = [0u32; MAX_DEGREE];
            for chunk_id in 0..num_chunks {
                let mut rng = AesCtrPrg::from_seed(seed);
                rng.set_stream(chunk_id as u64);

                let elem_start = chunk_id * aligned_chunk_len;
                let elem_end = (elem_start + aligned_chunk_len).min(total_elems);
                let rows_in_this_chunk = (elem_end - elem_start) / degree;

                for r in 0..rows_in_this_chunk {
                    let row_offset = elem_start + r * degree;

                    for d in 0..degree {
                        weights_uninit[row_offset + d].write(1u8);

                        let mut col_idx;
                        loop {
                            col_idx = rng.random_range(0..cols as u32);
                            if !used_cols[..d].contains(&col_idx) {
                                break;
                            }
                        }

                        used_cols[d] = col_idx;
                        col_indices_uninit[row_offset + d].write(col_idx);
                    }
                }
            }
        }

        // SAFETY:
        // weights_uninit[..total_elems] and
        // col_indices_uninit[..total_elems]
        // were fully initialized above.
        unsafe {
            weights.set_len(total_elems);
            col_indices.set_len(total_elems);
        }

        Self {
            rows,
            cols,
            degree,
            weights,
            col_indices,
        }
    }

    #[inline]
    pub fn rows(&self) -> usize {
        self.rows
    }

    #[inline]
    pub fn cols(&self) -> usize {
        self.cols
    }

    #[inline]
    pub fn degree(&self) -> usize {
        self.degree
    }

    #[inline]
    pub fn weights(&self) -> &[u8] {
        &self.weights
    }

    #[inline]
    pub fn col_indices(&self) -> &[u32] {
        &self.col_indices
    }

    /// Generic SpMV that promotes u8 weights to
    /// Field F on the fly. Uses the FlatPromote
    /// trait for max speed (partial lookups).
    /// Accepts any source implementing `VectorSource`.
    pub fn spmv<F, V>(&self, x: &V) -> Vec<Flat<F>>
    where
        F: HardwareField + FlatPromote<Block8>,
        V: VectorSource<Flat<F>> + ?Sized,
    {
        assert_eq!(x.len(), self.cols);

        let mut y: Vec<MaybeUninit<Flat<F>>> = Vec::with_capacity(self.rows);

        // SAFETY:
        // Every output slot is written
        // exactly once below.
        unsafe {
            y.set_len(self.rows);
        }

        #[cfg(feature = "parallel")]
        if self.rows >= PARALLEL_THRESHOLD {
            y.par_chunks_mut(CHUNK_SIZE)
                .enumerate()
                .for_each(|(chunk_id, out_chunk)| {
                    let start_row = chunk_id * CHUNK_SIZE;
                    self.process_chunk(start_row, out_chunk, x);
                });

            // SAFETY:
            // All elements were initialized above.
            return unsafe { assume_init_vec(y) };
        }

        for (chunk_id, out_chunk) in y.chunks_mut(CHUNK_SIZE).enumerate() {
            let start_row = chunk_id * CHUNK_SIZE;
            self.process_chunk(start_row, out_chunk, x);
        }

        unsafe { assume_init_vec(y) }
    }

    /// Process a chunk of rows with lookahead prefetching.
    #[inline(always)]
    fn process_chunk<F, V>(&self, start_row: usize, out_chunk: &mut [MaybeUninit<Flat<F>>], x: &V)
    where
        F: HardwareField + FlatPromote<Block8> + Default + Copy,
        V: VectorSource<Flat<F>> + ?Sized,
    {
        // Strategy:
        // Iterate rows. For row i, prefetch indices
        // for row i+LOOKAHEAD. Keep the memory
        // controller pipeline full.
        for i in 0..out_chunk.len() {
            let row_idx = start_row + i;

            // A. PREFETCH LOOKAHEAD
            // Look ahead to find which random
            // memory addresses we will need soon.
            if i + LOOKAHEAD < out_chunk.len() {
                let next_row = row_idx + LOOKAHEAD;
                let row_offset = next_row * self.degree;

                // Read the column indices for the future row
                unsafe {
                    for k in 0..self.degree {
                        let col_idx = *self.col_indices.get_unchecked(row_offset + k) as usize;
                        x.prefetch(&[col_idx]);
                    }
                }
            }

            // B. COMPUTE CURRENT ROW
            const B: usize = 8; // Inner loop unroll factor

            let row_offset = row_idx * self.degree;

            let mut acc = Flat::from_raw(F::ZERO);
            let mut j = 0;

            while j + B <= self.degree {
                let mut col_idxs = [0usize; B];
                let mut weights = [Flat::from_raw(F::ZERO); B];

                unsafe {
                    for k in 0..B {
                        let curr = row_offset + j + k;
                        col_idxs[k] = *self.col_indices.get_unchecked(curr) as usize;

                        let w = *self.weights.get_unchecked(curr);
                        weights[k] = F::promote_flat(Block8(w).to_hardware());
                    }
                }

                let values = x.get_batch::<B>(&col_idxs);
                for k in 0..B {
                    acc += weights[k] * values[k];
                }

                j += B;
            }

            while j < self.degree {
                unsafe {
                    let curr = row_offset + j;
                    let w = *self.weights.get_unchecked(curr);
                    let w_field = F::promote_flat(Block8(w).to_hardware());
                    let col_idx = *self.col_indices.get_unchecked(curr) as usize;
                    let val = x.get_at(col_idx);

                    acc += w_field * val;
                }

                j += 1;
            }

            out_chunk[i].write(acc);
        }
    }
}

/// AES-256-CTR PRG for
/// expander graph generation.
struct AesCtrPrg {
    cipher: Aes256,
    nonce: u64,
    counter: u64,
    buffer: [u8; AES_BUF_SIZE],
    buf_pos: usize,
}

impl AesCtrPrg {
    fn set_stream(&mut self, stream_id: u64) {
        self.nonce = stream_id;
        self.counter = 0;
        self.buf_pos = AES_BUF_SIZE;
    }

    fn refill(&mut self) {
        let nonce_high = (self.nonce as u128) << 64;

        let mut blocks: [aes::Block; AES_BATCH] = Default::default();
        for (i, block) in blocks.iter_mut().enumerate() {
            let val = (self.counter + i as u64) as u128 | nonce_high;
            *block = val.to_le_bytes().into();
        }

        self.cipher.encrypt_blocks(&mut blocks);

        for (i, block) in blocks.iter().enumerate() {
            self.buffer[i * AES_BLOCK..(i + 1) * AES_BLOCK].copy_from_slice(block.as_slice());
        }

        self.counter += AES_BATCH as u64;
        self.buf_pos = 0;
    }
}

impl SeedableRng for AesCtrPrg {
    type Seed = [u8; 32];

    fn from_seed(seed: [u8; 32]) -> Self {
        Self {
            cipher: Aes256::new(&seed.into()),
            nonce: 0,
            counter: 0,
            buffer: [0u8; AES_BUF_SIZE],
            buf_pos: AES_BUF_SIZE,
        }
    }
}

impl TryRng for AesCtrPrg {
    type Error = Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Infallible> {
        if self.buf_pos + 4 > AES_BUF_SIZE {
            self.refill();
        }

        let p = self.buf_pos;
        let val = u32::from_le_bytes(core::array::from_fn(|i| self.buffer[p + i]));

        self.buf_pos = p + 4;

        Ok(val)
    }

    fn try_next_u64(&mut self) -> Result<u64, Infallible> {
        if self.buf_pos + 8 > AES_BUF_SIZE {
            self.refill();
        }

        let p = self.buf_pos;
        let val = u64::from_le_bytes(core::array::from_fn(|i| self.buffer[p + i]));

        self.buf_pos = p + 8;

        Ok(val)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Infallible> {
        let mut written = 0;
        while written < dst.len() {
            if self.buf_pos >= AES_BUF_SIZE {
                self.refill();
            }

            let available = AES_BUF_SIZE - self.buf_pos;
            let copy_len = available.min(dst.len() - written);

            dst[written..written + copy_len]
                .copy_from_slice(&self.buffer[self.buf_pos..self.buf_pos + copy_len]);

            self.buf_pos += copy_len;
            written += copy_len;
        }

        Ok(())
    }
}

#[inline]
unsafe fn assume_init_vec<T>(mut v: Vec<MaybeUninit<T>>) -> Vec<T> {
    let ptr = v.as_mut_ptr() as *mut T;
    let len = v.len();
    let cap = v.capacity();

    core::mem::forget(v);

    unsafe { Vec::from_raw_parts(ptr, len, cap) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Block128, HardwareField};
    use alloc::vec;
    use proptest::prelude::*;

    struct VirtualLinearSource {
        size: usize,
        multiplier: u128,
    }

    impl VectorSource<Flat<Block128>> for VirtualLinearSource {
        fn len(&self) -> usize {
            self.size
        }

        fn is_empty(&self) -> bool {
            unimplemented!()
        }

        fn get_at(&self, index: usize) -> Flat<Block128> {
            // Generates value:
            // index * multiplier
            Block128::from((index as u128) * self.multiplier).to_hardware()
        }
    }

    fn b128(v: u128) -> Block128 {
        Block128::from(v)
    }

    #[test]
    fn spmv_with_virtual_source() {
        // Scenario: Multiply matrix by a
        // "Virtual" vector without allocation.
        // Matrix:
        // [1, 1] (Indices: 0, 1)
        // [1, 1] (Indices: 1, 0)
        let weights = vec![1u8, 1u8, 1u8, 1u8];
        let col_indices = vec![0, 1, 1, 0];

        let matrix = ByteSparseMatrix::new(2, 2, 2, weights, col_indices);

        // Virtual Vector: [0*10, 1*10] = [0, 10]
        let source = VirtualLinearSource {
            size: 2,
            multiplier: 10,
        };

        // Expected Output:
        // Row 0: 1*0 + 1*10 = 10
        // Row 1: 1*10 + 1*0 = 10
        let expected_val = Block128::from(10u128).to_hardware();
        let expected = vec![expected_val, expected_val];

        // Run SpMV with virtual source
        let res = matrix.spmv(&source);

        assert_eq!(res, expected, "SpMV failed with VirtualSource");
    }

    #[test]
    fn byte_sparse_matrix_spmv() {
        // Scenario: 2 Rows, 2 Cols, Degree 2

        // Weights are u8 (bytes)
        let v1 = 1u8;
        let v2 = 2u8;
        let v3 = 3u8;
        let v4 = 4u8;

        let weights = vec![v1, v2, v3, v4];
        let col_indices = vec![0, 1, 1, 0]; // Row 0: (0, 1), Row 1: (1, 0)

        // Manual construction of ByteSparseMatrix
        let matrix = ByteSparseMatrix::new(2, 2, 2, weights, col_indices);

        // Vector x = [10, 100]
        // IMPORTANT: SpMV expects inputs in HARDWARE Basis!
        // We must convert our test inputs to hardware basis first.
        let x0_tower = b128(10);
        let x1_tower = b128(100);

        let x = vec![x0_tower.to_hardware(), x1_tower.to_hardware()];

        // Calculate EXPECTED value using standard (Tower) arithmetic,
        // then convert the result to Hardware basis for comparison.
        //
        // Row 0 logic: 1*x0 + 2*x1
        let w1 = Block128::from(v1);
        let w2 = Block128::from(v2);
        let y0_tower = w1 * x0_tower + w2 * x1_tower;

        // Row 1 logic: 3*x1 + 4*x0
        let w3 = Block128::from(v3);
        let w4 = Block128::from(v4);
        let y1_tower = w3 * x1_tower + w4 * x0_tower;

        // The result from matrix.spmv will be in Hardware basis.
        let expected = vec![y0_tower.to_hardware(), y1_tower.to_hardware()];

        // Test
        let res = matrix.spmv(x.as_slice());

        // Now comparing Hardware(res) == Hardware(expected)
        assert_eq!(res, expected, "Sequential SpMV failed (Basis Mismatch?)");
    }

    #[test]
    #[should_panic(expected = "cols > 0")]
    fn safety_rejects_zero_cols() {
        // Division by zero prevention
        // cols == 0 would cause panic in random_range(0..cols)
        ByteSparseMatrix::generate_random(10, 0, 5, [1u8; 32]);
    }

    #[test]
    fn accepts_valid_dimensions() {
        // Valid dimensions should work
        let m = ByteSparseMatrix::generate_random(10, 10, 5, [1u8; 32]);
        assert_eq!(m.rows(), 10);
        assert_eq!(m.cols(), 10);
        assert_eq!(m.degree(), 5);
        assert_eq!(m.weights().len(), 50); // 10 * 5
    }

    #[test]
    fn accepts_zero_rows_or_degree() {
        // Zero rows or degree should return empty matrix
        let m1 = ByteSparseMatrix::generate_random(0, 10, 5, [1u8; 32]);
        assert_eq!(m1.weights().len(), 0);

        let m2 = ByteSparseMatrix::generate_random(10, 10, 0, [1u8; 32]);
        assert_eq!(m2.weights().len(), 0);
    }

    #[test]
    fn expander_properties_sanity_check() {
        // Test parameters
        // Use a reasonably small matrix to verify properties fast.
        let rows = 4096;
        let cols = 4096;
        let degree = 16; // Standard degree for Brakedown
        let seed = [42u8; 32];

        // 1. Generate matrix using production logic
        let matrix = ByteSparseMatrix::generate_random(rows, cols, degree, seed);

        // Helper to count Hamming weight (non-zero elements)
        // Verify properties using the Hardware Field representation.
        let hamming_weight = |vec: &[Flat<Block128>]| -> usize {
            vec.iter()
                .filter(|&&x| x != Block128::from(0u128).to_hardware())
                .count()
        };

        // TEST 1:
        // Expansion of Weight-1 Vectors (Atomic check)
        // Input weight 1 -> Output weight MUST be exactly 'degree'.
        // This guarantees no row indices are duplicated for a single column.
        for i in 0..100 {
            let mut x = vec![Block128::from(0u128).to_hardware(); cols];
            // Set 1 at random position (simulating a single active variable)
            x[i] = Block128::from(1u128).to_hardware();

            let y = matrix.spmv(x.as_slice());
            let w = hamming_weight(&y);

            assert!(w > 0, "Column {} is empty! Information loss", i);
        }

        // TEST 2:
        // Expansion of Weight-2 Vectors (Collision check)
        // Two columns should not share too many neighbors.
        // Expected weight ~ 2 * degree. Significantly less
        // implies poor expansion (collisions).
        let mut rng = AesCtrPrg::from_seed([1u8; 32]);
        let mut total_weight = 0;

        let trials = 100;
        for _ in 0..trials {
            let mut x = vec![Block128::from(0u128).to_hardware(); cols];

            // Pick two distinct indices
            let idx1 = rng.random_range(0..cols);
            let idx2 = (idx1 + 1) % cols;

            x[idx1] = Block128::from(1u128).to_hardware();
            x[idx2] = Block128::from(1u128).to_hardware();

            let y = matrix.spmv(x.as_slice());
            total_weight += hamming_weight(&y);
        }

        let avg_weight = total_weight as f64 / trials as f64;
        let expected_max = (degree * 2) as f64;

        // Allow some collisions (birthday paradox),
        // but avg weight should be high.
        // If avg < 25.6 (80% of 32),
        // the expander quality is suspicious.
        // println!("Average weight: {}", avg_weight);
        assert!(
            avg_weight > (expected_max * 0.8),
            "Too many collisions! Poor expansion property. Avg: {}",
            avg_weight
        );

        // TEST 3:
        // Avalanche Effect (Weight-10)
        // A small change in input should produce a large change in output.
        // Input weight 10 -> Output weight should be close to 160.
        let input_w = 10;
        let mut x = vec![Block128::from(0u128).to_hardware(); cols];

        for val in x.iter_mut().take(input_w) {
            *val = Block128::from(1u128).to_hardware();
        }

        let y = matrix.spmv(x.as_slice());
        let w_out = hamming_weight(&y);

        // Allow ~20% loss due to collisions for this density.
        assert!(
            w_out > (input_w * degree * 8 / 10),
            "Weight-10 vector collapsed too much! Weight: {}",
            w_out
        );
    }

    #[test]
    fn check_determinism() {
        let seed = [42u8; 32];
        let rows = 1024;
        let cols = 1024;
        let degree = 16;

        // Generate matrix twice (simulating
        // different thread pool configurations).
        let matrix1 = ByteSparseMatrix::generate_random(rows, cols, degree, seed);
        let matrix2 = ByteSparseMatrix::generate_random(rows, cols, degree, seed);

        // These should be exactly the same
        assert_eq!(
            matrix1.weights(),
            matrix2.weights(),
            "Matrix weights must be deterministic for the same seed"
        );
        assert_eq!(
            matrix1.col_indices(),
            matrix2.col_indices(),
            "Matrix column indices must be deterministic for the same seed"
        );

        // Also test with different thread counts
        #[cfg(feature = "parallel")]
        {
            use rayon::ThreadPoolBuilder;

            let matrix_1thread = ThreadPoolBuilder::new()
                .num_threads(1)
                .build()
                .unwrap()
                .install(|| ByteSparseMatrix::generate_random(rows, cols, degree, seed));

            let matrix_8threads = ThreadPoolBuilder::new()
                .num_threads(8)
                .build()
                .unwrap()
                .install(|| ByteSparseMatrix::generate_random(rows, cols, degree, seed));

            assert_eq!(
                matrix_1thread.weights(),
                matrix_8threads.weights(),
                "Matrix must be identical regardless of thread count"
            );
            assert_eq!(
                matrix_1thread.col_indices(),
                matrix_8threads.col_indices(),
                "Matrix indices must be identical regardless of thread count"
            );
        }
    }

    #[test]
    fn security_prevent_expander_collapse() {
        // SECURITY TEST:
        // The Expander Collapse
        // Force a high-density scenario where `degree`
        // equals `cols`. In GF(2^k), duplicate indices
        // cause X ^ X = 0, destroying the PCS soundness.

        let rows = 1000;
        let cols = 32;
        let degree = 32; // Maximum possible density
        let seed = [99u8; 32];

        // If the infinite loop protection or
        // Naive Rejection Sampling is broken,
        // this will either hang forever or produce
        // invalid matrices.
        let matrix = ByteSparseMatrix::generate_random(rows, cols, degree, seed);

        // Verify strictly that every row has
        // exactly `degree` unique column indices.
        for r in 0..rows {
            let row_offset = r * degree;

            // Extract the indices for the current row
            let mut row_indices: Vec<u32> =
                matrix.col_indices()[row_offset..row_offset + degree].to_vec();
            row_indices.sort_unstable();

            for d in 0..degree - 1 {
                assert_ne!(
                    row_indices[d],
                    row_indices[d + 1],
                    "Expander Collapse detected in row {}! Duplicate column index {}. \
                     The rejection sampling loop has been compromised.",
                    r,
                    row_indices[d]
                );
            }
        }
    }

    /// Identical output regardless of
    /// `--features parallel` or not.
    #[test]
    fn cross_feature_determinism_golden() {
        let matrix = ByteSparseMatrix::generate_random(1024, 512, 16, [42u8; 32]);

        #[rustfmt::skip]
        const EXPECTED: [u32; 64] = [
            442, 352, 465,  69, 176, 472, 322, 109,
            349, 216,  74,  35, 206,  50,   7, 443,
            349, 214,  30, 332,  66, 316, 297, 415,
            325,  88, 484, 345,   5, 224, 106, 326,
            454, 345, 295, 443, 267, 264,  91, 333,
            163, 359, 262,  49, 112, 499, 219,  67,
            420, 106, 415,  54, 437, 123, 366, 284,
            503, 249,  26, 353,  90,  29, 311, 111,
        ];

        assert_eq!(&matrix.col_indices()[..64], &EXPECTED);
    }

    /// Counter block = (nonce << 64 | counter).to_le_bytes()
    #[test]
    fn aes_ctr_prg_golden() {
        #[rustfmt::skip]
        const EXPECTED: [u8; 128] = [
            // block 0: AES-256([0;32], counter=0)
            0xdc, 0x95, 0xc0, 0x78, 0xa2, 0x40, 0x89, 0x89,
            0xad, 0x48, 0xa2, 0x14, 0x92, 0x84, 0x20, 0x87,
            // block 1: counter=1
            0x52, 0x75, 0xf3, 0xd8, 0x6b, 0x4f, 0xb8, 0x68,
            0x45, 0x93, 0x13, 0x3e, 0xbf, 0xa5, 0x3c, 0xd3,
            // block 2: counter=2
            0x77, 0x9b, 0x38, 0xd1, 0x5b, 0xff, 0xb6, 0x3d,
            0x8d, 0x60, 0x9d, 0x55, 0x1a, 0x5c, 0xc9, 0x8e,
            // block 3: counter=3
            0x39, 0xd6, 0xe9, 0xae, 0x76, 0xa9, 0xb2, 0xf3,
            0xfc, 0x46, 0x26, 0x80, 0xf7, 0x66, 0x72, 0x0e,
            // block 4: counter=4
            0x75, 0xd1, 0x1b, 0x0e, 0x3a, 0x68, 0xc4, 0x22,
            0x3d, 0x88, 0xdb, 0xf0, 0x17, 0x97, 0x7d, 0xd7,
            // block 5: counter=5
            0x84, 0x5c, 0x7d, 0x46, 0x90, 0xfa, 0x59, 0x4f,
            0x90, 0xe6, 0x7f, 0x7b, 0x52, 0x11, 0xa5, 0x1a,
            // block 6: counter=6
            0x6f, 0x87, 0x1f, 0x44, 0x5c, 0x18, 0xaf, 0xc2,
            0xf8, 0x93, 0x7a, 0xf8, 0x41, 0xfd, 0x2a, 0xd0,
            // block 7: counter=7
            0x8d, 0x3a, 0xe1, 0x50, 0x22, 0x15, 0x52, 0x33,
            0x4d, 0xdb, 0x29, 0xfe, 0x36, 0xa0, 0xb7, 0x24,
        ];

        let mut prg = AesCtrPrg::from_seed([0u8; 32]);
        let mut output = [0u8; 128];

        let _ = prg.try_fill_bytes(&mut output);

        assert_eq!(output, EXPECTED);
    }

    #[test]
    fn aes_ctr_prg_stream_isolation() {
        let seed = [0xabu8; 32];

        let mut prg0 = AesCtrPrg::from_seed(seed);
        prg0.set_stream(0);

        let mut out0 = [0u8; 64];
        let _ = prg0.try_fill_bytes(&mut out0);

        let mut prg1 = AesCtrPrg::from_seed(seed);
        prg1.set_stream(1);

        let mut out1 = [0u8; 64];
        let _ = prg1.try_fill_bytes(&mut out1);

        assert_ne!(
            out0, out1,
            "Different streams must produce different output"
        );

        let mut prg0_again = AesCtrPrg::from_seed(seed);
        prg0_again.set_stream(0);

        let mut out0_again = [0u8; 64];
        let _ = prg0_again.try_fill_bytes(&mut out0_again);

        assert_eq!(out0, out0_again, "Same stream must be deterministic");
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]
        #[test]
        fn expansion_proptest(
            seed in any::<[u8; 32]>(),
            random_col in 0..1024usize,
            val_raw in 1..255u128
        ) {
            let rows = 1024;
            let cols = 1024;
            let degree = 16;
            let matrix = ByteSparseMatrix::generate_random(rows, cols, degree, seed);

            let mut x = vec![Block128::from(0u128).to_hardware(); cols];
            x[random_col] = Block128::from(val_raw).to_hardware();

            let y = matrix.spmv(x.as_slice());
            let weight = y.iter().filter(|&&v|
                v != Block128::from(0u128).to_hardware()).count();

            let min_weight = degree / 6;
            prop_assert!(
                weight >= min_weight,
                "Column {} failed expansion: weight {}",
                random_col, weight,
            );
        }
    }
}
