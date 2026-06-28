// SPDX-License-Identifier: Apache-2.0
// This file is part of the hekate-math project.
// Copyright (C) 2026 Andrei Kochergin <andrei@oumuamua.dev>
// Copyright (C) 2026 Oumuamua Labs <info@oumuamua.dev>. All rights reserved.
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

use crate::{Flat, HardwareField};
use alloc::vec::Vec;
use core::arch::asm;
use core::mem::MaybeUninit;
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
/// implements `HardwareField`.
///
/// SOUNDNESS:
/// weights must be binary (0 or 1).
/// tower_bit is GF(2)-linear, not
/// GF(2^k)-linear, non-binary weight
/// break virtual packing commutativity.
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
        assert!(
            weights.iter().all(|&w| w == 0 || w == 1),
            "Virtual packing requires binary weights"
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

    /// Binary SpMV:
    /// weights are 0 or 1, so each
    /// term is a conditional XOR.
    /// Accepts any source implementing `VectorSource`.
    pub fn spmv<F, V>(&self, x: &V) -> Vec<Flat<F>>
    where
        F: HardwareField,
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

    /// Process a chunk of rows
    /// with lookahead prefetching.
    #[inline(always)]
    fn process_chunk<F, V>(&self, start_row: usize, out_chunk: &mut [MaybeUninit<Flat<F>>], x: &V)
    where
        F: HardwareField + Default + Copy,
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

            // Binary weight invariant:
            // w ∈ {0, 1}
            while j + B <= self.degree {
                let mut col_idxs = [0usize; B];
                unsafe {
                    for (k, slot) in col_idxs.iter_mut().enumerate() {
                        *slot = *self.col_indices.get_unchecked(row_offset + j + k) as usize;
                    }
                }

                let values = x.get_batch::<B>(&col_idxs);
                unsafe {
                    for (k, &val) in values.iter().enumerate() {
                        if *self.weights.get_unchecked(row_offset + j + k) != 0 {
                            acc += val;
                        }
                    }
                }

                j += B;
            }

            while j < self.degree {
                unsafe {
                    let curr = row_offset + j;
                    if *self.weights.get_unchecked(curr) != 0 {
                        let col_idx = *self.col_indices.get_unchecked(curr) as usize;
                        acc += x.get_at(col_idx);
                    }
                }

                j += 1;
            }

            out_chunk[i].write(acc);
        }
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
        // 2 rows, 3 cols, degree 2,
        // binary weights only.
        let weights = vec![1u8, 1u8, 1u8, 1u8];

        // Row 0:
        // col 0 + col 2,
        // Row 1:
        // col 1 + col 0
        let col_indices = vec![0, 2, 1, 0];

        let matrix = ByteSparseMatrix::new(2, 3, 2, weights, col_indices);

        let x0_tower = b128(10);
        let x1_tower = b128(100);
        let x2_tower = b128(255);

        let x = vec![
            x0_tower.to_hardware(),
            x1_tower.to_hardware(),
            x2_tower.to_hardware(),
        ];

        // Row 0:
        // 1*x0 + 1*x2 = x0 + x2 (XOR)
        let y0_tower = x0_tower + x2_tower;

        // Row 1:
        // 1*x1 + 1*x0 = x1 + x0 (XOR)
        let y1_tower = x1_tower + x0_tower;

        let expected = vec![y0_tower.to_hardware(), y1_tower.to_hardware()];
        let res = matrix.spmv(x.as_slice());

        assert_eq!(res, expected, "Sequential SpMV failed (Basis Mismatch?)");
    }

    #[test]
    fn zero_weight_entries_contribute_nothing() {
        // 2 rows, 3 cols, degree 3.
        // Row 0:
        // w=1 col=0,
        // w=0 col=1,
        // w=1 col=2
        // Row 1:
        // w=0 col=0,
        // w=1 col=1,
        // w=0 col=2
        let weights = vec![1, 0, 1, 0, 1, 0];
        let col_indices = vec![0, 1, 2, 0, 1, 2];
        let matrix = ByteSparseMatrix::new(2, 3, 3, weights, col_indices);

        let x0 = b128(0xA0);
        let x1 = b128(0xB0);
        let x2 = b128(0xC0);
        let x = vec![x0.to_hardware(), x1.to_hardware(), x2.to_hardware()];

        // Row 0:
        // 1*x0 + 0*x1 + 1*x2 = x0 + x2
        // Row 1:
        // 0*x0 + 1*x1 + 0*x2 = x1
        let expected = vec![(x0 + x2).to_hardware(), x1.to_hardware()];

        assert_eq!(matrix.spmv(x.as_slice()), expected);
    }

    #[test]
    #[should_panic(expected = "binary weights")]
    fn rejects_non_binary_weights() {
        ByteSparseMatrix::new(1, 2, 2, vec![1, 3], vec![0, 1]);
    }
}
