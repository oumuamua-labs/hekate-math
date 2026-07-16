// SPDX-License-Identifier: Apache-2.0
// This file is part of the hekate-math project.
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

//! Memory-safety twin of production `process_chunk`/`spmv`:
//! indexes in bounds, every slot initialized, writes confined
//! to each chunk's range. `Flat<F>` is `u128`; values don't
//! affect safety. Confinement stands in for the disjoint
//! `&mut` subslices production uses; rayon's partition
//! contract stays trusted (TRUSTED_AXIOMS.md).

use core::mem::MaybeUninit;
use vstd::prelude::*;
use vstd::slice::*;

verus! {

const LOOKAHEAD: usize = 8;
const CHUNK_SIZE: usize = 1024;

struct ByteSparseMatrix {
    rows: usize,
    cols: usize,
    degree: usize,
    weights: Vec<u8>,
    col_indices: Vec<u32>,
}

impl ByteSparseMatrix {
    spec fn well_formed(self) -> bool {
        &&& self.weights@.len() == self.rows * self.degree
        &&& self.col_indices@.len() == self.rows * self.degree
        &&& self.rows * self.degree <= usize::MAX
        &&& forall|t: int|
            0 <= t < self.col_indices@.len() ==> (#[trigger] self.col_indices@[t]) < self.cols
    }

    proof fn lemma_no_overflow(self, row_idx: usize)
        requires
            self.well_formed(),
            row_idx < self.rows,
        ensures
            row_idx * self.degree <= usize::MAX,
    {
        assert(row_idx * self.degree <= self.rows * self.degree) by (nonlinear_arith)
            requires row_idx <= self.rows;
    }

    proof fn lemma_row_span(self, row_idx: usize, m: usize)
        requires
            self.well_formed(),
            row_idx < self.rows,
            m < self.degree,
        ensures
            (row_idx * self.degree + m) < self.rows * self.degree,
    {
        assert((row_idx + 1) * self.degree <= self.rows * self.degree) by (nonlinear_arith)
            requires row_idx + 1 <= self.rows;

        assert(row_idx * self.degree + m < (row_idx + 1) * self.degree) by (nonlinear_arith)
            requires m < self.degree;
    }

    // Production unrolls this 8-way + tail (src/matrix.rs:288-318); same
    // accessed range [row_offset, row_offset+degree), one loop covers both.
    fn scan_row(&self, row_idx: usize, x: &Vec<u128>)
        requires
            self.well_formed(),
            x@.len() == self.cols,
            row_idx < self.rows,
    {
        proof {
            self.lemma_no_overflow(row_idx);
        }

        let row_offset = row_idx * self.degree;
        let mut j: usize = 0;

        while j < self.degree
            invariant
                self.well_formed(),
                x@.len() == self.cols,
                row_idx < self.rows,
                row_offset == row_idx * self.degree,
            decreases self.degree - j,
        {
            proof {
                self.lemma_row_span(row_idx, j);
            }

            let idx = row_offset + j;
            let col = self.col_indices[idx] as usize;
            let _w = self.weights[idx];

            assert((self.col_indices@[idx as int] as int) < self.cols);
            let _v = x[col];

            j += 1;
        }
    }

    // Rows [start_row, start_row + chunk_len): every index read in bounds,
    // every slot in the range initialized, no slot outside the range touched.
    fn process_chunk(
        &self,
        start_row: usize,
        chunk_len: usize,
        y: &mut Vec<MaybeUninit<u128>>,
        x: &Vec<u128>,
    )
        requires
            self.well_formed(),
            x@.len() == self.cols,
            old(y)@.len() == self.rows,
            start_row + chunk_len <= self.rows,
        ensures
            final(y)@.len() == old(y)@.len(),
            forall|k: int|
                start_row <= k < start_row + chunk_len
                    ==> (#[trigger] final(y)@[k]).mem_contents().is_init(),
            forall|k: int|
                0 <= k < final(y)@.len() && (k < start_row || start_row + chunk_len <= k)
                    ==> (#[trigger] final(y)@[k]) == old(y)@[k],
    {
        let n = chunk_len;
        let mut i: usize = 0;

        while i < n
            invariant
                self.well_formed(),
                x@.len() == self.cols,
                y@.len() == self.rows,
                n == chunk_len,
                start_row + n <= self.rows,
                i <= n,
                forall|k: int|
                    start_row <= k < start_row + i
                        ==> (#[trigger] y@[k]).mem_contents().is_init(),
                forall|k: int|
                    0 <= k < y@.len() && (k < start_row || start_row + i <= k)
                        ==> (#[trigger] y@[k]) == old(y)@[k],
            decreases n - i,
        {
            let row_idx = start_row + i;
            assert(row_idx < self.rows);

            // Overflow-safe form of production's `i + LOOKAHEAD < len` (src/matrix.rs:265).
            if LOOKAHEAD < n - i {
                let next_row = row_idx + LOOKAHEAD;
                assert(next_row < self.rows);
                self.scan_row(next_row, x);
            }

            self.scan_row(row_idx, x);
            y[row_idx] = MaybeUninit::new(0u128);

            i += 1;
        }
    }

    // The invariant proves production's enumerate() arithmetic:
    // start_row == chunk_id * CHUNK_SIZE. Confinement makes
    // chunk order irrelevant, covering the parallel path too.
    fn spmv(&self, x: &Vec<u128>) -> (r: Vec<u128>)
        requires
            self.well_formed(),
            x@.len() == self.cols,
        ensures
            r@.len() == self.rows,
    {
        let mut y = alloc_uninit(self.rows);
        let mut chunk_id: usize = 0;
        let mut start_row: usize = 0;

        while start_row < self.rows
            invariant
                self.well_formed(),
                x@.len() == self.cols,
                y@.len() == self.rows,
                start_row == chunk_id * CHUNK_SIZE || start_row == self.rows,
                forall|k: int|
                    0 <= k < start_row ==> (#[trigger] y@[k]).mem_contents().is_init(),
            decreases self.rows - start_row,
        {
            let chunk_len = if CHUNK_SIZE < self.rows - start_row {
                CHUNK_SIZE
            } else {
                self.rows - start_row
            };

            self.process_chunk(start_row, chunk_len, &mut y, x);

            chunk_id += 1;
            start_row += chunk_len;
        }

        assume_init_vec(y)
    }
}

// src/matrix.rs, with_capacity + set_len; `n` slots, uninitialized.
#[verifier::external_body]
fn alloc_uninit(n: usize) -> (v: Vec<MaybeUninit<u128>>)
    ensures
        v@.len() == n,
{
    let mut v = Vec::with_capacity(n);
    unsafe {
        v.set_len(n);
    }
    v
}

// src/matrix.rs, from_raw_parts reinterpret; the `requires`
// is its soundness condition, discharged by every caller.
#[verifier::external_body]
fn assume_init_vec(v: Vec<MaybeUninit<u128>>) -> (r: Vec<u128>)
    requires
        forall|k: int| 0 <= k < v@.len() ==> (#[trigger] v@[k]).mem_contents().is_init(),
    ensures
        r@.len() == v@.len(),
{
    let mut v = v;
    let ptr = v.as_mut_ptr() as *mut u128;
    let len = v.len();
    let cap = v.capacity();
    core::mem::forget(v);
    unsafe { Vec::from_raw_parts(ptr, len, cap) }
}

fn main() {}

}
