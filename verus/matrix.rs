// SPDX-License-Identifier: Apache-2.0
// This file is part of the hekate-math project.
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

//! Standalone Verus twin of production `process_chunk` (src/matrix.rs:250):
//! proves the SpMV loop indexes in bounds and leaves no output slot uninit.
//! `Flat<F>` is modeled as `u128`; field values don't affect memory safety.

use core::mem::MaybeUninit;
use vstd::prelude::*;
use vstd::slice::*;

verus! {

const LOOKAHEAD: usize = 8;

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

    fn process_chunk(&self, start_row: usize, out_chunk: &mut [MaybeUninit<u128>], x: &Vec<u128>)
        requires
            self.well_formed(),
            x@.len() == self.cols,
            start_row + old(out_chunk)@.len() <= self.rows,
        ensures
            forall|k: int|
                0 <= k < final(out_chunk)@.len() ==> (#[trigger] final(out_chunk)@[k]).mem_contents().is_init(),
    {
        let n = out_chunk.len();
        let mut i: usize = 0;

        while i < n
            invariant
                n == out_chunk@.len(),
                self.well_formed(),
                x@.len() == self.cols,
                start_row + n <= self.rows,
                forall|k: int|
                    0 <= k < i ==> (#[trigger] out_chunk@[k]).mem_contents().is_init(),
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
            out_chunk[i] = MaybeUninit::new(0u128);

            i += 1;
        }
    }

    // Twin of spmv (src/matrix.rs:209): build uninitialized, fill every row,
    // finalize. The chunked fill is flattened; chunk partitioning is trusted.
    fn spmv(&self, x: &Vec<u128>) -> (r: Vec<u128>)
        requires
            self.well_formed(),
            x@.len() == self.cols,
        ensures
            r@.len() == self.rows,
    {
        let mut y = alloc_uninit(self.rows);
        let mut i: usize = 0;

        while i < self.rows
            invariant
                y@.len() == self.rows,
                self.well_formed(),
                x@.len() == self.cols,
                forall|k: int| 0 <= k < i ==> (#[trigger] y@[k]).mem_contents().is_init(),
            decreases self.rows - i,
        {
            self.scan_row(i, x);
            y[i] = MaybeUninit::new(0u128);
            i += 1;
        }

        assume_init_vec(y)
    }
}

// src/matrix.rs:216-223, with_capacity + set_len; `n` slots, uninitialized.
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

// src/matrix.rs:326, from_raw_parts reinterpret; the `requires` is its
// soundness condition, discharged by every caller.
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