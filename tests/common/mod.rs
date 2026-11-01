// SPDX-License-Identifier: Apache-2.0
// This file is part of the hekate-math project.
// Copyright (C) 2026 Andrei Kochergin <andrei@oumuamua.dev>
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
// See the License for the specific language governing permissions and
// limitations under the License.

use hekate_math::{BinaryFieldExtras, Flat, HardwareField, TowerField};

pub mod cantor_oracle {
    include!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/build/cantor_oracle.rs"
    ));
}

pub fn eval_point<F: TowerField>(j: usize) -> F {
    let mut acc = F::ZERO;
    let mut bits = j;

    while bits != 0 {
        let i = bits.trailing_zeros() as usize;
        acc += F::from(cantor_oracle::CANTOR_TOWER[i]);
        bits &= bits - 1;
    }

    acc
}

/// Independent O(n^2) oracle: f(x) = Σ a_t X_t(x),
/// X_t = ∏_{bit i of t} s_i, s_i the i-fold σ(t) = t^2 + t.
pub fn horner_eval<F: BinaryFieldExtras>(coeffs: &[F], x: F, log_n: u32) -> F {
    let mut s = [F::ZERO; 64];
    s[0] = x;

    for i in 1..log_n as usize {
        s[i] = s[i - 1].square() + s[i - 1];
    }

    let mut acc = F::ZERO;
    for (t, &a) in coeffs.iter().enumerate() {
        let mut xt = F::ONE;
        let mut bits = t;

        while bits != 0 {
            let i = bits.trailing_zeros() as usize;
            xt *= s[i];
            bits &= bits - 1;
        }

        acc += a * xt;
    }

    acc
}

/// Oracle: the plain level loop over the
/// full twiddle table of `CANTOR_TOWER`.
pub fn reference_forward<F: HardwareField>(data: &mut [Flat<F>], offset: Flat<F>) {
    let log_n = data.len().trailing_zeros() as usize;
    let tw = reference_twiddles::<F>(log_n);

    let mut chain = vec![offset];
    for l in 1..log_n {
        let c = chain[l - 1];
        chain.push(c * c + c);
    }

    for l in (0..log_n).rev() {
        let s = 1usize << l;

        for (b, blk) in data.chunks_exact_mut(2 * s).enumerate() {
            let t = chain[l] + tw[b];
            let (lo, hi) = blk.split_at_mut(s);

            for (p, q) in lo.iter_mut().zip(hi.iter_mut()) {
                let v = *p + *q * t;
                *q = v + *q;
                *p = v;
            }
        }
    }
}

pub fn reference_twiddles<F: HardwareField>(log_n: usize) -> Vec<Flat<F>> {
    let mut tw = vec![Flat::from_raw(F::ZERO)];
    for &beta in &cantor_oracle::CANTOR_TOWER[1..log_n] {
        let beta = F::from(beta).to_hardware();
        for t in 0..tw.len() {
            let v = tw[t] + beta;
            tw.push(v);
        }
    }

    tw
}
