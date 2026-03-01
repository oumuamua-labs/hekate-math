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

use hekate_math::{Block8, Block16, Block32, Block64, Block128, TowerField};
use rand::{RngExt, SeedableRng, rngs::StdRng};
use std::fmt;
use std::ops::{Add, Mul};

// --- RANDOM GENERATION TRAIT ---
trait GenerateRand: TowerField {
    fn rand(rng: &mut StdRng) -> Self;
}

impl GenerateRand for Block8 {
    fn rand(rng: &mut StdRng) -> Self {
        Block8(rng.random())
    }
}

impl GenerateRand for Block16 {
    fn rand(rng: &mut StdRng) -> Self {
        Block16(rng.random::<u16>())
    }
}

impl GenerateRand for Block32 {
    fn rand(rng: &mut StdRng) -> Self {
        Block32(rng.random())
    }
}

impl GenerateRand for Block64 {
    fn rand(rng: &mut StdRng) -> Self {
        Block64(rng.random())
    }
}

impl GenerateRand for Block128 {
    fn rand(rng: &mut StdRng) -> Self {
        Block128(rng.random())
    }
}

// --- GENERIC POLYNOMIAL HELPER ---
#[derive(Clone, PartialEq)]
struct Poly<F: TowerField> {
    coeffs: Vec<F>,
}

impl<F: TowerField> fmt::Debug for Poly<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Poly")
    }
}

impl<F: TowerField> Poly<F> {
    fn new(mut c: Vec<F>) -> Self {
        while let Some(last) = c.last() {
            if *last == F::ZERO {
                c.pop();
            } else {
                break;
            }
        }
        Self { coeffs: c }
    }

    fn degree(&self) -> isize {
        if self.coeffs.is_empty() {
            -1
        } else {
            (self.coeffs.len() - 1) as isize
        }
    }
}

// Ops for Generic Poly
impl<F: TowerField> Add for &Poly<F> {
    type Output = Poly<F>;

    fn add(self, rhs: Self) -> Poly<F> {
        let max = std::cmp::max(self.coeffs.len(), rhs.coeffs.len());
        let mut res = Vec::with_capacity(max);

        for i in 0..max {
            let a = if i < self.coeffs.len() {
                self.coeffs[i]
            } else {
                F::ZERO
            };

            let b = if i < rhs.coeffs.len() {
                rhs.coeffs[i]
            } else {
                F::ZERO
            };

            res.push(a + b);
        }

        Poly::new(res)
    }
}

impl<F: TowerField> Mul for &Poly<F> {
    type Output = Poly<F>;

    fn mul(self, rhs: Self) -> Poly<F> {
        if self.coeffs.is_empty() || rhs.coeffs.is_empty() {
            return Poly::new(vec![]);
        }

        let mut res = vec![F::ZERO; self.coeffs.len() + rhs.coeffs.len()];
        for i in 0..self.coeffs.len() {
            if self.coeffs[i] == F::ZERO {
                continue;
            }

            for j in 0..rhs.coeffs.len() {
                res[i + j] += self.coeffs[i] * rhs.coeffs[j];
            }
        }

        Poly::new(res)
    }
}

// Generic Modulo & GCD
fn poly_mod<F: TowerField>(a: &Poly<F>, b: &Poly<F>) -> Poly<F> {
    let mut rem = a.clone();
    let inv = b.coeffs.last().unwrap().invert();

    while rem.degree() >= b.degree() {
        let diff = (rem.degree() - b.degree()) as usize;
        let scale = *rem.coeffs.last().unwrap() * inv;

        for (i, c) in b.coeffs.iter().enumerate() {
            if i + diff < rem.coeffs.len() {
                rem.coeffs[i + diff] += *c * scale;
            }
        }

        // Manual trim
        while let Some(last) = rem.coeffs.last() {
            if *last == F::ZERO {
                rem.coeffs.pop();
            } else {
                break;
            }
        }
    }

    rem
}

fn poly_gcd<F: TowerField>(a: &Poly<F>, b: &Poly<F>) -> Poly<F> {
    let (mut x, mut y) = (a.clone(), b.clone());
    while y.degree() >= 0 {
        let r = poly_mod(&x, &y);
        x = y;
        y = r;
    }

    if let Some(l) = x.coeffs.last() {
        let inv = l.invert();
        for c in x.coeffs.iter_mut() {
            *c *= inv;
        }
    }

    x
}

fn find_root<F: TowerField + GenerateRand>(target_poly: Poly<F>) -> F {
    let mut factors = vec![target_poly];
    let mut rng = StdRng::seed_from_u64(42);

    // x term
    let x_poly = Poly::new(vec![F::ZERO, F::ONE]);

    loop {
        let curr = factors.pop().unwrap();
        if curr.degree() == 1 {
            // ax + b = 0 -> x = b/a
            return curr.coeffs[0] * curr.coeffs[1].invert();
        }

        // Trace Map:
        // x + x^2 + ... + x^(2^(BITS-1))
        let delta = F::rand(&mut rng);
        let dx_base = &x_poly * &Poly::new(vec![delta]);
        let dx = poly_mod(&dx_base, &curr);

        let mut trace = dx.clone();
        let mut term = dx;

        // Compute Trace
        for _ in 0..(F::BITS - 1) {
            // Square term
            let mut sq = vec![F::ZERO; term.coeffs.len() * 2];
            for (i, c) in term.coeffs.iter().enumerate() {
                sq[2 * i] = *c * *c;
            }

            term = poly_mod(&Poly::new(sq), &curr);
            trace = &trace + &term;
        }

        let gcd = poly_gcd(&curr, &trace);
        if gcd.degree() > 0 && gcd.degree() < curr.degree() {
            factors.push(gcd);
        } else {
            factors.push(curr);
        }
    }
}

// --- LINEAR ALGEBRA UTILS ---

macro_rules! impl_invert_matrix {
    ($func_name:ident, $type:ty, $size:expr) => {
        fn $func_name(cols: [$type; $size]) -> [$type; $size] {
            let mut rows = [0 as $type; $size];
            let mut inv = [0 as $type; $size];

            // 1. Transpose input (cols -> rows)
            // and setup Identity matrix.
            for r in 0..$size {
                // Cast 1 to the target type
                inv[r] = (1 as $type) << r;

                for (c, &col) in cols.iter().enumerate() {
                    if (col >> r) & 1 == 1 {
                        rows[r] |= (1 as $type) << c;
                    }
                }
            }

            // 2. Gaussian elimination
            for i in 0..$size {
                let mut p = i;

                // Find pivot
                while p < $size && (rows[p] >> i) & 1 == 0 {
                    p += 1;
                }

                rows.swap(i, p);
                inv.swap(i, p);

                // Eliminate other rows
                for k in 0..$size {
                    if k != i && (rows[k] >> i) & 1 == 1 {
                        rows[k] ^= rows[i];
                        inv[k] ^= inv[i];
                    }
                }
            }

            // 3. Transpose result back (inv rows -> output cols)
            let mut res = [0 as $type; $size];
            for (c, res_c) in res.iter_mut().enumerate() {
                for (r, &inv_r) in inv.iter().enumerate() {
                    if (inv_r >> c) & 1 == 1 {
                        *res_c |= (1 as $type) << r;
                    }
                }
            }

            res
        }
    };
}

impl_invert_matrix!(invert_matrix_8, u8, 8);
impl_invert_matrix!(invert_matrix_16, u16, 16);
impl_invert_matrix!(invert_matrix_32, u32, 32);
impl_invert_matrix!(invert_matrix_64, u64, 64);
impl_invert_matrix!(invert_matrix_128, u128, 128);

// --- PRINTING TABLES (8-bit window) ---

macro_rules! impl_print_table {
    ($func_name:ident, $type:ty, $windows:expr, $hex_fmt:literal) => {
        fn $func_name(name: &str, cols: &[$type]) {
            // Print the array definition header
            println!(
                "    pub const {}: [{}; {}] = [",
                name,
                stringify!($type),
                $windows * 256
            );

            // Iterate over 8-bit windows
            for w in 0..$windows {
                for val in 0..=255u8 {
                    let mut res = 0 as $type;

                    // Slice the specific window of 8 columns
                    let window = &cols[(w * 8)..((w + 1) * 8)];
                    for (bit, &col) in window.iter().enumerate() {
                        if (val >> bit) & 1 == 1 {
                            res ^= col;
                        }
                    }

                    println!($hex_fmt, res);
                }
            }

            println!("    ];");
        }
    };
}

impl_print_table!(print_table_8, u8, 1, "        0x{:02x},");
impl_print_table!(print_table_16, u16, 2, "        0x{:04x},");
impl_print_table!(print_table_32, u32, 4, "        0x{:08x},");
impl_print_table!(print_table_64, u64, 8, "        0x{:016x},");
impl_print_table!(print_table_128, u128, 16, "        0x{:032x},");

// --- MAIN GENERATORS ---

fn gen_tables_16() {
    println!("\n// === 16 BIT CONSTANTS ===");
    // P(x) = x^16 + x^5 + x^3 + x + 1 (Sparse)
    // Coeffs: 16, 5, 3, 1, 0
    let mut c = vec![Block16::ZERO; 17];
    c[16] = Block16::ONE;
    c[5] = Block16::ONE;
    c[3] = Block16::ONE;
    c[1] = Block16::ONE;
    c[0] = Block16::ONE;

    let gen_val = find_root(Poly::new(c));
    println!("// Generator 16: {:?}", gen_val);

    let mut flat = [0u16; 16];
    let mut curr = Block16::ONE;

    for v in flat.iter_mut() {
        *v = curr.0;
        curr *= gen_val;
    }

    let inv = invert_matrix_16(flat);

    print_table_16("FLAT_TO_TOWER_16", &flat);
    print_table_16("TOWER_TO_FLAT_16", &inv);
}

fn gen_tables_8() {
    println!("\n// === 8 BIT CONSTANTS ===");
    // P(x) = x^8 + x^4 + x^3 + x + 1 (AES, our native Block8 poly)
    // Since Block8 is already using this poly,
    // the generator should be just 'x' (element 2).
    let mut c = vec![Block8::ZERO; 9];
    c[8] = Block8::ONE;
    c[4] = Block8::ONE;
    c[3] = Block8::ONE;
    c[1] = Block8::ONE;
    c[0] = Block8::ONE;

    let gen_val = find_root(Poly::new(c));
    println!("// Generator 8: {:?}", gen_val);

    let mut flat = [0u8; 8];
    let mut curr = Block8::ONE;

    for v in flat.iter_mut() {
        *v = curr.0;
        curr *= gen_val;
    }

    let inv = invert_matrix_8(flat);

    print_table_8("FLAT_TO_TOWER_8", &flat);
    print_table_8("TOWER_TO_FLAT_8", &inv);
}

fn gen_tables_128() {
    println!("\n// === 128 BIT CONSTANTS ===");
    let mut c = vec![Block128::ZERO; 129];
    c[128] = Block128::ONE;
    c[7] = Block128::ONE;
    c[2] = Block128::ONE;
    c[1] = Block128::ONE;
    c[0] = Block128::ONE;

    let gen_val = find_root(Poly::new(c));
    println!("// Generator 128: {:?}", gen_val);

    let mut flat = [0u128; 128];
    let mut curr = Block128::ONE;

    for v in flat.iter_mut() {
        *v = curr.0;
        curr *= gen_val;
    }

    let inv = invert_matrix_128(flat);

    print_table_128("FLAT_TO_TOWER_128", &flat);
    print_table_128("TOWER_TO_FLAT_128", &inv);
}

fn gen_tables_64() {
    println!("\n// === 64 BIT CONSTANTS ===");
    let mut c = vec![Block64::ZERO; 65];
    c[64] = Block64::ONE;
    c[4] = Block64::ONE;
    c[3] = Block64::ONE;
    c[1] = Block64::ONE;
    c[0] = Block64::ONE;

    let gen_val = find_root(Poly::new(c));
    println!("// Generator 64: {:?}", gen_val);

    let mut flat = [0u64; 64];
    let mut curr = Block64::ONE;

    for v in flat.iter_mut() {
        *v = curr.0;
        curr *= gen_val;
    }

    let inv = invert_matrix_64(flat);

    print_table_64("FLAT_TO_TOWER_64", &flat);
    print_table_64("TOWER_TO_FLAT_64", &inv);
}

fn gen_tables_32() {
    println!("\n// === 32 BIT CONSTANTS ===");
    let mut c = vec![Block32::ZERO; 33];
    c[32] = Block32::ONE;
    c[7] = Block32::ONE;
    c[3] = Block32::ONE;
    c[2] = Block32::ONE;
    c[0] = Block32::ONE;

    let gen_val = find_root(Poly::new(c));
    println!("// Generator 32: {:?}", gen_val);

    let mut flat = [0u32; 32];
    let mut curr = Block32::ONE;

    for v in flat.iter_mut() {
        *v = curr.0;
        curr *= gen_val;
    }

    let inv = invert_matrix_32(flat);

    print_table_32("FLAT_TO_TOWER_32", &flat);
    print_table_32("TOWER_TO_FLAT_32", &inv);
}

#[ignore]
#[test]
fn generate_all_iso_tables() {
    println!("pub mod constants {{");

    // 8
    println!(
        "    pub const POLY_8: u8 = 0x{:02x};",
        (1 << 4) | (1 << 3) | (1 << 1) | 1
    );
    gen_tables_8();

    println!(
        "    pub const POLY_16: u16 = 0x{:04x};",
        (1 << 5) | (1 << 3) | (1 << 1) | 1
    );
    gen_tables_16();

    println!(
        "    pub const POLY_32: u32 = 0x{:08x};",
        (1 << 7) | (1 << 3) | (1 << 2) | 1
    );
    gen_tables_32();

    println!(
        "    pub const POLY_64: u64 = 0x{:016x};",
        (1 << 4) | (1 << 3) | (1 << 1) | 1
    );
    gen_tables_64();

    println!(
        "    pub const POLY_128: u128 = 0x{:032x};",
        (1 << 7) | (1 << 2) | (1 << 1) | 1
    );
    gen_tables_128();

    println!("}}");
}
