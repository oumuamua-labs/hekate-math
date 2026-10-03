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

//! Binary tower fields GF(2^8) through GF(2^256), each with a
//! second, polynomial basis for carry-less multiplication hardware.
//!
//! Every level is a quadratic extension of the one below:
//! GF(2^(2m)) = GF(2^m)\[X\] / (X^2 + X + τ), τ the lower level's
//! [`TowerField::EXTENSION_TAU`]. [`Block8`] is the AES field,
//! GF(2)\[x\] / (x^8 + x^4 + x^3 + x + 1) (FIPS-197 §4.2), and [`Bit`]
//! is GF(2) inside it. A level stores its `(lo, hi)` pair as one
//! integer, `Block16(u16)` to `Block128(u128)`; `Block256` holds
//! `[u128; 2]`.
//!
//! # Two bases
//!
//! Tower elements have type `F`. The same field in the flat basis
//! has type [`Flat<F>`], and the two types never mix in arithmetic.
//! [`HardwareField::to_hardware`] maps tower to flat and
//! [`HardwareField::from_hardware`] maps back. The flat basis is
//! GF(2)\[x\] modulo:
//!
//! | Field     | Flat modulus               |
//! |:----------|:---------------------------|
//! | GF(2^8)   | x^8 + x^4 + x^3 + x + 1    |
//! | GF(2^16)  | x^16 + x^5 + x^3 + x + 1   |
//! | GF(2^32)  | x^32 + x^7 + x^3 + x^2 + 1 |
//! | GF(2^64)  | x^64 + x^4 + x^3 + x + 1   |
//! | GF(2^128) | x^128 + x^7 + x^2 + x + 1  |
//!
//! `Flat<Block256>` extends the GF(2^128) flat basis by
//! y^2 + y + φ(τ), φ the tower-to-flat map.
//!
//! [`PackableField`] groups `WIDTH` elements into one packed value and
//! [`PackedFlat<F>`] is its flat form. [`FlatPromote`] embeds a flat
//! subfield element into a flat superfield.
//!
//! # Timing
//!
//! By default the basis maps are bit-sliced matrix products: no
//! branch or memory access depends on the value. Timing is not
//! formally verified. The `table-math` feature swaps in lookup tables
//! for the basis maps, the subfield lifts and GF(2^8) arithmetic;
//! their memory access depends on the operands, for public data only.
//!
//! Flat multiplication from GF(2^32) up uses PMULL on aarch64 with
//! the `aes` target feature, which `aarch64-unknown-linux-gnu` leaves
//! off by default (`-C target-feature=+aes`). Other targets take a
//! software path with the same results.
//!
//! # Features
//!
//! | Feature      | Default | Effect                                |
//! |:-------------|:--------|:--------------------------------------|
//! | `std`        | yes     | without it: `no_std` with `alloc`     |
//! | `parallel`   | yes     | Rayon for FFT buffers of 1 MiB and up |
//! | `table-math` | no      | variable-time lookup tables, above    |
//!
//! # Contents
//!
//! [`fft`] holds the additive FFT over the Cantor basis
//! ([`AdditiveFft`], [`CantorBasis`]) and a systematic Reed-Solomon
//! encoder ([`ReedSolomon`]). [`BinaryFieldExtras`] adds square,
//! Frobenius, trace and a root of x^2 + x = c, for Block16 through
//! Block256.
//!
//! # Examples
//!
//! ## Isomorphic workflow
//!
//! ```
//! use hekate_math::{Block128, HardwareField, TowerField};
//!
//! let a = Block128::from_uniform_bytes(&[0xaa; 32]);
//! let b = Block128::from_uniform_bytes(&[0xbb; 32]);
//!
//! let product = (a.to_hardware() * b.to_hardware()).to_tower();
//! assert_eq!(product, a * b);
//! ```
//!
//! ## SIMD vectorization
//!
//! ```
//! use hekate_math::{Block32, Flat, HardwareField, PackableField};
//!
//! let data: Vec<Flat<Block32>> = (1..=8u32)
//!     .map(|i| Block32::from(i).to_hardware())
//!     .collect();
//!
//! let a = Flat::<Block32>::pack(&data[..4]);
//! let b = Flat::<Block32>::pack(&data[4..]);
//!
//! let mut out = [Flat::<Block32>::default(); 4];
//! Flat::<Block32>::unpack(a * b, &mut out);
//!
//! for (i, lane) in out.iter().enumerate() {
//!     let expected = data[i].to_tower() * data[4 + i].to_tower();
//!     assert_eq!(lane.to_tower(), expected);
//! }
//! ```
//!
//! ## Additive FFT
//!
//! ```
//! use hekate_math::{AdditiveFft, Block16, Flat, HardwareField};
//!
//! let log_n = 10;
//! let fft = AdditiveFft::<Block16>::new(log_n)?;
//!
//! let coeffs: Vec<Flat<Block16>> = (0..1u32 << log_n)
//!     .map(|i| Block16::from(i).to_hardware())
//!     .collect();
//!
//! let mut data = coeffs.clone();
//! fft.forward_scalar(&mut data)?;
//! fft.inverse_scalar(&mut data)?;
//!
//! assert_eq!(data, coeffs);
//! # Ok::<(), hekate_math::FftError>(())
//! ```
//!
//! # Formal verification
//!
//! Tower `mul` and `invert`, the NEON kernels, the constant-time
//! basis maps and the additive FFT have Verus proofs against a
//! GF(2^k) model, kept outside the crate build in [`verus/`][verus].
//!
//! [verus]: https://github.com/oumuamua-labs/hekate-math/tree/main/verus

#![cfg_attr(not(feature = "std"), no_std)]
#![warn(missing_docs)]

extern crate alloc;

mod algebra;
mod field;
mod towers;

mod constants;
mod hardware;
mod packable;

pub mod fft;

pub use algebra::BinaryFieldExtras;
pub use fft::{AdditiveFft, CantorBasis, CantorError, FftError, ReedSolomon, RsError};
pub use field::*;
pub use hardware::{Flat, FlatPromote, HardwareField};
pub use packable::{PackableField, PackedFlat};
pub use towers::*;
