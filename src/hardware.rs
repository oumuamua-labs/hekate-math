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

//! The flat basis: `HardwareField` (φ and flat arithmetic), the
//! `Flat<F>` wrapper that keeps the bases apart, and `FlatPromote`.

use crate::packable::PackedFlat;
use crate::{PackableField, TowerField};
use core::fmt::{self, Debug, Formatter};
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use zeroize::Zeroize;

/// A [`TowerField`] with a flat basis: the isomorphism
/// φ and the flat arithmetic behind [`Flat`] operators.
pub trait HardwareField: TowerField + PackableField {
    /// Maps `self` to the flat basis: φ(self).
    fn to_hardware(self) -> Flat<Self>;

    /// Maps `value` back to the tower basis: φ⁻¹(value).
    fn from_hardware(value: Flat<Self>) -> Self;

    /// Adds two flat elements (XOR).
    fn add_hardware(lhs: Flat<Self>, rhs: Flat<Self>) -> Flat<Self>;

    /// Adds two packed flat vectors lane by lane (XOR).
    fn add_hardware_packed(lhs: PackedFlat<Self>, rhs: PackedFlat<Self>) -> PackedFlat<Self>;

    /// Multiplies two flat elements.
    fn mul_hardware(lhs: Flat<Self>, rhs: Flat<Self>) -> Flat<Self>;

    /// Multiplies two packed flat vectors lane by lane.
    fn mul_hardware_packed(lhs: PackedFlat<Self>, rhs: PackedFlat<Self>) -> PackedFlat<Self>;

    /// Multiplies every lane of `lhs` by the flat scalar `rhs`.
    fn mul_hardware_scalar_packed(lhs: PackedFlat<Self>, rhs: Flat<Self>) -> PackedFlat<Self>;

    /// Returns bit `bit_idx` of φ⁻¹(value) without
    /// a full conversion; constant time in `value`.
    ///
    /// # Panics
    /// If `bit_idx >= Self::BITS`.
    fn tower_bit_from_hardware(value: Flat<Self>, bit_idx: usize) -> u8;
}

/// An element of `F` in the flat basis; `+`, `-` and `*` compute in that basis.
#[derive(Copy, Clone, Default, PartialEq, Eq, Zeroize)]
#[repr(transparent)]
pub struct Flat<F>(F);

impl<F> Flat<F> {
    /// Wraps `raw` as flat-basis bits; does not convert.
    #[inline(always)]
    pub fn from_raw(raw: F) -> Self {
        Self(raw)
    }

    /// Returns the flat-basis bits; does not convert.
    #[inline(always)]
    pub fn into_raw(self) -> F {
        self.0
    }

    /// Borrows the flat-basis bits; does not convert.
    #[inline(always)]
    pub fn as_raw(&self) -> &F {
        &self.0
    }
}

impl<F: Debug> Debug for Flat<F> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Flat").field(&self.0).finish()
    }
}

impl<F: HardwareField> Flat<F> {
    /// Maps `self` back to the tower basis: φ⁻¹(self).
    #[inline(always)]
    pub fn to_tower(self) -> F {
        F::from_hardware(self)
    }

    /// Returns bit `bit_idx` of `self` in the tower basis.
    ///
    /// # Panics
    /// If `bit_idx >= F::BITS`.
    #[inline(always)]
    pub fn tower_bit(self, bit_idx: usize) -> u8 {
        F::tower_bit_from_hardware(self, bit_idx)
    }
}

impl<F: HardwareField> Add for Flat<F> {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        F::add_hardware(self, rhs)
    }
}

impl<F: HardwareField> AddAssign for Flat<F> {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<F: HardwareField> Sub for Flat<F> {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self::Output {
        F::add_hardware(self, rhs)
    }
}

impl<F: HardwareField> SubAssign for Flat<F> {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<F: HardwareField> Mul for Flat<F> {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        F::mul_hardware(self, rhs)
    }
}

impl<F: HardwareField> MulAssign for Flat<F> {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

/// Embedding of a flat subfield `FromF` into the flat basis of `Self`:
/// `promote_flat(x.to_hardware())` equals `Self::from(x).to_hardware()`.
pub trait FlatPromote<FromF>: HardwareField
where
    FromF: HardwareField,
{
    /// Maps a flat `FromF` element into the flat basis of `Self`.
    fn promote_flat(val: Flat<FromF>) -> Flat<Self>;

    /// Promotes `input[i]` into `output[i]` for every `i` below
    /// the shorter length; the rest of `output` is left as it is.
    fn promote_flat_batch(input: &[Flat<FromF>], output: &mut [Flat<Self>]) {
        for (o, v) in output.iter_mut().zip(input.iter()) {
            *o = Self::promote_flat(*v);
        }
    }
}

impl<F: HardwareField> FlatPromote<F> for F {
    #[inline(always)]
    fn promote_flat(val: Flat<F>) -> Flat<Self> {
        val
    }
}
