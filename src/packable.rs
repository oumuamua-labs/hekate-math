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

use crate::{Flat, HardwareField};
use core::fmt;
use core::fmt::{Debug, Formatter};
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

/// A trait linking a Field element
/// to its SIMD packed representation.
pub trait PackableField: Sized + Copy + Clone + Default {
    /// The packed vector type (e.g., PackedBlock128).
    type Packed: Add<Output = Self::Packed>
        + Sub<Output = Self::Packed>
        + Mul<Output = Self::Packed>
        + Mul<Self, Output = Self::Packed>
        + AddAssign
        + SubAssign
        + MulAssign
        + Copy
        + Clone
        + Default;

    /// How many elements fit in one packed vector.
    const WIDTH: usize;

    /// Pack a slice of scalars into a vector.
    /// Panics if slice len < WIDTH.
    fn pack(chunk: &[Self]) -> Self::Packed;

    /// Unpack vector back to scalars.
    fn unpack(packed: Self::Packed, output: &mut [Self]);
}

impl<F: HardwareField> PackableField for Flat<F> {
    type Packed = PackedFlat<F>;

    const WIDTH: usize = F::WIDTH;

    #[inline(always)]
    fn pack(chunk: &[Self]) -> Self::Packed {
        PackedFlat::from_raw(F::pack(flat_slice_as_raw(chunk)))
    }

    #[inline(always)]
    fn unpack(packed: Self::Packed, output: &mut [Self]) {
        F::unpack(packed.into_raw(), flat_slice_as_raw_mut(output));
    }
}

/// A packed SIMD register storing
/// hardware / flat-basis field elements.
#[repr(transparent)]
pub struct PackedFlat<F: PackableField>(<F as PackableField>::Packed);

impl<F> PackedFlat<F>
where
    F: PackableField,
{
    #[inline(always)]
    pub fn from_raw(raw: F::Packed) -> Self {
        Self(raw)
    }

    #[inline(always)]
    pub fn into_raw(self) -> F::Packed {
        self.0
    }

    #[inline(always)]
    pub fn as_raw(&self) -> &F::Packed {
        &self.0
    }
}

impl<F> Copy for PackedFlat<F>
where
    F: PackableField,
    F::Packed: Copy,
{
}

impl<F> Clone for PackedFlat<F>
where
    F: PackableField,
    F::Packed: Copy,
{
    #[inline(always)]
    fn clone(&self) -> Self {
        *self
    }
}

impl<F> Default for PackedFlat<F>
where
    F: PackableField,
    F::Packed: Default,
{
    #[inline(always)]
    fn default() -> Self {
        Self(F::Packed::default())
    }
}

impl<F> PartialEq for PackedFlat<F>
where
    F: PackableField,
    F::Packed: PartialEq,
{
    #[inline(always)]
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<F> Eq for PackedFlat<F>
where
    F: PackableField,
    F::Packed: Eq,
{
}

impl<F> Debug for PackedFlat<F>
where
    F: PackableField,
    F::Packed: Debug,
{
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PackedFlat").field(&self.0).finish()
    }
}

impl<F: HardwareField> Add for PackedFlat<F> {
    type Output = Self;

    #[inline(always)]
    fn add(self, rhs: Self) -> Self::Output {
        F::add_hardware_packed(self, rhs)
    }
}

impl<F: HardwareField> AddAssign for PackedFlat<F> {
    #[inline(always)]
    fn add_assign(&mut self, rhs: Self) {
        *self = *self + rhs;
    }
}

impl<F: HardwareField> Sub for PackedFlat<F> {
    type Output = Self;

    #[inline(always)]
    fn sub(self, rhs: Self) -> Self::Output {
        F::add_hardware_packed(self, rhs)
    }
}

impl<F: HardwareField> SubAssign for PackedFlat<F> {
    #[inline(always)]
    fn sub_assign(&mut self, rhs: Self) {
        *self = *self - rhs;
    }
}

impl<F: HardwareField> Mul for PackedFlat<F> {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Self) -> Self::Output {
        F::mul_hardware_packed(self, rhs)
    }
}

impl<F: HardwareField> MulAssign for PackedFlat<F> {
    #[inline(always)]
    fn mul_assign(&mut self, rhs: Self) {
        *self = *self * rhs;
    }
}

impl<F: HardwareField> Mul<Flat<F>> for PackedFlat<F> {
    type Output = Self;

    #[inline(always)]
    fn mul(self, rhs: Flat<F>) -> Self::Output {
        F::mul_hardware_scalar_packed(self, rhs)
    }
}

#[inline(always)]
fn flat_slice_as_raw<F>(slice: &[Flat<F>]) -> &[F] {
    unsafe { core::slice::from_raw_parts(slice.as_ptr().cast::<F>(), slice.len()) }
}

#[inline(always)]
fn flat_slice_as_raw_mut<F>(slice: &mut [Flat<F>]) -> &mut [F] {
    unsafe { core::slice::from_raw_parts_mut(slice.as_mut_ptr().cast::<F>(), slice.len()) }
}
