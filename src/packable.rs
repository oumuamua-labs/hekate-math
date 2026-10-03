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

//! `PackableField` and `PackedFlat<F>`: `WIDTH` lanes
//! per packed value, flat-basis arithmetic lane by lane.

use crate::{Flat, HardwareField};
use core::fmt;
use core::fmt::{Debug, Formatter};
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};

/// A scalar type with a packed form of `WIDTH` lanes.
pub trait PackableField: Sized + Copy + Clone + Default {
    /// The packed form; operators act lane by lane.
    type Packed: Add<Output = Self::Packed>
        + Sub<Output = Self::Packed>
        + Mul<Output = Self::Packed>
        + Mul<Self, Output = Self::Packed>
        + AddAssign
        + SubAssign
        + MulAssign
        + Copy
        + Clone
        + Default
        + Send;

    /// How many elements fit in one packed vector.
    const WIDTH: usize;

    /// Packs `chunk[..WIDTH]` into one value; ignores the rest.
    ///
    /// # Panics
    /// If `chunk.len() < WIDTH`.
    fn pack(chunk: &[Self]) -> Self::Packed;

    /// Writes the lanes of `packed` to `output[..WIDTH]`;
    /// the rest of `output` is left as it is.
    ///
    /// # Panics
    /// If `output.len() < WIDTH`.
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

/// `F::WIDTH` flat-basis elements of `F` in one packed value;
/// operators act lane by lane.
///
/// # Examples
///
/// ```
/// use hekate_math::{Block32, Flat, HardwareField, PackableField};
///
/// let data: Vec<Flat<Block32>> = (1..=8u32)
///     .map(|i| Block32::from(i).to_hardware())
///     .collect();
///
/// let a = Flat::<Block32>::pack(&data[..4]);
/// let b = Flat::<Block32>::pack(&data[4..]);
///
/// let mut out = [Flat::<Block32>::default(); 4];
/// Flat::<Block32>::unpack(a * b, &mut out);
///
/// for (i, lane) in out.iter().enumerate() {
///     let expected = data[i].to_tower() * data[4 + i].to_tower();
///     assert_eq!(lane.to_tower(), expected);
/// }
/// ```
#[repr(transparent)]
pub struct PackedFlat<F: PackableField>(<F as PackableField>::Packed);

impl<F> PackedFlat<F>
where
    F: PackableField,
{
    /// Wraps `raw` lanes as flat-basis bits; does not convert.
    #[inline(always)]
    pub fn from_raw(raw: F::Packed) -> Self {
        Self(raw)
    }

    /// Returns the packed flat-basis bits; does not convert.
    #[inline(always)]
    pub fn into_raw(self) -> F::Packed {
        self.0
    }

    /// Borrows the packed flat-basis bits; does not convert.
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
    // SAFETY:
    // Flat<F> is #[repr(transparent)] over F: same size and alignment;
    // the result borrows `slice` for its lifetime.
    unsafe { core::slice::from_raw_parts(slice.as_ptr().cast::<F>(), slice.len()) }
}

#[inline(always)]
fn flat_slice_as_raw_mut<F>(slice: &mut [Flat<F>]) -> &mut [F] {
    // SAFETY:
    // Flat<F> is #[repr(transparent)] over F: same size and alignment;
    // the result reborrows `slice` exclusively.
    unsafe { core::slice::from_raw_parts_mut(slice.as_mut_ptr().cast::<F>(), slice.len()) }
}
