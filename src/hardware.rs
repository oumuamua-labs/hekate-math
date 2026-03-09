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

use crate::packable::PackedFlat;
use crate::{PackableField, TowerField};
use alloc::vec;
use alloc::vec::Vec;
use core::fmt::{self, Debug, Formatter};
use core::ops::{Add, AddAssign, Mul, MulAssign, Sub, SubAssign};
use zeroize::Zeroize;

/// Trait for Hardware Isomorphism acceleration.
pub trait HardwareField: TowerField + PackableField {
    /// Convert standard Tower element
    /// to hardware basis (Isomorphic).
    fn to_hardware(self) -> Flat<Self>;

    /// Convert hardware element back to Tower basis.
    fn from_hardware(value: Flat<Self>) -> Self;

    /// Sum two elements assuming they
    /// are already in hardware basis.
    fn add_hardware(lhs: Flat<Self>, rhs: Flat<Self>) -> Flat<Self>;

    /// Sum packed vectors in hardware basis.
    fn add_hardware_packed(lhs: PackedFlat<Self>, rhs: PackedFlat<Self>) -> PackedFlat<Self>;

    /// Multiply two elements assuming
    /// they are already in hardware basis.
    fn mul_hardware(lhs: Flat<Self>, rhs: Flat<Self>) -> Flat<Self>;

    /// Multiply packed vectors in hardware basis.
    fn mul_hardware_packed(lhs: PackedFlat<Self>, rhs: PackedFlat<Self>) -> PackedFlat<Self>;

    /// Multiply packed vectors by
    /// a scalar in hardware basis.
    #[inline(always)]
    fn mul_hardware_scalar_packed(lhs: PackedFlat<Self>, rhs: Flat<Self>) -> PackedFlat<Self> {
        let mut lhs_values: Vec<Self> = vec![Self::ZERO; <Self as PackableField>::WIDTH];
        let mut result: Vec<Self> = vec![Self::ZERO; <Self as PackableField>::WIDTH];

        let rhs = rhs.into_raw();

        Self::unpack(lhs.into_raw(), &mut lhs_values);

        for i in 0..<Self as PackableField>::WIDTH {
            result[i] =
                Self::mul_hardware(Flat::from_raw(lhs_values[i]), Flat::from_raw(rhs)).into_raw();
        }

        PackedFlat::from_raw(Self::pack(&result))
    }

    /// Extracts the `bit_idx` bit of the
    /// canonical Tower representation
    /// directly from the Hardware (Flat)
    /// representation without a full basis
    /// conversion. Strictly constant time.
    fn tower_bit_from_hardware(value: Flat<Self>, bit_idx: usize) -> u8;
}

/// A field element stored in the hardware / flat basis.
#[derive(Copy, Clone, Default, PartialEq, Eq, Zeroize)]
#[repr(transparent)]
pub struct Flat<F>(F);

impl<F> Flat<F> {
    #[inline(always)]
    pub fn from_raw(raw: F) -> Self {
        Self(raw)
    }

    #[inline(always)]
    pub fn into_raw(self) -> F {
        self.0
    }

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
    #[inline(always)]
    pub fn to_tower(self) -> F {
        F::from_hardware(self)
    }

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

/// Trait to efficiently promote smaller
/// flat-basis fields to a larger flat-basis field
/// bypassing redundant zero-byte lookups.
pub trait FlatPromote<FromF>: HardwareField
where
    FromF: HardwareField,
{
    fn promote_flat(val: Flat<FromF>) -> Flat<Self>;
}

impl<F: HardwareField> FlatPromote<F> for F {
    #[inline(always)]
    fn promote_flat(val: Flat<F>) -> Flat<Self> {
        val
    }
}
