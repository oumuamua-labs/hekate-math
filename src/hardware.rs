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

use crate::{PackableField, TowerField};

/// Trait for Hardware Isomorphism acceleration.
pub trait HardwareField: TowerField + PackableField {
    /// Convert standard Tower element
    /// to hardware basis (Isomorphic).
    fn to_hardware(self) -> Self;

    /// Convert hardware element back to Tower basis.
    fn convert_hardware(self) -> Self;

    /// Sum two elements assuming they
    /// are already in hardware basis.
    fn add_hardware(self, rhs: Self) -> Self;

    /// Sum packed vectors in hardware basis.
    fn add_hardware_packed(lhs: Self::Packed, rhs: Self::Packed) -> Self::Packed;

    /// Multiply two elements assuming
    /// they are already in hardware basis.
    fn mul_hardware(self, rhs: Self) -> Self;

    /// Multiply packed vectors in hardware basis.
    fn mul_hardware_packed(lhs: Self::Packed, rhs: Self::Packed) -> Self::Packed;

    /// Extracts the `bit_idx` bit of the
    /// canonical Tower representation
    /// directly from the Hardware (Flat)
    /// representation without a full basis
    /// conversion. Strictly constant time.
    fn tower_bit_from_hardware(self, bit_idx: usize) -> u8;
}

/// Trait to efficiently promote smaller
/// fields to a larger HardwareField
/// bypassing redundant zero-byte lookups.
pub trait HardwarePromote<FromF>: HardwareField {
    fn from_partial_hardware(val: FromF) -> Self;
}
