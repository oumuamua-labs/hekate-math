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

/// Cantor chain β_0..β_63 in the tower basis. It fixes every
/// AdditiveFft domain point; a changed entry is a protocol break.
/// Block16/32/64 chains are prefixes; Block128 agrees on all 64.
pub const CANTOR_TOWER: [u64; 64] = [
    0x1,
    0xbc,
    0x5c,
    0xc,
    0xae,
    0x5a,
    0xe,
    0x84,
    0x1f6,
    0xbc5c,
    0x5c18,
    0xc7e,
    0xae46,
    0x5a68,
    0xe02,
    0x8456,
    0x1f6fa,
    0xbc5cc4,
    0x5c181e,
    0xc7e5a,
    0xae46a2,
    0x5a686a,
    0xe02fc,
    0x8456e2,
    0x1f6daec,
    0xbc5caed6,
    0x5c186b7c,
    0xc7ec17a,
    0xae46be6c,
    0x5a68df6a,
    0xe02275c,
    0x8456c9c2,
    0x1f6fb3c88,
    0xbc5c78d778,
    0x5c1842197c,
    0xc7e56147e,
    0xae460ccf90,
    0x5a68301b02,
    0xe02f259de,
    0x845666976c,
    0x1f6db1ad40a,
    0xbc5c128ab77c,
    0x5c183764b7ee,
    0xc7ecd04a750,
    0xae46102af8ea,
    0x5a6885024364,
    0xe02295e5b08,
    0x84564d94a196,
    0x1f6faea7394ca,
    0xbc5cc4e1008fce,
    0x5c181e743ef5ae,
    0xc7e5af128cba8,
    0xae46a2959c26da,
    0x5a686ac6328352,
    0xe02fc802c244c,
    0x8456e2ea0ac720,
    0x1f6daecc67c48c8,
    0xbc5caed6ba196f70,
    0x5c186b7cd8a84b90,
    0xc7ec17aa8b29156,
    0xae46be6cec6d431e,
    0x5a68df6adc37b77e,
    0xe02275ce9686a16,
    0x8456c9c2e915c086,
];
