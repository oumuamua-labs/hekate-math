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

#[allow(dead_code, clippy::large_const_arrays)]
mod constants {
    include!(concat!(env!("OUT_DIR"), "/generated_constants.rs"));
}
#[allow(dead_code)]
#[path = "../tower/block8.rs"]
mod block8;
#[allow(dead_code)]
#[path = "../flat/convert.rs"]
mod convert;
#[allow(
    dead_code,
    unused_braces,
    unused_variables,
    clippy::only_used_in_recursion,
    clippy::ptr_arg,
    clippy::too_many_arguments
)]
#[path = "../fft.rs"]
mod fft;
#[cfg(pmull)]
#[allow(dead_code)]
#[path = "../flat/neon_exec.rs"]
mod neon_exec;
mod pins;
#[cfg(pmull)]
mod rows;
mod twins;
