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

//! Twins of the batch promotes `promote_batch_{8,16,32,64}_to_128`
//! (block128.rs): UZP byte deinterleave, per-nibble TBL planes,
//! and the four-phase TRN transpose, over the instruction model.
//! Each output lane is proven to be the bytes of `bit_comb`.

use vstd::prelude::*;

#[path = "convert.rs"]
pub mod convert;

use convert::bridge::gf_model::{bit_comb, bit_comb_additive, pow2, xor, xor_split};
use convert::bridge::neon_model::{
    bytes16, bytes32, bytes64, hi8, lanes16, lanes32, lanes64, lo8, u128_bytes, vand_m8, vdup_m8,
    veor_m8, vqtbl1_m, vshr_m8, vtrn1_m, vtrn2_m, vuzp1_m, vuzp2_m,
};
use convert::bridge::{xor8_reflect, xor16_reflect, xor32_reflect, xor64_reflect};
use convert::u128_shr_div;

verus! {

// ============================================================
// Byte j of a value, and of the XOR of two
// ============================================================

pub open spec fn byte_at(x: nat, j: int) -> nat {
    (x / pow2((8 * j) as nat)) % 256
}

proof fn byte_at_xor(a: nat, b: nat, j: int)
    requires 0 <= j
    ensures byte_at(xor(a, b), j) == xor(byte_at(a, j), byte_at(b, j))
{
    let m = (8 * j) as nat;

    xor_split(m, a, b);
    xor_split(8, a / pow2(m), b / pow2(m));

    assert(pow2(8) == 256) by (compute);
}

proof fn u128_byte(x: u128, j: int)
    requires 0 <= j < 16
    ensures u128_bytes(x)[j] as nat == byte_at(x as nat, j)
{
    let s = (8 * j) as u128;
    let y = x >> s;

    u128_shr_div(x, s);

    assert(u128_bytes(x)[j] == y as u8);
    assert((y as u8) as u128 == y % 256) by (bit_vector);
}

proof fn pair_byte(t0: u8, t1: u8, a: nat, b: nat, j: int)
    requires
        0 <= j,
        t0 as nat == byte_at(a, j),
        t1 as nat == byte_at(b, j),
    ensures (t0 ^ t1) as nat == byte_at(xor(a, b), j)
{
    xor8_reflect(t0, t1);
    byte_at_xor(a, b, j);
}

// ============================================================
// TRN1/TRN2 at element width w, on the byte view
// ============================================================

pub open spec fn trn1_w(a: Seq<u8>, b: Seq<u8>, w: int) -> Seq<u8> {
    Seq::new(16, |i: int| if (i / w) % 2 == 0 { a[i] } else { b[i - w] })
}

pub open spec fn trn2_w(a: Seq<u8>, b: Seq<u8>, w: int) -> Seq<u8> {
    Seq::new(16, |i: int| if (i / w) % 2 == 0 { a[i + w] } else { b[i] })
}

proof fn pack16_byte(v: Seq<u8>, l: int, k: int)
    requires
        0 <= l,
        2 * l + 1 < v.len(),
        0 <= k < 2,
    ensures (lanes16(v)[l] >> ((8 * k) as u16)) as u8 == v[2 * l + k]
{
    let x = lanes16(v)[l];
    let b0 = v[2 * l];
    let b1 = v[2 * l + 1];

    if k == 0 {
        assert((x >> 0u16) as u8 == b0) by (bit_vector)
            requires x == (b0 as u16) | ((b1 as u16) << 8);
    } else {
        assert((x >> 8u16) as u8 == b1) by (bit_vector)
            requires x == (b0 as u16) | ((b1 as u16) << 8);
    }
}

proof fn pack32_byte(v: Seq<u8>, l: int, k: int)
    requires
        0 <= l,
        4 * l + 3 < v.len(),
        0 <= k < 4,
    ensures (lanes32(v)[l] >> ((8 * k) as u32)) as u8 == v[4 * l + k]
{
    let x = lanes32(v)[l];

    let b0 = v[4 * l];
    let b1 = v[4 * l + 1];
    let b2 = v[4 * l + 2];
    let b3 = v[4 * l + 3];

    if k == 0 {
        assert((x >> 0u32) as u8 == b0) by (bit_vector)
            requires x == (b0 as u32) | ((b1 as u32) << 8) | ((b2 as u32) << 16) | ((b3 as u32) << 24);
    } else if k == 1 {
        assert((x >> 8u32) as u8 == b1) by (bit_vector)
            requires x == (b0 as u32) | ((b1 as u32) << 8) | ((b2 as u32) << 16) | ((b3 as u32) << 24);
    } else if k == 2 {
        assert((x >> 16u32) as u8 == b2) by (bit_vector)
            requires x == (b0 as u32) | ((b1 as u32) << 8) | ((b2 as u32) << 16) | ((b3 as u32) << 24);
    } else {
        assert((x >> 24u32) as u8 == b3) by (bit_vector)
            requires x == (b0 as u32) | ((b1 as u32) << 8) | ((b2 as u32) << 16) | ((b3 as u32) << 24);
    }
}

proof fn pack64_byte(v: Seq<u8>, l: int, k: int)
    requires
        0 <= l,
        8 * l + 7 < v.len(),
        0 <= k < 8,
    ensures (lanes64(v)[l] >> ((8 * k) as u64)) as u8 == v[8 * l + k]
{
    let x = lanes64(v)[l];

    let b0 = v[8 * l];
    let b1 = v[8 * l + 1];
    let b2 = v[8 * l + 2];
    let b3 = v[8 * l + 3];
    let b4 = v[8 * l + 4];
    let b5 = v[8 * l + 5];
    let b6 = v[8 * l + 6];
    let b7 = v[8 * l + 7];

    if k == 0 {
        assert((x >> 0u64) as u8 == b0) by (bit_vector)
            requires x == (b0 as u64) | ((b1 as u64) << 8) | ((b2 as u64) << 16) | ((b3 as u64) << 24) | ((b4 as u64) << 32) | ((b5 as u64) << 40) | ((b6 as u64) << 48) | ((b7 as u64) << 56);
    } else if k == 1 {
        assert((x >> 8u64) as u8 == b1) by (bit_vector)
            requires x == (b0 as u64) | ((b1 as u64) << 8) | ((b2 as u64) << 16) | ((b3 as u64) << 24) | ((b4 as u64) << 32) | ((b5 as u64) << 40) | ((b6 as u64) << 48) | ((b7 as u64) << 56);
    } else if k == 2 {
        assert((x >> 16u64) as u8 == b2) by (bit_vector)
            requires x == (b0 as u64) | ((b1 as u64) << 8) | ((b2 as u64) << 16) | ((b3 as u64) << 24) | ((b4 as u64) << 32) | ((b5 as u64) << 40) | ((b6 as u64) << 48) | ((b7 as u64) << 56);
    } else if k == 3 {
        assert((x >> 24u64) as u8 == b3) by (bit_vector)
            requires x == (b0 as u64) | ((b1 as u64) << 8) | ((b2 as u64) << 16) | ((b3 as u64) << 24) | ((b4 as u64) << 32) | ((b5 as u64) << 40) | ((b6 as u64) << 48) | ((b7 as u64) << 56);
    } else if k == 4 {
        assert((x >> 32u64) as u8 == b4) by (bit_vector)
            requires x == (b0 as u64) | ((b1 as u64) << 8) | ((b2 as u64) << 16) | ((b3 as u64) << 24) | ((b4 as u64) << 32) | ((b5 as u64) << 40) | ((b6 as u64) << 48) | ((b7 as u64) << 56);
    } else if k == 5 {
        assert((x >> 40u64) as u8 == b5) by (bit_vector)
            requires x == (b0 as u64) | ((b1 as u64) << 8) | ((b2 as u64) << 16) | ((b3 as u64) << 24) | ((b4 as u64) << 32) | ((b5 as u64) << 40) | ((b6 as u64) << 48) | ((b7 as u64) << 56);
    } else if k == 6 {
        assert((x >> 48u64) as u8 == b6) by (bit_vector)
            requires x == (b0 as u64) | ((b1 as u64) << 8) | ((b2 as u64) << 16) | ((b3 as u64) << 24) | ((b4 as u64) << 32) | ((b5 as u64) << 40) | ((b6 as u64) << 48) | ((b7 as u64) << 56);
    } else {
        assert((x >> 56u64) as u8 == b7) by (bit_vector)
            requires x == (b0 as u64) | ((b1 as u64) << 8) | ((b2 as u64) << 16) | ((b3 as u64) << 24) | ((b4 as u64) << 32) | ((b5 as u64) << 40) | ((b6 as u64) << 48) | ((b7 as u64) << 56);
    }
}

proof fn trn_view_1(a: Seq<u8>, b: Seq<u8>)
    requires
        a.len() == 16,
        b.len() == 16,
    ensures
        vtrn1_m(a, b) == trn1_w(a, b, 1),
        vtrn2_m(a, b) == trn2_w(a, b, 1),
{
    assert(vtrn1_m(a, b) =~= trn1_w(a, b, 1));
    assert(vtrn2_m(a, b) =~= trn2_w(a, b, 1));
}

proof fn trn_view_2(a: Seq<u8>, b: Seq<u8>)
    requires
        a.len() == 16,
        b.len() == 16,
    ensures
        bytes16(vtrn1_m(lanes16(a), lanes16(b))) == trn1_w(a, b, 2),
        bytes16(vtrn2_m(lanes16(a), lanes16(b))) == trn2_w(a, b, 2),
{
    let t1 = vtrn1_m(lanes16(a), lanes16(b));
    let t2 = vtrn2_m(lanes16(a), lanes16(b));

    assert forall|i: int| 0 <= i < 16 implies bytes16(t1)[i] == trn1_w(a, b, 2)[i] && bytes16(t2)[i]
        == trn2_w(a, b, 2)[i] by {
        let l = i / 2;
        let k = i % 2;

        if l % 2 == 0 {
            pack16_byte(a, l, k);
            pack16_byte(a, l + 1, k);
        } else {
            pack16_byte(b, l - 1, k);
            pack16_byte(b, l, k);
        }
    }

    assert(bytes16(t1) =~= trn1_w(a, b, 2));
    assert(bytes16(t2) =~= trn2_w(a, b, 2));
}

proof fn trn_view_4(a: Seq<u8>, b: Seq<u8>)
    requires
        a.len() == 16,
        b.len() == 16,
    ensures
        bytes32(vtrn1_m(lanes32(a), lanes32(b))) == trn1_w(a, b, 4),
        bytes32(vtrn2_m(lanes32(a), lanes32(b))) == trn2_w(a, b, 4),
{
    let t1 = vtrn1_m(lanes32(a), lanes32(b));
    let t2 = vtrn2_m(lanes32(a), lanes32(b));

    assert forall|i: int| 0 <= i < 16 implies bytes32(t1)[i] == trn1_w(a, b, 4)[i] && bytes32(t2)[i]
        == trn2_w(a, b, 4)[i] by {
        let l = i / 4;
        let k = i % 4;

        if l % 2 == 0 {
            pack32_byte(a, l, k);
            pack32_byte(a, l + 1, k);
        } else {
            pack32_byte(b, l - 1, k);
            pack32_byte(b, l, k);
        }
    }

    assert(bytes32(t1) =~= trn1_w(a, b, 4));
    assert(bytes32(t2) =~= trn2_w(a, b, 4));
}

proof fn trn_view_8(a: Seq<u8>, b: Seq<u8>)
    requires
        a.len() == 16,
        b.len() == 16,
    ensures
        bytes64(vtrn1_m(lanes64(a), lanes64(b))) == trn1_w(a, b, 8),
        bytes64(vtrn2_m(lanes64(a), lanes64(b))) == trn2_w(a, b, 8),
{
    let t1 = vtrn1_m(lanes64(a), lanes64(b));
    let t2 = vtrn2_m(lanes64(a), lanes64(b));

    assert forall|i: int| 0 <= i < 16 implies bytes64(t1)[i] == trn1_w(a, b, 8)[i] && bytes64(t2)[i]
        == trn2_w(a, b, 8)[i] by {
        let l = i / 8;
        let k = i % 8;

        if l % 2 == 0 {
            pack64_byte(a, l, k);
            pack64_byte(a, l + 1, k);
        } else {
            pack64_byte(b, l - 1, k);
            pack64_byte(b, l, k);
        }
    }

    assert(bytes64(t1) =~= trn1_w(a, b, 8));
    assert(bytes64(t2) =~= trn2_w(a, b, 8));
}

// ============================================================
// The 16×16 byte transpose: four TRN phases, block size doubling
// ============================================================

pub open spec fn rows16(a: Seq<Seq<u8>>) -> bool {
    a.len() == 16 && forall|j: int| 0 <= j < 16 ==> (#[trigger] a[j]).len() == 16
}

pub open spec fn phase(a: Seq<Seq<u8>>, s: int) -> Seq<Seq<u8>> {
    Seq::new(
        16,
        |j: int| if (j / s) % 2 == 0 { trn1_w(a[j], a[j + s], s) } else { trn2_w(a[j - s], a[j], s) },
    )
}

pub open spec fn blocked(out: Seq<Seq<u8>>, r: Seq<Seq<u8>>, s: int) -> bool {
    forall|j: int, i: int| 0 <= j < 16 && 0 <= i < 16
        ==> #[trigger] out[j][i] == r[(j / s) * s + i % s][(i / s) * s + j % s]
}

proof fn phase_step_1(r: Seq<Seq<u8>>, a: Seq<Seq<u8>>)
    requires
        rows16(r),
        rows16(a),
        blocked(a, r, 1),
    ensures
        rows16(phase(a, 1)),
        blocked(phase(a, 1), r, 2),
{
    let out = phase(a, 1);

    assert forall|j: int, i: int| 0 <= j < 16 && 0 <= i < 16 implies #[trigger] out[j][i] == r[(j
        / 2) * 2 + i % 2][(i / 2) * 2 + j % 2] by {
        if j % 2 == 0 {
            if i % 2 == 0 {
                assert(out[j][i] == a[j][i]);
            } else {
                assert(out[j][i] == a[j + 1][i - 1]);
            }
        } else {
            if i % 2 == 0 {
                assert(out[j][i] == a[j - 1][i + 1]);
            } else {
                assert(out[j][i] == a[j][i]);
            }
        }
    }
}

proof fn phase_step_2(r: Seq<Seq<u8>>, a: Seq<Seq<u8>>)
    requires
        rows16(r),
        rows16(a),
        blocked(a, r, 2),
    ensures
        rows16(phase(a, 2)),
        blocked(phase(a, 2), r, 4),
{
    let out = phase(a, 2);

    assert forall|j: int, i: int| 0 <= j < 16 && 0 <= i < 16 implies #[trigger] out[j][i] == r[(j
        / 4) * 4 + i % 4][(i / 4) * 4 + j % 4] by {
        if (j / 2) % 2 == 0 {
            if (i / 2) % 2 == 0 {
                assert(out[j][i] == a[j][i]);
            } else {
                assert(out[j][i] == a[j + 2][i - 2]);
            }
        } else {
            if (i / 2) % 2 == 0 {
                assert(out[j][i] == a[j - 2][i + 2]);
            } else {
                assert(out[j][i] == a[j][i]);
            }
        }
    }
}

proof fn phase_step_4(r: Seq<Seq<u8>>, a: Seq<Seq<u8>>)
    requires
        rows16(r),
        rows16(a),
        blocked(a, r, 4),
    ensures
        rows16(phase(a, 4)),
        blocked(phase(a, 4), r, 8),
{
    let out = phase(a, 4);

    assert forall|j: int, i: int| 0 <= j < 16 && 0 <= i < 16 implies #[trigger] out[j][i] == r[(j
        / 8) * 8 + i % 8][(i / 8) * 8 + j % 8] by {
        if (j / 4) % 2 == 0 {
            if (i / 4) % 2 == 0 {
                assert(out[j][i] == a[j][i]);
            } else {
                assert(out[j][i] == a[j + 4][i - 4]);
            }
        } else {
            if (i / 4) % 2 == 0 {
                assert(out[j][i] == a[j - 4][i + 4]);
            } else {
                assert(out[j][i] == a[j][i]);
            }
        }
    }
}

proof fn phase_step_8(r: Seq<Seq<u8>>, a: Seq<Seq<u8>>)
    requires
        rows16(r),
        rows16(a),
        blocked(a, r, 8),
    ensures
        rows16(phase(a, 8)),
        blocked(phase(a, 8), r, 16),
{
    let out = phase(a, 8);

    assert forall|j: int, i: int| 0 <= j < 16 && 0 <= i < 16 implies #[trigger] out[j][i] == r[(j
        / 16) * 16 + i % 16][(i / 16) * 16 + j % 16] by {
        if (j / 8) % 2 == 0 {
            if (i / 8) % 2 == 0 {
                assert(out[j][i] == a[j][i]);
            } else {
                assert(out[j][i] == a[j + 8][i - 8]);
            }
        } else {
            if (i / 8) % 2 == 0 {
                assert(out[j][i] == a[j - 8][i + 8]);
            } else {
                assert(out[j][i] == a[j][i]);
            }
        }
    }
}

// ============================================================
// transpose_16x16, block128.rs: the model phases
// ============================================================

pub open spec fn phase1_m(r: Seq<Seq<u8>>) -> Seq<Seq<u8>> {
    Seq::new(
        16,
        |j: int| if j % 2 == 0 { vtrn1_m(r[j], r[j + 1]) } else { vtrn2_m(r[j - 1], r[j]) },
    )
}

pub open spec fn phase2_m(a: Seq<Seq<u8>>) -> Seq<Seq<u8>> {
    Seq::new(
        16,
        |j: int|
            if (j / 2) % 2 == 0 {
                bytes16(vtrn1_m(lanes16(a[j]), lanes16(a[j + 2])))
            } else {
                bytes16(vtrn2_m(lanes16(a[j - 2]), lanes16(a[j])))
            },
    )
}

pub open spec fn phase4_m(b: Seq<Seq<u8>>) -> Seq<Seq<u8>> {
    Seq::new(
        16,
        |j: int|
            if (j / 4) % 2 == 0 {
                bytes32(vtrn1_m(lanes32(b[j]), lanes32(b[j + 4])))
            } else {
                bytes32(vtrn2_m(lanes32(b[j - 4]), lanes32(b[j])))
            },
    )
}

pub open spec fn phase8_m(c: Seq<Seq<u8>>) -> Seq<Seq<u8>> {
    Seq::new(
        16,
        |j: int|
            if (j / 8) % 2 == 0 {
                bytes64(vtrn1_m(lanes64(c[j]), lanes64(c[j + 8])))
            } else {
                bytes64(vtrn2_m(lanes64(c[j - 8]), lanes64(c[j])))
            },
    )
}

pub open spec fn transpose_16x16_twin(r: Seq<Seq<u8>>) -> Seq<Seq<u8>> {
    phase8_m(phase4_m(phase2_m(phase1_m(r))))
}

proof fn phase1_is(r: Seq<Seq<u8>>)
    requires rows16(r)
    ensures phase1_m(r) == phase(r, 1)
{
    assert forall|j: int| 0 <= j < 16 implies phase1_m(r)[j] == phase(r, 1)[j] by {
        if j % 2 == 0 {
            trn_view_1(r[j], r[j + 1]);
        } else {
            trn_view_1(r[j - 1], r[j]);
        }
    }

    assert(phase1_m(r) =~= phase(r, 1));
}

proof fn phase2_is(a: Seq<Seq<u8>>)
    requires rows16(a)
    ensures phase2_m(a) == phase(a, 2)
{
    assert forall|j: int| 0 <= j < 16 implies phase2_m(a)[j] == phase(a, 2)[j] by {
        if (j / 2) % 2 == 0 {
            trn_view_2(a[j], a[j + 2]);
        } else {
            trn_view_2(a[j - 2], a[j]);
        }
    }

    assert(phase2_m(a) =~= phase(a, 2));
}

proof fn phase4_is(b: Seq<Seq<u8>>)
    requires rows16(b)
    ensures phase4_m(b) == phase(b, 4)
{
    assert forall|j: int| 0 <= j < 16 implies phase4_m(b)[j] == phase(b, 4)[j] by {
        if (j / 4) % 2 == 0 {
            trn_view_4(b[j], b[j + 4]);
        } else {
            trn_view_4(b[j - 4], b[j]);
        }
    }

    assert(phase4_m(b) =~= phase(b, 4));
}

proof fn phase8_is(c: Seq<Seq<u8>>)
    requires rows16(c)
    ensures phase8_m(c) == phase(c, 8)
{
    assert forall|j: int| 0 <= j < 16 implies phase8_m(c)[j] == phase(c, 8)[j] by {
        if (j / 8) % 2 == 0 {
            trn_view_8(c[j], c[j + 8]);
        } else {
            trn_view_8(c[j - 8], c[j]);
        }
    }

    assert(phase8_m(c) =~= phase(c, 8));
}

pub proof fn transpose_correct(r: Seq<Seq<u8>>)
    requires rows16(r)
    ensures
        rows16(transpose_16x16_twin(r)),
        forall|j: int, i: int| 0 <= j < 16 && 0 <= i < 16
            ==> #[trigger] transpose_16x16_twin(r)[j][i] == r[i][j],
{
    hide(phase);
    hide(phase1_m);
    hide(phase2_m);
    hide(phase4_m);
    hide(phase8_m);

    let a = phase(r, 1);
    let b = phase(a, 2);
    let c = phase(b, 4);
    let d = phase(c, 8);

    assert(blocked(r, r, 1)) by {
        assert forall|j: int, i: int| 0 <= j < 16 && 0 <= i < 16 implies #[trigger] r[j][i] == r[(j
            / 1) * 1 + i % 1][(i / 1) * 1 + j % 1] by {
        }
    }

    phase_step_1(r, r);
    phase_step_2(r, a);
    phase_step_4(r, b);
    phase_step_8(r, c);

    phase1_is(r);
    phase2_is(a);
    phase4_is(b);
    phase8_is(c);

    assert(transpose_16x16_twin(r) == d);

    assert forall|j: int, i: int| 0 <= j < 16 && 0 <= i < 16 implies #[trigger] d[j][i] == r[i][j] by {
        assert(d[j][i] == r[(j / 16) * 16 + i % 16][(i / 16) * 16 + j % 16]);
    }
}

// ============================================================
// Nibble tables: NIBBLE_PROMOTE_{N}_{p}_TO_128[j][v] is byte
// j of the lift of nibble v at position p (build/main.rs).
// ============================================================

pub open spec fn nibble_tables(tbl: Seq<Seq<Seq<u8>>>, basis: Seq<nat>, n: nat, planes: int) -> bool {
    &&& tbl.len() == planes
    &&& forall|p: int, j: int| 0 <= p < planes && 0 <= j < 16 ==> (#[trigger] tbl[p][j]).len() == 16
    &&& forall|p: int, j: int, v: int|
        0 <= p < planes && 0 <= j < 16 && 0 <= v < 16 ==> (#[trigger] tbl[p][j][v]) as nat == byte_at(
            bit_comb((v as nat) * pow2((4 * p) as nat), basis, n),
            j,
        )
}

pub open spec fn lo_nib(v: Seq<u8>) -> Seq<u8> {
    vand_m8(v, vdup_m8(0x0F, 16))
}

pub open spec fn hi_nib(v: Seq<u8>) -> Seq<u8> {
    vshr_m8(v, 4)
}

// ============================================================
// promote_batch_8_to_128, block128.rs
// ============================================================

pub open spec fn planes_8(tbl: Seq<Seq<Seq<u8>>>, vals: Seq<u8>) -> Seq<Seq<u8>> {
    Seq::new(
        16,
        |j: int| veor_m8(vqtbl1_m(tbl[0][j], lo_nib(vals)), vqtbl1_m(tbl[1][j], hi_nib(vals))),
    )
}

pub open spec fn promote_batch_8_twin(tbl: Seq<Seq<Seq<u8>>>, vals: Seq<u8>) -> Seq<Seq<u8>> {
    transpose_16x16_twin(planes_8(tbl, vals))
}

proof fn plane_8_lane(tbl: Seq<Seq<Seq<u8>>>, basis: Seq<nat>, vals: Seq<u8>, l: int, j: int)
    requires
        vals.len() == 16,
        nibble_tables(tbl, basis, 8, 2),
        0 <= l < 16,
        0 <= j < 16,
    ensures planes_8(tbl, vals)[j][l] as nat == byte_at(bit_comb(vals[l] as nat, basis, 8), j)
{
    let v = vals[l];
    let lo = v & 0x0F;
    let hi = v >> 4;
    let hi_sh = (v >> 4) << 4;

    assert(lo < 16 && hi < 16 && (lo ^ hi_sh) == v && hi_sh == 16 * hi) by (bit_vector)
        requires
            lo == v & 0x0F,
            hi == v >> 4,
            hi_sh == (v >> 4) << 4,
    ;

    let t0 = tbl[0][j][lo as int];
    let t1 = tbl[1][j][hi as int];

    assert(planes_8(tbl, vals)[j][l] == t0 ^ t1);

    let p0 = pow2((4 * 0) as nat);
    let p1 = pow2((4 * 1) as nat);

    assert(pow2((4 * 0) as nat) == 1 && pow2((4 * 1) as nat) == 16) by (compute);
    assert((lo as nat) * p0 == lo as nat && (hi as nat) * p1 == (hi as nat) * 16)
        by (nonlinear_arith)
        requires p0 == 1, p1 == 16;

    let a = bit_comb(lo as nat, basis, 8);
    let b = bit_comb((hi as nat) * 16, basis, 8);

    assert(t0 as nat == byte_at(bit_comb((lo as nat) * p0, basis, 8), j));
    assert(t1 as nat == byte_at(bit_comb((hi as nat) * p1, basis, 8), j));

    pair_byte(t0, t1, a, b, j);
    bit_comb_additive(lo as nat, (hi as nat) * 16, basis, 8);
    xor8_reflect(lo, hi_sh);
}

pub proof fn promote_batch_8_correct(tbl: Seq<Seq<Seq<u8>>>, basis: Seq<nat>, vals: Seq<u8>)
    requires
        vals.len() == 16,
        nibble_tables(tbl, basis, 8, 2),
    ensures
        rows16(promote_batch_8_twin(tbl, vals)),
        forall|l: int, j: int| 0 <= l < 16 && 0 <= j < 16
            ==> (#[trigger] promote_batch_8_twin(tbl, vals)[l][j]) as nat == byte_at(
                bit_comb(vals[l] as nat, basis, 8),
                j,
            ),
{
    let planes = planes_8(tbl, vals);

    assert(rows16(planes));
    transpose_correct(planes);

    assert forall|l: int, j: int| 0 <= l < 16 && 0 <= j < 16 implies (#[trigger] promote_batch_8_twin(
        tbl,
        vals,
    )[l][j]) as nat == byte_at(bit_comb(vals[l] as nat, basis, 8), j) by {
        plane_8_lane(tbl, basis, vals, l, j);
    }
}

pub proof fn promote_batch_8_lane(
    tbl: Seq<Seq<Seq<u8>>>,
    basis: Seq<nat>,
    vals: Seq<u8>,
    l: int,
    x: u128,
)
    requires
        vals.len() == 16,
        nibble_tables(tbl, basis, 8, 2),
        0 <= l < 16,
        x as nat == bit_comb(vals[l] as nat, basis, 8),
    ensures promote_batch_8_twin(tbl, vals)[l] == u128_bytes(x)
{
    promote_batch_8_correct(tbl, basis, vals);

    assert forall|j: int| 0 <= j < 16 implies promote_batch_8_twin(tbl, vals)[l][j] == u128_bytes(
        x,
    )[j] by {
        u128_byte(x, j);
    }

    assert(promote_batch_8_twin(tbl, vals)[l] =~= u128_bytes(x));
}

// ============================================================
// promote_batch_16_to_128, block128.rs: UZP splits the
// lanes into their low and high bytes, four nibble planes.
// ============================================================

pub open spec fn lo_bytes_16(vals: Seq<u16>) -> Seq<u8> {
    vuzp1_m(bytes16(vals.subrange(0, 8)), bytes16(vals.subrange(8, 16)))
}

pub open spec fn hi_bytes_16(vals: Seq<u16>) -> Seq<u8> {
    vuzp2_m(bytes16(vals.subrange(0, 8)), bytes16(vals.subrange(8, 16)))
}

proof fn uzp_16(vals: Seq<u16>)
    requires vals.len() == 16
    ensures
        lo_bytes_16(vals).len() == 16,
        hi_bytes_16(vals).len() == 16,
        forall|l: int| 0 <= l < 16 ==> #[trigger] lo_bytes_16(vals)[l] == lo8(vals[l]),
        forall|l: int| 0 <= l < 16 ==> #[trigger] hi_bytes_16(vals)[l] == hi8(vals[l]),
{
    let r0 = bytes16(vals.subrange(0, 8));
    let r1 = bytes16(vals.subrange(8, 16));

    assert forall|l: int| 0 <= l < 16 implies #[trigger] lo_bytes_16(vals)[l] == lo8(vals[l]) by {
        let v = vals[l];

        assert(v >> 0u16 == v) by (bit_vector);

        if l < 8 {
            assert(r0[2 * l] == (v >> ((8 * ((2 * l) % 2)) as u16)) as u8);
        } else {
            assert(r1[2 * l - 16] == (v >> ((8 * ((2 * l - 16) % 2)) as u16)) as u8);
        }
    }

    assert forall|l: int| 0 <= l < 16 implies #[trigger] hi_bytes_16(vals)[l] == hi8(vals[l]) by {
        let v = vals[l];

        if l < 8 {
            assert(r0[2 * l + 1] == (v >> ((8 * ((2 * l + 1) % 2)) as u16)) as u8);
        } else {
            assert(r1[2 * l - 15] == (v >> ((8 * ((2 * l - 15) % 2)) as u16)) as u8);
        }
    }
}

pub open spec fn planes_16(tbl: Seq<Seq<Seq<u8>>>, vals: Seq<u16>) -> Seq<Seq<u8>> {
    let lo = lo_bytes_16(vals);
    let hi = hi_bytes_16(vals);

    Seq::new(
        16,
        |j: int|
            veor_m8(
                veor_m8(vqtbl1_m(tbl[0][j], lo_nib(lo)), vqtbl1_m(tbl[1][j], hi_nib(lo))),
                veor_m8(vqtbl1_m(tbl[2][j], lo_nib(hi)), vqtbl1_m(tbl[3][j], hi_nib(hi))),
            ),
    )
}

pub open spec fn promote_batch_16_twin(tbl: Seq<Seq<Seq<u8>>>, vals: Seq<u16>) -> Seq<Seq<u8>> {
    transpose_16x16_twin(planes_16(tbl, vals))
}

proof fn plane_16_lane(tbl: Seq<Seq<Seq<u8>>>, basis: Seq<nat>, vals: Seq<u16>, l: int, j: int)
    requires
        vals.len() == 16,
        nibble_tables(tbl, basis, 16, 4),
        0 <= l < 16,
        0 <= j < 16,
    ensures planes_16(tbl, vals)[j][l] as nat == byte_at(bit_comb(vals[l] as nat, basis, 16), j)
{
    uzp_16(vals);

    let v = vals[l];

    let b0 = lo8(v);
    let b1 = hi8(v);

    let n0 = b0 & 0x0F;
    let n1 = b0 >> 4;
    let n2 = b1 & 0x0F;
    let n3 = b1 >> 4;

    let m0 = n0 as u16;
    let m1 = (n1 as u16) << 4;
    let m2 = (n2 as u16) << 8;
    let m3 = (n3 as u16) << 12;

    assert(n0 < 16 && n1 < 16 && n2 < 16 && n3 < 16 && m1 == 16 * (n1 as u16) && m2 == 256 * (n2
        as u16) && m3 == 4096 * (n3 as u16) && v == (m0 ^ m1) ^ (m2 ^ m3)) by (bit_vector)
        requires
            b0 == v as u8,
            b1 == (v >> 8) as u8,
            n0 == b0 & 0x0F,
            n1 == b0 >> 4,
            n2 == b1 & 0x0F,
            n3 == b1 >> 4,
            m0 == n0 as u16,
            m1 == (n1 as u16) << 4,
            m2 == (n2 as u16) << 8,
            m3 == (n3 as u16) << 12,
    ;

    let t0 = tbl[0][j][n0 as int];
    let t1 = tbl[1][j][n1 as int];
    let t2 = tbl[2][j][n2 as int];
    let t3 = tbl[3][j][n3 as int];

    assert(planes_16(tbl, vals)[j][l] == (t0 ^ t1) ^ (t2 ^ t3));

    let p0 = pow2((4 * 0) as nat);
    let p1 = pow2((4 * 1) as nat);
    let p2 = pow2((4 * 2) as nat);
    let p3 = pow2((4 * 3) as nat);

    assert(pow2((4 * 0) as nat) == 1 && pow2((4 * 1) as nat) == 16 && pow2((4 * 2) as nat) == 256
        && pow2((4 * 3) as nat) == 4096) by (compute);

    let x0 = (n0 as nat) * p0;
    let x1 = (n1 as nat) * p1;
    let x2 = (n2 as nat) * p2;
    let x3 = (n3 as nat) * p3;

    assert(x0 == m0 as nat && x1 == m1 as nat && x2 == m2 as nat && x3 == m3 as nat)
        by (nonlinear_arith)
        requires
            p0 == 1,
            p1 == 16,
            p2 == 256,
            p3 == 4096,
            x0 == (n0 as nat) * p0,
            x1 == (n1 as nat) * p1,
            x2 == (n2 as nat) * p2,
            x3 == (n3 as nat) * p3,
            m0 as nat == n0 as nat,
            m1 as nat == 16 * (n1 as nat),
            m2 as nat == 256 * (n2 as nat),
            m3 as nat == 4096 * (n3 as nat),
    ;

    let a0 = bit_comb(x0, basis, 16);
    let a1 = bit_comb(x1, basis, 16);
    let a2 = bit_comb(x2, basis, 16);
    let a3 = bit_comb(x3, basis, 16);

    assert(t0 as nat == byte_at(a0, j));
    assert(t1 as nat == byte_at(a1, j));
    assert(t2 as nat == byte_at(a2, j));
    assert(t3 as nat == byte_at(a3, j));

    pair_byte(t0, t1, a0, a1, j);
    pair_byte(t2, t3, a2, a3, j);
    pair_byte(t0 ^ t1, t2 ^ t3, xor(a0, a1), xor(a2, a3), j);

    bit_comb_additive(x0, x1, basis, 16);
    bit_comb_additive(x2, x3, basis, 16);
    bit_comb_additive(xor(x0, x1), xor(x2, x3), basis, 16);

    xor16_reflect(m0, m1);
    xor16_reflect(m2, m3);
    xor16_reflect(m0 ^ m1, m2 ^ m3);
}

pub proof fn promote_batch_16_correct(tbl: Seq<Seq<Seq<u8>>>, basis: Seq<nat>, vals: Seq<u16>)
    requires
        vals.len() == 16,
        nibble_tables(tbl, basis, 16, 4),
    ensures
        rows16(promote_batch_16_twin(tbl, vals)),
        forall|l: int, j: int| 0 <= l < 16 && 0 <= j < 16
            ==> (#[trigger] promote_batch_16_twin(tbl, vals)[l][j]) as nat == byte_at(
                bit_comb(vals[l] as nat, basis, 16),
                j,
            ),
{
    let planes = planes_16(tbl, vals);

    uzp_16(vals);
    assert(rows16(planes));
    transpose_correct(planes);

    assert forall|l: int, j: int| 0 <= l < 16 && 0 <= j < 16 implies (
    #[trigger] promote_batch_16_twin(tbl, vals)[l][j]) as nat == byte_at(
        bit_comb(vals[l] as nat, basis, 16),
        j,
    ) by {
        plane_16_lane(tbl, basis, vals, l, j);
    }
}

pub proof fn promote_batch_16_lane(
    tbl: Seq<Seq<Seq<u8>>>,
    basis: Seq<nat>,
    vals: Seq<u16>,
    l: int,
    x: u128,
)
    requires
        vals.len() == 16,
        nibble_tables(tbl, basis, 16, 4),
        0 <= l < 16,
        x as nat == bit_comb(vals[l] as nat, basis, 16),
    ensures promote_batch_16_twin(tbl, vals)[l] == u128_bytes(x)
{
    promote_batch_16_correct(tbl, basis, vals);

    assert forall|j: int| 0 <= j < 16 implies promote_batch_16_twin(tbl, vals)[l][j] == u128_bytes(
        x,
    )[j] by {
        u128_byte(x, j);
    }

    assert(promote_batch_16_twin(tbl, vals)[l] =~= u128_bytes(x));
}

// ============================================================
// promote_batch_32_to_128, block128.rs: two UZP stages
// split the lanes into their four bytes, eight nibble planes.
// ============================================================

pub open spec fn raw_32(vals: Seq<u32>, k: int) -> Seq<u8> {
    bytes32(vals.subrange(4 * k, 4 * k + 4))
}

pub open spec fn byte_plane_32(vals: Seq<u32>, k: int) -> Seq<u8> {
    let a02 = vuzp1_m(raw_32(vals, 0), raw_32(vals, 1));
    let a13 = vuzp2_m(raw_32(vals, 0), raw_32(vals, 1));
    let b02 = vuzp1_m(raw_32(vals, 2), raw_32(vals, 3));
    let b13 = vuzp2_m(raw_32(vals, 2), raw_32(vals, 3));

    if k == 0 {
        vuzp1_m(a02, b02)
    } else if k == 1 {
        vuzp1_m(a13, b13)
    } else if k == 2 {
        vuzp2_m(a02, b02)
    } else {
        vuzp2_m(a13, b13)
    }
}

proof fn uzp_32_stage1(vals: Seq<u32>, k: int)
    requires
        vals.len() == 16,
        k == 0 || k == 2,
    ensures
        vuzp1_m(raw_32(vals, k), raw_32(vals, k + 1)).len() == 16,
        vuzp2_m(raw_32(vals, k), raw_32(vals, k + 1)).len() == 16,
        forall|i: int| 0 <= i < 16 ==> #[trigger] vuzp1_m(raw_32(vals, k), raw_32(vals, k + 1))[i]
            == (vals[4 * k + i / 2] >> ((8 * (2 * (i % 2))) as u32)) as u8,
        forall|i: int| 0 <= i < 16 ==> #[trigger] vuzp2_m(raw_32(vals, k), raw_32(vals, k + 1))[i]
            == (vals[4 * k + i / 2] >> ((8 * (2 * (i % 2) + 1)) as u32)) as u8,
{
    let r0 = raw_32(vals, k);
    let r1 = raw_32(vals, k + 1);

    assert forall|i: int| 0 <= i < 16 implies #[trigger] vuzp1_m(r0, r1)[i] == (vals[4 * k + i / 2]
        >> ((8 * (2 * (i % 2))) as u32)) as u8 by {
        if i < 8 {
            assert(r0[2 * i] == (vals[4 * k + (2 * i) / 4] >> ((8 * ((2 * i) % 4)) as u32)) as u8);
        } else {
            assert(r1[2 * i - 16] == (vals[4 * (k + 1) + (2 * i - 16) / 4] >> ((8 * ((2 * i - 16)
                % 4)) as u32)) as u8);
        }
    }

    assert forall|i: int| 0 <= i < 16 implies #[trigger] vuzp2_m(r0, r1)[i] == (vals[4 * k + i / 2]
        >> ((8 * (2 * (i % 2) + 1)) as u32)) as u8 by {
        if i < 8 {
            assert(r0[2 * i + 1] == (vals[4 * k + (2 * i + 1) / 4] >> ((8 * ((2 * i + 1) % 4))
                as u32)) as u8);
        } else {
            assert(r1[2 * i - 15] == (vals[4 * (k + 1) + (2 * i - 15) / 4] >> ((8 * ((2 * i - 15)
                % 4)) as u32)) as u8);
        }
    }
}

proof fn uzp_32(vals: Seq<u32>)
    requires vals.len() == 16
    ensures
        forall|k: int| 0 <= k < 4 ==> (#[trigger] byte_plane_32(vals, k)).len() == 16,
        forall|k: int, l: int| 0 <= k < 4 && 0 <= l < 16
            ==> #[trigger] byte_plane_32(vals, k)[l] == (vals[l] >> ((8 * k) as u32)) as u8,
{
    uzp_32_stage1(vals, 0);
    uzp_32_stage1(vals, 2);

    let a02 = vuzp1_m(raw_32(vals, 0), raw_32(vals, 1));
    let a13 = vuzp2_m(raw_32(vals, 0), raw_32(vals, 1));
    let b02 = vuzp1_m(raw_32(vals, 2), raw_32(vals, 3));
    let b13 = vuzp2_m(raw_32(vals, 2), raw_32(vals, 3));

    assert forall|k: int, l: int| 0 <= k < 4 && 0 <= l < 16 implies #[trigger] byte_plane_32(vals, k)[l]
        == (vals[l] >> ((8 * k) as u32)) as u8 by {
        if l < 8 {
            assert(a02[2 * l] == (vals[l] >> ((8 * (2 * ((2 * l) % 2))) as u32)) as u8);
            assert(a02[2 * l + 1] == (vals[l] >> ((8 * (2 * ((2 * l + 1) % 2))) as u32)) as u8);
            assert(a13[2 * l] == (vals[l] >> ((8 * (2 * ((2 * l) % 2) + 1)) as u32)) as u8);
            assert(a13[2 * l + 1] == (vals[l] >> ((8 * (2 * ((2 * l + 1) % 2) + 1)) as u32)) as u8);
        } else {
            assert(b02[2 * l - 16] == (vals[l] >> ((8 * (2 * ((2 * l - 16) % 2))) as u32)) as u8);
            assert(b02[2 * l - 15] == (vals[l] >> ((8 * (2 * ((2 * l - 15) % 2))) as u32)) as u8);
            assert(b13[2 * l - 16] == (vals[l] >> ((8 * (2 * ((2 * l - 16) % 2) + 1)) as u32)) as u8);
            assert(b13[2 * l - 15] == (vals[l] >> ((8 * (2 * ((2 * l - 15) % 2) + 1)) as u32)) as u8);
        }
    }
}

pub open spec fn nib_32(vals: Seq<u32>, p: int) -> Seq<u8> {
    if p % 2 == 0 {
        lo_nib(byte_plane_32(vals, p / 2))
    } else {
        hi_nib(byte_plane_32(vals, p / 2))
    }
}

pub open spec fn planes_32(tbl: Seq<Seq<Seq<u8>>>, vals: Seq<u32>) -> Seq<Seq<u8>> {
    Seq::new(
        16,
        |j: int|
            veor_m8(
                veor_m8(
                    veor_m8(vqtbl1_m(tbl[0][j], nib_32(vals, 0)), vqtbl1_m(tbl[1][j], nib_32(vals, 1))),
                    veor_m8(vqtbl1_m(tbl[2][j], nib_32(vals, 2)), vqtbl1_m(tbl[3][j], nib_32(vals, 3))),
                ),
                veor_m8(
                    veor_m8(vqtbl1_m(tbl[4][j], nib_32(vals, 4)), vqtbl1_m(tbl[5][j], nib_32(vals, 5))),
                    veor_m8(vqtbl1_m(tbl[6][j], nib_32(vals, 6)), vqtbl1_m(tbl[7][j], nib_32(vals, 7))),
                ),
            ),
    )
}

pub open spec fn promote_batch_32_twin(tbl: Seq<Seq<Seq<u8>>>, vals: Seq<u32>) -> Seq<Seq<u8>> {
    transpose_16x16_twin(planes_32(tbl, vals))
}

proof fn plane_32_lane(tbl: Seq<Seq<Seq<u8>>>, basis: Seq<nat>, vals: Seq<u32>, l: int, j: int)
    requires
        vals.len() == 16,
        nibble_tables(tbl, basis, 32, 8),
        0 <= l < 16,
        0 <= j < 16,
    ensures planes_32(tbl, vals)[j][l] as nat == byte_at(bit_comb(vals[l] as nat, basis, 32), j)
{
    uzp_32(vals);

    let v = vals[l];

    let b0 = (v >> 0u32) as u8;
    let b1 = (v >> 8u32) as u8;
    let b2 = (v >> 16u32) as u8;
    let b3 = (v >> 24u32) as u8;

    let n0 = b0 & 0x0F;
    let n1 = b0 >> 4;
    let n2 = b1 & 0x0F;
    let n3 = b1 >> 4;
    let n4 = b2 & 0x0F;
    let n5 = b2 >> 4;
    let n6 = b3 & 0x0F;
    let n7 = b3 >> 4;

    let m0 = n0 as u32;
    let m1 = (n1 as u32) << 4;
    let m2 = (n2 as u32) << 8;
    let m3 = (n3 as u32) << 12;
    let m4 = (n4 as u32) << 16;
    let m5 = (n5 as u32) << 20;
    let m6 = (n6 as u32) << 24;
    let m7 = (n7 as u32) << 28;

    assert(n0 < 16 && n1 < 16 && n2 < 16 && n3 < 16 && n4 < 16 && n5 < 16 && n6 < 16 && n7 < 16
        && m1 == 16 * (n1 as u32) && m2 == 256 * (n2 as u32) && m3 == 4096 * (n3 as u32) && m4
        == 65536 * (n4 as u32) && m5 == 1048576 * (n5 as u32) && m6 == 16777216 * (n6 as u32) && m7
        == 268435456 * (n7 as u32) && v == ((m0 ^ m1) ^ (m2 ^ m3)) ^ ((m4 ^ m5) ^ (m6 ^ m7)))
        by (bit_vector)
        requires
            b0 == (v >> 0u32) as u8,
            b1 == (v >> 8u32) as u8,
            b2 == (v >> 16u32) as u8,
            b3 == (v >> 24u32) as u8,
            n0 == b0 & 0x0F,
            n1 == b0 >> 4,
            n2 == b1 & 0x0F,
            n3 == b1 >> 4,
            n4 == b2 & 0x0F,
            n5 == b2 >> 4,
            n6 == b3 & 0x0F,
            n7 == b3 >> 4,
            m0 == n0 as u32,
            m1 == (n1 as u32) << 4,
            m2 == (n2 as u32) << 8,
            m3 == (n3 as u32) << 12,
            m4 == (n4 as u32) << 16,
            m5 == (n5 as u32) << 20,
            m6 == (n6 as u32) << 24,
            m7 == (n7 as u32) << 28,
    ;

    assert(byte_plane_32(vals, 0)[l] == b0);
    assert(byte_plane_32(vals, 1)[l] == b1);
    assert(byte_plane_32(vals, 2)[l] == b2);
    assert(byte_plane_32(vals, 3)[l] == b3);

    let t0 = tbl[0][j][n0 as int];
    let t1 = tbl[1][j][n1 as int];
    let t2 = tbl[2][j][n2 as int];
    let t3 = tbl[3][j][n3 as int];
    let t4 = tbl[4][j][n4 as int];
    let t5 = tbl[5][j][n5 as int];
    let t6 = tbl[6][j][n6 as int];
    let t7 = tbl[7][j][n7 as int];

    assert(planes_32(tbl, vals)[j][l] == ((t0 ^ t1) ^ (t2 ^ t3)) ^ ((t4 ^ t5) ^ (t6 ^ t7)));

    let p0 = pow2((4 * 0) as nat);
    let p1 = pow2((4 * 1) as nat);
    let p2 = pow2((4 * 2) as nat);
    let p3 = pow2((4 * 3) as nat);
    let p4 = pow2((4 * 4) as nat);
    let p5 = pow2((4 * 5) as nat);
    let p6 = pow2((4 * 6) as nat);
    let p7 = pow2((4 * 7) as nat);

    assert(pow2((4 * 0) as nat) == 1 && pow2((4 * 1) as nat) == 16 && pow2((4 * 2) as nat) == 256
        && pow2((4 * 3) as nat) == 4096 && pow2((4 * 4) as nat) == 65536 && pow2((4 * 5) as nat)
        == 1048576 && pow2((4 * 6) as nat) == 16777216 && pow2((4 * 7) as nat) == 268435456)
        by (compute);

    let x0 = (n0 as nat) * p0;
    let x1 = (n1 as nat) * p1;
    let x2 = (n2 as nat) * p2;
    let x3 = (n3 as nat) * p3;
    let x4 = (n4 as nat) * p4;
    let x5 = (n5 as nat) * p5;
    let x6 = (n6 as nat) * p6;
    let x7 = (n7 as nat) * p7;

    assert(x0 == m0 as nat && x1 == m1 as nat && x2 == m2 as nat && x3 == m3 as nat && x4 == m4
        as nat && x5 == m5 as nat && x6 == m6 as nat && x7 == m7 as nat) by (nonlinear_arith)
        requires
            p0 == 1,
            p1 == 16,
            p2 == 256,
            p3 == 4096,
            p4 == 65536,
            p5 == 1048576,
            p6 == 16777216,
            p7 == 268435456,
            x0 == (n0 as nat) * p0,
            x1 == (n1 as nat) * p1,
            x2 == (n2 as nat) * p2,
            x3 == (n3 as nat) * p3,
            x4 == (n4 as nat) * p4,
            x5 == (n5 as nat) * p5,
            x6 == (n6 as nat) * p6,
            x7 == (n7 as nat) * p7,
            m0 as nat == n0 as nat,
            m1 as nat == 16 * (n1 as nat),
            m2 as nat == 256 * (n2 as nat),
            m3 as nat == 4096 * (n3 as nat),
            m4 as nat == 65536 * (n4 as nat),
            m5 as nat == 1048576 * (n5 as nat),
            m6 as nat == 16777216 * (n6 as nat),
            m7 as nat == 268435456 * (n7 as nat),
    ;

    let a0 = bit_comb(x0, basis, 32);
    let a1 = bit_comb(x1, basis, 32);
    let a2 = bit_comb(x2, basis, 32);
    let a3 = bit_comb(x3, basis, 32);
    let a4 = bit_comb(x4, basis, 32);
    let a5 = bit_comb(x5, basis, 32);
    let a6 = bit_comb(x6, basis, 32);
    let a7 = bit_comb(x7, basis, 32);

    assert(t0 as nat == byte_at(a0, j));
    assert(t1 as nat == byte_at(a1, j));
    assert(t2 as nat == byte_at(a2, j));
    assert(t3 as nat == byte_at(a3, j));
    assert(t4 as nat == byte_at(a4, j));
    assert(t5 as nat == byte_at(a5, j));
    assert(t6 as nat == byte_at(a6, j));
    assert(t7 as nat == byte_at(a7, j));

    pair_byte(t0, t1, a0, a1, j);
    pair_byte(t2, t3, a2, a3, j);
    pair_byte(t4, t5, a4, a5, j);
    pair_byte(t6, t7, a6, a7, j);
    pair_byte(t0 ^ t1, t2 ^ t3, xor(a0, a1), xor(a2, a3), j);
    pair_byte(t4 ^ t5, t6 ^ t7, xor(a4, a5), xor(a6, a7), j);
    pair_byte(
        (t0 ^ t1) ^ (t2 ^ t3),
        (t4 ^ t5) ^ (t6 ^ t7),
        xor(xor(a0, a1), xor(a2, a3)),
        xor(xor(a4, a5), xor(a6, a7)),
        j,
    );

    bit_comb_additive(x0, x1, basis, 32);
    bit_comb_additive(x2, x3, basis, 32);
    bit_comb_additive(x4, x5, basis, 32);
    bit_comb_additive(x6, x7, basis, 32);
    bit_comb_additive(xor(x0, x1), xor(x2, x3), basis, 32);
    bit_comb_additive(xor(x4, x5), xor(x6, x7), basis, 32);
    bit_comb_additive(xor(xor(x0, x1), xor(x2, x3)), xor(xor(x4, x5), xor(x6, x7)), basis, 32);

    xor32_reflect(m0, m1);
    xor32_reflect(m2, m3);
    xor32_reflect(m4, m5);
    xor32_reflect(m6, m7);
    xor32_reflect(m0 ^ m1, m2 ^ m3);
    xor32_reflect(m4 ^ m5, m6 ^ m7);
    xor32_reflect((m0 ^ m1) ^ (m2 ^ m3), (m4 ^ m5) ^ (m6 ^ m7));
}

pub proof fn promote_batch_32_correct(tbl: Seq<Seq<Seq<u8>>>, basis: Seq<nat>, vals: Seq<u32>)
    requires
        vals.len() == 16,
        nibble_tables(tbl, basis, 32, 8),
    ensures
        rows16(promote_batch_32_twin(tbl, vals)),
        forall|l: int, j: int| 0 <= l < 16 && 0 <= j < 16
            ==> (#[trigger] promote_batch_32_twin(tbl, vals)[l][j]) as nat == byte_at(
                bit_comb(vals[l] as nat, basis, 32),
                j,
            ),
{
    let planes = planes_32(tbl, vals);

    uzp_32(vals);
    assert(rows16(planes));
    transpose_correct(planes);

    assert forall|l: int, j: int| 0 <= l < 16 && 0 <= j < 16 implies (
    #[trigger] promote_batch_32_twin(tbl, vals)[l][j]) as nat == byte_at(
        bit_comb(vals[l] as nat, basis, 32),
        j,
    ) by {
        plane_32_lane(tbl, basis, vals, l, j);
    }
}

pub proof fn promote_batch_32_lane(
    tbl: Seq<Seq<Seq<u8>>>,
    basis: Seq<nat>,
    vals: Seq<u32>,
    l: int,
    x: u128,
)
    requires
        vals.len() == 16,
        nibble_tables(tbl, basis, 32, 8),
        0 <= l < 16,
        x as nat == bit_comb(vals[l] as nat, basis, 32),
    ensures promote_batch_32_twin(tbl, vals)[l] == u128_bytes(x)
{
    promote_batch_32_correct(tbl, basis, vals);

    assert forall|j: int| 0 <= j < 16 implies promote_batch_32_twin(tbl, vals)[l][j] == u128_bytes(
        x,
    )[j] by {
        u128_byte(x, j);
    }

    assert(promote_batch_32_twin(tbl, vals)[l] =~= u128_bytes(x));
}

// ============================================================
// promote_batch_64_to_128, block128.rs: three UZP stages split
// the lanes into their eight bytes, sixteen nibble planes.
// ============================================================

pub open spec fn raw_64(vals: Seq<u64>, k: int) -> Seq<u8> {
    bytes64(vals.subrange(2 * k, 2 * k + 2))
}

pub open spec fn even_64(vals: Seq<u64>, k: int) -> Seq<u8> {
    vuzp1_m(raw_64(vals, k), raw_64(vals, k + 1))
}

pub open spec fn odd_64(vals: Seq<u64>, k: int) -> Seq<u8> {
    vuzp2_m(raw_64(vals, k), raw_64(vals, k + 1))
}

pub open spec fn byte_plane_64(vals: Seq<u64>, k: int) -> Seq<u8> {
    let e0_lo = vuzp1_m(even_64(vals, 0), even_64(vals, 2));
    let e2_lo = vuzp2_m(even_64(vals, 0), even_64(vals, 2));
    let o1_lo = vuzp1_m(odd_64(vals, 0), odd_64(vals, 2));
    let o3_lo = vuzp2_m(odd_64(vals, 0), odd_64(vals, 2));
    let e0_hi = vuzp1_m(even_64(vals, 4), even_64(vals, 6));
    let e2_hi = vuzp2_m(even_64(vals, 4), even_64(vals, 6));
    let o1_hi = vuzp1_m(odd_64(vals, 4), odd_64(vals, 6));
    let o3_hi = vuzp2_m(odd_64(vals, 4), odd_64(vals, 6));

    if k == 0 {
        vuzp1_m(e0_lo, e0_hi)
    } else if k == 1 {
        vuzp1_m(o1_lo, o1_hi)
    } else if k == 2 {
        vuzp1_m(e2_lo, e2_hi)
    } else if k == 3 {
        vuzp1_m(o3_lo, o3_hi)
    } else if k == 4 {
        vuzp2_m(e0_lo, e0_hi)
    } else if k == 5 {
        vuzp2_m(o1_lo, o1_hi)
    } else if k == 6 {
        vuzp2_m(e2_lo, e2_hi)
    } else {
        vuzp2_m(o3_lo, o3_hi)
    }
}

proof fn uzp_64_stage1(vals: Seq<u64>, k: int)
    requires
        vals.len() == 16,
        k == 0 || k == 2 || k == 4 || k == 6,
    ensures
        even_64(vals, k).len() == 16,
        odd_64(vals, k).len() == 16,
        forall|i: int| 0 <= i < 16 ==> #[trigger] even_64(vals, k)[i] == (vals[2 * k + i / 4] >> ((8
            * (2 * (i % 4))) as u64)) as u8,
        forall|i: int| 0 <= i < 16 ==> #[trigger] odd_64(vals, k)[i] == (vals[2 * k + i / 4] >> ((8
            * (2 * (i % 4) + 1)) as u64)) as u8,
{
    let r0 = raw_64(vals, k);
    let r1 = raw_64(vals, k + 1);

    assert forall|i: int| 0 <= i < 16 implies #[trigger] even_64(vals, k)[i] == (vals[2 * k + i / 4]
        >> ((8 * (2 * (i % 4))) as u64)) as u8 by {
        if i < 8 {
            assert(r0[2 * i] == (vals[2 * k + (2 * i) / 8] >> ((8 * ((2 * i) % 8)) as u64)) as u8);
        } else {
            assert(r1[2 * i - 16] == (vals[2 * (k + 1) + (2 * i - 16) / 8] >> ((8 * ((2 * i - 16)
                % 8)) as u64)) as u8);
        }
    }

    assert forall|i: int| 0 <= i < 16 implies #[trigger] odd_64(vals, k)[i] == (vals[2 * k + i / 4]
        >> ((8 * (2 * (i % 4) + 1)) as u64)) as u8 by {
        if i < 8 {
            assert(r0[2 * i + 1] == (vals[2 * k + (2 * i + 1) / 8] >> ((8 * ((2 * i + 1) % 8))
                as u64)) as u8);
        } else {
            assert(r1[2 * i - 15] == (vals[2 * (k + 1) + (2 * i - 15) / 8] >> ((8 * ((2 * i - 15)
                % 8)) as u64)) as u8);
        }
    }
}

proof fn uzp_64_stage2(vals: Seq<u64>, k: int)
    requires
        vals.len() == 16,
        k == 0 || k == 4,
    ensures
        forall|i: int| 0 <= i < 16 ==> #[trigger] vuzp1_m(even_64(vals, k), even_64(vals, k + 2))[i]
            == (vals[2 * k + i / 2] >> ((8 * (4 * (i % 2))) as u64)) as u8,
        forall|i: int| 0 <= i < 16 ==> #[trigger] vuzp2_m(even_64(vals, k), even_64(vals, k + 2))[i]
            == (vals[2 * k + i / 2] >> ((8 * (4 * (i % 2) + 2)) as u64)) as u8,
        forall|i: int| 0 <= i < 16 ==> #[trigger] vuzp1_m(odd_64(vals, k), odd_64(vals, k + 2))[i]
            == (vals[2 * k + i / 2] >> ((8 * (4 * (i % 2) + 1)) as u64)) as u8,
        forall|i: int| 0 <= i < 16 ==> #[trigger] vuzp2_m(odd_64(vals, k), odd_64(vals, k + 2))[i]
            == (vals[2 * k + i / 2] >> ((8 * (4 * (i % 2) + 3)) as u64)) as u8,
{
    uzp_64_stage1(vals, k);
    uzp_64_stage1(vals, k + 2);

    let ea = even_64(vals, k);
    let eb = even_64(vals, k + 2);
    let oa = odd_64(vals, k);
    let ob = odd_64(vals, k + 2);

    assert forall|i: int| 0 <= i < 16 implies #[trigger] vuzp1_m(ea, eb)[i] == (vals[2 * k + i / 2]
        >> ((8 * (4 * (i % 2))) as u64)) as u8 by {
        if i < 8 {
            assert(ea[2 * i] == (vals[2 * k + (2 * i) / 4] >> ((8 * (2 * ((2 * i) % 4))) as u64)) as u8);
        } else {
            assert(eb[2 * i - 16] == (vals[2 * (k + 2) + (2 * i - 16) / 4] >> ((8 * (2 * ((2 * i - 16)
                % 4))) as u64)) as u8);
        }
    }

    assert forall|i: int| 0 <= i < 16 implies #[trigger] vuzp2_m(ea, eb)[i] == (vals[2 * k + i / 2]
        >> ((8 * (4 * (i % 2) + 2)) as u64)) as u8 by {
        if i < 8 {
            assert(ea[2 * i + 1] == (vals[2 * k + (2 * i + 1) / 4] >> ((8 * (2 * ((2 * i + 1) % 4)))
                as u64)) as u8);
        } else {
            assert(eb[2 * i - 15] == (vals[2 * (k + 2) + (2 * i - 15) / 4] >> ((8 * (2 * ((2 * i - 15)
                % 4))) as u64)) as u8);
        }
    }

    assert forall|i: int| 0 <= i < 16 implies #[trigger] vuzp1_m(oa, ob)[i] == (vals[2 * k + i / 2]
        >> ((8 * (4 * (i % 2) + 1)) as u64)) as u8 by {
        if i < 8 {
            assert(oa[2 * i] == (vals[2 * k + (2 * i) / 4] >> ((8 * (2 * ((2 * i) % 4) + 1)) as u64))
                as u8);
        } else {
            assert(ob[2 * i - 16] == (vals[2 * (k + 2) + (2 * i - 16) / 4] >> ((8 * (2 * ((2 * i - 16)
                % 4) + 1)) as u64)) as u8);
        }
    }

    assert forall|i: int| 0 <= i < 16 implies #[trigger] vuzp2_m(oa, ob)[i] == (vals[2 * k + i / 2]
        >> ((8 * (4 * (i % 2) + 3)) as u64)) as u8 by {
        if i < 8 {
            assert(oa[2 * i + 1] == (vals[2 * k + (2 * i + 1) / 4] >> ((8 * (2 * ((2 * i + 1) % 4)
                + 1)) as u64)) as u8);
        } else {
            assert(ob[2 * i - 15] == (vals[2 * (k + 2) + (2 * i - 15) / 4] >> ((8 * (2 * ((2 * i - 15)
                % 4) + 1)) as u64)) as u8);
        }
    }
}

proof fn uzp_64(vals: Seq<u64>)
    requires vals.len() == 16
    ensures
        forall|k: int| 0 <= k < 8 ==> (#[trigger] byte_plane_64(vals, k)).len() == 16,
        forall|k: int, l: int| 0 <= k < 8 && 0 <= l < 16
            ==> #[trigger] byte_plane_64(vals, k)[l] == (vals[l] >> ((8 * k) as u64)) as u8,
{
    uzp_64_stage2(vals, 0);
    uzp_64_stage2(vals, 4);

    let e0_lo = vuzp1_m(even_64(vals, 0), even_64(vals, 2));
    let e2_lo = vuzp2_m(even_64(vals, 0), even_64(vals, 2));
    let o1_lo = vuzp1_m(odd_64(vals, 0), odd_64(vals, 2));
    let o3_lo = vuzp2_m(odd_64(vals, 0), odd_64(vals, 2));
    let e0_hi = vuzp1_m(even_64(vals, 4), even_64(vals, 6));
    let e2_hi = vuzp2_m(even_64(vals, 4), even_64(vals, 6));
    let o1_hi = vuzp1_m(odd_64(vals, 4), odd_64(vals, 6));
    let o3_hi = vuzp2_m(odd_64(vals, 4), odd_64(vals, 6));

    assert forall|k: int, l: int| 0 <= k < 8 && 0 <= l < 16 implies #[trigger] byte_plane_64(vals, k)[l]
        == (vals[l] >> ((8 * k) as u64)) as u8 by {
        if l < 8 {
            assert(e0_lo[2 * l] == (vals[l] >> ((8 * (4 * ((2 * l) % 2))) as u64)) as u8);
            assert(e0_lo[2 * l + 1] == (vals[l] >> ((8 * (4 * ((2 * l + 1) % 2))) as u64)) as u8);
            assert(e2_lo[2 * l] == (vals[l] >> ((8 * (4 * ((2 * l) % 2) + 2)) as u64)) as u8);
            assert(e2_lo[2 * l + 1] == (vals[l] >> ((8 * (4 * ((2 * l + 1) % 2) + 2)) as u64)) as u8);
            assert(o1_lo[2 * l] == (vals[l] >> ((8 * (4 * ((2 * l) % 2) + 1)) as u64)) as u8);
            assert(o1_lo[2 * l + 1] == (vals[l] >> ((8 * (4 * ((2 * l + 1) % 2) + 1)) as u64)) as u8);
            assert(o3_lo[2 * l] == (vals[l] >> ((8 * (4 * ((2 * l) % 2) + 3)) as u64)) as u8);
            assert(o3_lo[2 * l + 1] == (vals[l] >> ((8 * (4 * ((2 * l + 1) % 2) + 3)) as u64)) as u8);
        } else {
            assert(e0_hi[2 * l - 16] == (vals[l] >> ((8 * (4 * ((2 * l - 16) % 2))) as u64)) as u8);
            assert(e0_hi[2 * l - 15] == (vals[l] >> ((8 * (4 * ((2 * l - 15) % 2))) as u64)) as u8);
            assert(e2_hi[2 * l - 16] == (vals[l] >> ((8 * (4 * ((2 * l - 16) % 2) + 2)) as u64)) as u8);
            assert(e2_hi[2 * l - 15] == (vals[l] >> ((8 * (4 * ((2 * l - 15) % 2) + 2)) as u64)) as u8);
            assert(o1_hi[2 * l - 16] == (vals[l] >> ((8 * (4 * ((2 * l - 16) % 2) + 1)) as u64)) as u8);
            assert(o1_hi[2 * l - 15] == (vals[l] >> ((8 * (4 * ((2 * l - 15) % 2) + 1)) as u64)) as u8);
            assert(o3_hi[2 * l - 16] == (vals[l] >> ((8 * (4 * ((2 * l - 16) % 2) + 3)) as u64)) as u8);
            assert(o3_hi[2 * l - 15] == (vals[l] >> ((8 * (4 * ((2 * l - 15) % 2) + 3)) as u64)) as u8);
        }
    }
}

pub open spec fn nib_64(vals: Seq<u64>, p: int) -> Seq<u8> {
    if p % 2 == 0 {
        lo_nib(byte_plane_64(vals, p / 2))
    } else {
        hi_nib(byte_plane_64(vals, p / 2))
    }
}

pub open spec fn look_64(tbl: Seq<Seq<Seq<u8>>>, vals: Seq<u64>, p: int, j: int) -> Seq<u8> {
    vqtbl1_m(tbl[p][j], nib_64(vals, p))
}

pub open spec fn planes_64(tbl: Seq<Seq<Seq<u8>>>, vals: Seq<u64>) -> Seq<Seq<u8>> {
    Seq::new(
        16,
        |j: int|
            veor_m8(
                veor_m8(
                    veor_m8(
                        veor_m8(look_64(tbl, vals, 0, j), look_64(tbl, vals, 1, j)),
                        veor_m8(look_64(tbl, vals, 2, j), look_64(tbl, vals, 3, j)),
                    ),
                    veor_m8(
                        veor_m8(look_64(tbl, vals, 4, j), look_64(tbl, vals, 5, j)),
                        veor_m8(look_64(tbl, vals, 6, j), look_64(tbl, vals, 7, j)),
                    ),
                ),
                veor_m8(
                    veor_m8(
                        veor_m8(look_64(tbl, vals, 8, j), look_64(tbl, vals, 9, j)),
                        veor_m8(look_64(tbl, vals, 10, j), look_64(tbl, vals, 11, j)),
                    ),
                    veor_m8(
                        veor_m8(look_64(tbl, vals, 12, j), look_64(tbl, vals, 13, j)),
                        veor_m8(look_64(tbl, vals, 14, j), look_64(tbl, vals, 15, j)),
                    ),
                ),
            ),
    )
}

pub open spec fn promote_batch_64_twin(tbl: Seq<Seq<Seq<u8>>>, vals: Seq<u64>) -> Seq<Seq<u8>> {
    transpose_16x16_twin(planes_64(tbl, vals))
}

proof fn nibble_64_lane(
    tbl: Seq<Seq<Seq<u8>>>,
    basis: Seq<nat>,
    vals: Seq<u64>,
    l: int,
    j: int,
    p: int,
    n: u8,
)
    requires
        vals.len() == 16,
        nibble_tables(tbl, basis, 64, 16),
        0 <= l < 16,
        0 <= j < 16,
        0 <= p < 16,
        n < 16,
        nib_64(vals, p)[l] == n,
    ensures look_64(tbl, vals, p, j)[l] as nat == byte_at(bit_comb((n as nat) * pow2((4 * p) as nat), basis, 64), j)
{
    uzp_64(vals);
}

proof fn plane_64_lane(tbl: Seq<Seq<Seq<u8>>>, basis: Seq<nat>, vals: Seq<u64>, l: int, j: int)
    requires
        vals.len() == 16,
        nibble_tables(tbl, basis, 64, 16),
        0 <= l < 16,
        0 <= j < 16,
    ensures planes_64(tbl, vals)[j][l] as nat == byte_at(bit_comb(vals[l] as nat, basis, 64), j)
{
    uzp_64(vals);

    let v = vals[l];

    let b0 = (v >> 0u64) as u8;
    let b1 = (v >> 8u64) as u8;
    let b2 = (v >> 16u64) as u8;
    let b3 = (v >> 24u64) as u8;
    let b4 = (v >> 32u64) as u8;
    let b5 = (v >> 40u64) as u8;
    let b6 = (v >> 48u64) as u8;
    let b7 = (v >> 56u64) as u8;

    let n0 = b0 & 0x0F;
    let n1 = b0 >> 4;
    let n2 = b1 & 0x0F;
    let n3 = b1 >> 4;
    let n4 = b2 & 0x0F;
    let n5 = b2 >> 4;
    let n6 = b3 & 0x0F;
    let n7 = b3 >> 4;
    let n8 = b4 & 0x0F;
    let n9 = b4 >> 4;
    let n10 = b5 & 0x0F;
    let n11 = b5 >> 4;
    let n12 = b6 & 0x0F;
    let n13 = b6 >> 4;
    let n14 = b7 & 0x0F;
    let n15 = b7 >> 4;

    let m0 = n0 as u64;
    let m1 = (n1 as u64) << 4;
    let m2 = (n2 as u64) << 8;
    let m3 = (n3 as u64) << 12;
    let m4 = (n4 as u64) << 16;
    let m5 = (n5 as u64) << 20;
    let m6 = (n6 as u64) << 24;
    let m7 = (n7 as u64) << 28;
    let m8 = (n8 as u64) << 32;
    let m9 = (n9 as u64) << 36;
    let m10 = (n10 as u64) << 40;
    let m11 = (n11 as u64) << 44;
    let m12 = (n12 as u64) << 48;
    let m13 = (n13 as u64) << 52;
    let m14 = (n14 as u64) << 56;
    let m15 = (n15 as u64) << 60;

    assert(n0 < 16 && n1 < 16 && n2 < 16 && n3 < 16 && n4 < 16 && n5 < 16 && n6 < 16 && n7 < 16 && n8
        < 16 && n9 < 16 && n10 < 16 && n11 < 16 && n12 < 16 && n13 < 16 && n14 < 16 && n15 < 16 && m1
        == 0x10 * (n1 as u64) && m2 == 0x100 * (n2 as u64) && m3 == 0x1000 * (n3 as u64) && m4
        == 0x10000 * (n4 as u64) && m5 == 0x100000 * (n5 as u64) && m6 == 0x1000000 * (n6 as u64)
        && m7 == 0x10000000 * (n7 as u64) && m8 == 0x100000000 * (n8 as u64) && m9
        == 0x1000000000 * (n9 as u64) && m10 == 0x10000000000 * (n10 as u64) && m11
        == 0x100000000000 * (n11 as u64) && m12 == 0x1000000000000 * (n12 as u64) && m13
        == 0x10000000000000 * (n13 as u64) && m14 == 0x100000000000000 * (n14 as u64) && m15
        == 0x1000000000000000 * (n15 as u64) && v == (((m0 ^ m1) ^ (m2 ^ m3)) ^ ((m4 ^ m5) ^ (m6
        ^ m7))) ^ (((m8 ^ m9) ^ (m10 ^ m11)) ^ ((m12 ^ m13) ^ (m14 ^ m15)))) by (bit_vector)
        requires
            b0 == (v >> 0u64) as u8,
            b1 == (v >> 8u64) as u8,
            b2 == (v >> 16u64) as u8,
            b3 == (v >> 24u64) as u8,
            b4 == (v >> 32u64) as u8,
            b5 == (v >> 40u64) as u8,
            b6 == (v >> 48u64) as u8,
            b7 == (v >> 56u64) as u8,
            n0 == b0 & 0x0F,
            n1 == b0 >> 4,
            n2 == b1 & 0x0F,
            n3 == b1 >> 4,
            n4 == b2 & 0x0F,
            n5 == b2 >> 4,
            n6 == b3 & 0x0F,
            n7 == b3 >> 4,
            n8 == b4 & 0x0F,
            n9 == b4 >> 4,
            n10 == b5 & 0x0F,
            n11 == b5 >> 4,
            n12 == b6 & 0x0F,
            n13 == b6 >> 4,
            n14 == b7 & 0x0F,
            n15 == b7 >> 4,
            m0 == n0 as u64,
            m1 == (n1 as u64) << 4,
            m2 == (n2 as u64) << 8,
            m3 == (n3 as u64) << 12,
            m4 == (n4 as u64) << 16,
            m5 == (n5 as u64) << 20,
            m6 == (n6 as u64) << 24,
            m7 == (n7 as u64) << 28,
            m8 == (n8 as u64) << 32,
            m9 == (n9 as u64) << 36,
            m10 == (n10 as u64) << 40,
            m11 == (n11 as u64) << 44,
            m12 == (n12 as u64) << 48,
            m13 == (n13 as u64) << 52,
            m14 == (n14 as u64) << 56,
            m15 == (n15 as u64) << 60,
    ;

    assert(byte_plane_64(vals, 0)[l] == b0);
    assert(byte_plane_64(vals, 1)[l] == b1);
    assert(byte_plane_64(vals, 2)[l] == b2);
    assert(byte_plane_64(vals, 3)[l] == b3);
    assert(byte_plane_64(vals, 4)[l] == b4);
    assert(byte_plane_64(vals, 5)[l] == b5);
    assert(byte_plane_64(vals, 6)[l] == b6);
    assert(byte_plane_64(vals, 7)[l] == b7);

    assert(pow2((4 * 0) as nat) == 0x1 && pow2((4 * 1) as nat) == 0x10 && pow2((4 * 2) as nat)
        == 0x100 && pow2((4 * 3) as nat) == 0x1000 && pow2((4 * 4) as nat) == 0x10000 && pow2((4
        * 5) as nat) == 0x100000 && pow2((4 * 6) as nat) == 0x1000000 && pow2((4 * 7) as nat)
        == 0x10000000 && pow2((4 * 8) as nat) == 0x100000000 && pow2((4 * 9) as nat)
        == 0x1000000000 && pow2((4 * 10) as nat) == 0x10000000000 && pow2((4 * 11) as nat)
        == 0x100000000000 && pow2((4 * 12) as nat) == 0x1000000000000 && pow2((4 * 13) as nat)
        == 0x10000000000000 && pow2((4 * 14) as nat) == 0x100000000000000 && pow2((4 * 15) as nat)
        == 0x1000000000000000) by (compute);

    let x0 = (n0 as nat) * pow2((4 * 0) as nat);
    let x1 = (n1 as nat) * pow2((4 * 1) as nat);
    let x2 = (n2 as nat) * pow2((4 * 2) as nat);
    let x3 = (n3 as nat) * pow2((4 * 3) as nat);
    let x4 = (n4 as nat) * pow2((4 * 4) as nat);
    let x5 = (n5 as nat) * pow2((4 * 5) as nat);
    let x6 = (n6 as nat) * pow2((4 * 6) as nat);
    let x7 = (n7 as nat) * pow2((4 * 7) as nat);
    let x8 = (n8 as nat) * pow2((4 * 8) as nat);
    let x9 = (n9 as nat) * pow2((4 * 9) as nat);
    let x10 = (n10 as nat) * pow2((4 * 10) as nat);
    let x11 = (n11 as nat) * pow2((4 * 11) as nat);
    let x12 = (n12 as nat) * pow2((4 * 12) as nat);
    let x13 = (n13 as nat) * pow2((4 * 13) as nat);
    let x14 = (n14 as nat) * pow2((4 * 14) as nat);
    let x15 = (n15 as nat) * pow2((4 * 15) as nat);

    assert(x0 == m0 as nat && x1 == m1 as nat && x2 == m2 as nat && x3 == m3 as nat && x4 == m4
        as nat && x5 == m5 as nat && x6 == m6 as nat && x7 == m7 as nat && x8 == m8 as nat && x9
        == m9 as nat && x10 == m10 as nat && x11 == m11 as nat && x12 == m12 as nat && x13 == m13
        as nat && x14 == m14 as nat && x15 == m15 as nat) by (nonlinear_arith)
        requires
            pow2((4 * 0) as nat) == 0x1,
            pow2((4 * 1) as nat) == 0x10,
            pow2((4 * 2) as nat) == 0x100,
            pow2((4 * 3) as nat) == 0x1000,
            pow2((4 * 4) as nat) == 0x10000,
            pow2((4 * 5) as nat) == 0x100000,
            pow2((4 * 6) as nat) == 0x1000000,
            pow2((4 * 7) as nat) == 0x10000000,
            pow2((4 * 8) as nat) == 0x100000000,
            pow2((4 * 9) as nat) == 0x1000000000,
            pow2((4 * 10) as nat) == 0x10000000000,
            pow2((4 * 11) as nat) == 0x100000000000,
            pow2((4 * 12) as nat) == 0x1000000000000,
            pow2((4 * 13) as nat) == 0x10000000000000,
            pow2((4 * 14) as nat) == 0x100000000000000,
            pow2((4 * 15) as nat) == 0x1000000000000000,
            x0 == (n0 as nat) * pow2((4 * 0) as nat),
            x1 == (n1 as nat) * pow2((4 * 1) as nat),
            x2 == (n2 as nat) * pow2((4 * 2) as nat),
            x3 == (n3 as nat) * pow2((4 * 3) as nat),
            x4 == (n4 as nat) * pow2((4 * 4) as nat),
            x5 == (n5 as nat) * pow2((4 * 5) as nat),
            x6 == (n6 as nat) * pow2((4 * 6) as nat),
            x7 == (n7 as nat) * pow2((4 * 7) as nat),
            x8 == (n8 as nat) * pow2((4 * 8) as nat),
            x9 == (n9 as nat) * pow2((4 * 9) as nat),
            x10 == (n10 as nat) * pow2((4 * 10) as nat),
            x11 == (n11 as nat) * pow2((4 * 11) as nat),
            x12 == (n12 as nat) * pow2((4 * 12) as nat),
            x13 == (n13 as nat) * pow2((4 * 13) as nat),
            x14 == (n14 as nat) * pow2((4 * 14) as nat),
            x15 == (n15 as nat) * pow2((4 * 15) as nat),
            m0 as nat == n0 as nat,
            m1 as nat == 0x10 * (n1 as nat),
            m2 as nat == 0x100 * (n2 as nat),
            m3 as nat == 0x1000 * (n3 as nat),
            m4 as nat == 0x10000 * (n4 as nat),
            m5 as nat == 0x100000 * (n5 as nat),
            m6 as nat == 0x1000000 * (n6 as nat),
            m7 as nat == 0x10000000 * (n7 as nat),
            m8 as nat == 0x100000000 * (n8 as nat),
            m9 as nat == 0x1000000000 * (n9 as nat),
            m10 as nat == 0x10000000000 * (n10 as nat),
            m11 as nat == 0x100000000000 * (n11 as nat),
            m12 as nat == 0x1000000000000 * (n12 as nat),
            m13 as nat == 0x10000000000000 * (n13 as nat),
            m14 as nat == 0x100000000000000 * (n14 as nat),
            m15 as nat == 0x1000000000000000 * (n15 as nat),
    ;

    let a0 = bit_comb(x0, basis, 64);
    let a1 = bit_comb(x1, basis, 64);
    let a2 = bit_comb(x2, basis, 64);
    let a3 = bit_comb(x3, basis, 64);
    let a4 = bit_comb(x4, basis, 64);
    let a5 = bit_comb(x5, basis, 64);
    let a6 = bit_comb(x6, basis, 64);
    let a7 = bit_comb(x7, basis, 64);
    let a8 = bit_comb(x8, basis, 64);
    let a9 = bit_comb(x9, basis, 64);
    let a10 = bit_comb(x10, basis, 64);
    let a11 = bit_comb(x11, basis, 64);
    let a12 = bit_comb(x12, basis, 64);
    let a13 = bit_comb(x13, basis, 64);
    let a14 = bit_comb(x14, basis, 64);
    let a15 = bit_comb(x15, basis, 64);

    let t0 = look_64(tbl, vals, 0, j)[l];
    let t1 = look_64(tbl, vals, 1, j)[l];
    let t2 = look_64(tbl, vals, 2, j)[l];
    let t3 = look_64(tbl, vals, 3, j)[l];
    let t4 = look_64(tbl, vals, 4, j)[l];
    let t5 = look_64(tbl, vals, 5, j)[l];
    let t6 = look_64(tbl, vals, 6, j)[l];
    let t7 = look_64(tbl, vals, 7, j)[l];
    let t8 = look_64(tbl, vals, 8, j)[l];
    let t9 = look_64(tbl, vals, 9, j)[l];
    let t10 = look_64(tbl, vals, 10, j)[l];
    let t11 = look_64(tbl, vals, 11, j)[l];
    let t12 = look_64(tbl, vals, 12, j)[l];
    let t13 = look_64(tbl, vals, 13, j)[l];
    let t14 = look_64(tbl, vals, 14, j)[l];
    let t15 = look_64(tbl, vals, 15, j)[l];

    nibble_64_lane(tbl, basis, vals, l, j, 0, n0);
    nibble_64_lane(tbl, basis, vals, l, j, 1, n1);
    nibble_64_lane(tbl, basis, vals, l, j, 2, n2);
    nibble_64_lane(tbl, basis, vals, l, j, 3, n3);
    nibble_64_lane(tbl, basis, vals, l, j, 4, n4);
    nibble_64_lane(tbl, basis, vals, l, j, 5, n5);
    nibble_64_lane(tbl, basis, vals, l, j, 6, n6);
    nibble_64_lane(tbl, basis, vals, l, j, 7, n7);
    nibble_64_lane(tbl, basis, vals, l, j, 8, n8);
    nibble_64_lane(tbl, basis, vals, l, j, 9, n9);
    nibble_64_lane(tbl, basis, vals, l, j, 10, n10);
    nibble_64_lane(tbl, basis, vals, l, j, 11, n11);
    nibble_64_lane(tbl, basis, vals, l, j, 12, n12);
    nibble_64_lane(tbl, basis, vals, l, j, 13, n13);
    nibble_64_lane(tbl, basis, vals, l, j, 14, n14);
    nibble_64_lane(tbl, basis, vals, l, j, 15, n15);

    assert(planes_64(tbl, vals)[j][l] == (((t0 ^ t1) ^ (t2 ^ t3)) ^ ((t4 ^ t5) ^ (t6 ^ t7))) ^ (((t8
        ^ t9) ^ (t10 ^ t11)) ^ ((t12 ^ t13) ^ (t14 ^ t15))));

    pair_byte(t0, t1, a0, a1, j);
    pair_byte(t2, t3, a2, a3, j);
    pair_byte(t4, t5, a4, a5, j);
    pair_byte(t6, t7, a6, a7, j);
    pair_byte(t8, t9, a8, a9, j);
    pair_byte(t10, t11, a10, a11, j);
    pair_byte(t12, t13, a12, a13, j);
    pair_byte(t14, t15, a14, a15, j);
    pair_byte(t0 ^ t1, t2 ^ t3, xor(a0, a1), xor(a2, a3), j);
    pair_byte(t4 ^ t5, t6 ^ t7, xor(a4, a5), xor(a6, a7), j);
    pair_byte(t8 ^ t9, t10 ^ t11, xor(a8, a9), xor(a10, a11), j);
    pair_byte(t12 ^ t13, t14 ^ t15, xor(a12, a13), xor(a14, a15), j);
    pair_byte(
        (t0 ^ t1) ^ (t2 ^ t3),
        (t4 ^ t5) ^ (t6 ^ t7),
        xor(xor(a0, a1), xor(a2, a3)),
        xor(xor(a4, a5), xor(a6, a7)),
        j,
    );
    pair_byte(
        (t8 ^ t9) ^ (t10 ^ t11),
        (t12 ^ t13) ^ (t14 ^ t15),
        xor(xor(a8, a9), xor(a10, a11)),
        xor(xor(a12, a13), xor(a14, a15)),
        j,
    );
    pair_byte(
        ((t0 ^ t1) ^ (t2 ^ t3)) ^ ((t4 ^ t5) ^ (t6 ^ t7)),
        ((t8 ^ t9) ^ (t10 ^ t11)) ^ ((t12 ^ t13) ^ (t14 ^ t15)),
        xor(xor(xor(a0, a1), xor(a2, a3)), xor(xor(a4, a5), xor(a6, a7))),
        xor(xor(xor(a8, a9), xor(a10, a11)), xor(xor(a12, a13), xor(a14, a15))),
        j,
    );

    bit_comb_additive(x0, x1, basis, 64);
    bit_comb_additive(x2, x3, basis, 64);
    bit_comb_additive(x4, x5, basis, 64);
    bit_comb_additive(x6, x7, basis, 64);
    bit_comb_additive(x8, x9, basis, 64);
    bit_comb_additive(x10, x11, basis, 64);
    bit_comb_additive(x12, x13, basis, 64);
    bit_comb_additive(x14, x15, basis, 64);
    bit_comb_additive(xor(x0, x1), xor(x2, x3), basis, 64);
    bit_comb_additive(xor(x4, x5), xor(x6, x7), basis, 64);
    bit_comb_additive(xor(x8, x9), xor(x10, x11), basis, 64);
    bit_comb_additive(xor(x12, x13), xor(x14, x15), basis, 64);
    bit_comb_additive(xor(xor(x0, x1), xor(x2, x3)), xor(xor(x4, x5), xor(x6, x7)), basis, 64);
    bit_comb_additive(xor(xor(x8, x9), xor(x10, x11)), xor(xor(x12, x13), xor(x14, x15)), basis, 64);
    bit_comb_additive(
        xor(xor(xor(x0, x1), xor(x2, x3)), xor(xor(x4, x5), xor(x6, x7))),
        xor(xor(xor(x8, x9), xor(x10, x11)), xor(xor(x12, x13), xor(x14, x15))),
        basis,
        64,
    );

    xor64_reflect(m0, m1);
    xor64_reflect(m2, m3);
    xor64_reflect(m4, m5);
    xor64_reflect(m6, m7);
    xor64_reflect(m8, m9);
    xor64_reflect(m10, m11);
    xor64_reflect(m12, m13);
    xor64_reflect(m14, m15);
    xor64_reflect(m0 ^ m1, m2 ^ m3);
    xor64_reflect(m4 ^ m5, m6 ^ m7);
    xor64_reflect(m8 ^ m9, m10 ^ m11);
    xor64_reflect(m12 ^ m13, m14 ^ m15);
    xor64_reflect((m0 ^ m1) ^ (m2 ^ m3), (m4 ^ m5) ^ (m6 ^ m7));
    xor64_reflect((m8 ^ m9) ^ (m10 ^ m11), (m12 ^ m13) ^ (m14 ^ m15));
    xor64_reflect(
        ((m0 ^ m1) ^ (m2 ^ m3)) ^ ((m4 ^ m5) ^ (m6 ^ m7)),
        ((m8 ^ m9) ^ (m10 ^ m11)) ^ ((m12 ^ m13) ^ (m14 ^ m15)),
    );
}

pub proof fn promote_batch_64_correct(tbl: Seq<Seq<Seq<u8>>>, basis: Seq<nat>, vals: Seq<u64>)
    requires
        vals.len() == 16,
        nibble_tables(tbl, basis, 64, 16),
    ensures
        rows16(promote_batch_64_twin(tbl, vals)),
        forall|l: int, j: int| 0 <= l < 16 && 0 <= j < 16
            ==> (#[trigger] promote_batch_64_twin(tbl, vals)[l][j]) as nat == byte_at(
                bit_comb(vals[l] as nat, basis, 64),
                j,
            ),
{
    let planes = planes_64(tbl, vals);

    uzp_64(vals);
    assert(rows16(planes));
    transpose_correct(planes);

    assert forall|l: int, j: int| 0 <= l < 16 && 0 <= j < 16 implies (
    #[trigger] promote_batch_64_twin(tbl, vals)[l][j]) as nat == byte_at(
        bit_comb(vals[l] as nat, basis, 64),
        j,
    ) by {
        plane_64_lane(tbl, basis, vals, l, j);
    }
}

pub proof fn promote_batch_64_lane(
    tbl: Seq<Seq<Seq<u8>>>,
    basis: Seq<nat>,
    vals: Seq<u64>,
    l: int,
    x: u128,
)
    requires
        vals.len() == 16,
        nibble_tables(tbl, basis, 64, 16),
        0 <= l < 16,
        x as nat == bit_comb(vals[l] as nat, basis, 64),
    ensures promote_batch_64_twin(tbl, vals)[l] == u128_bytes(x)
{
    promote_batch_64_correct(tbl, basis, vals);

    assert forall|j: int| 0 <= j < 16 implies promote_batch_64_twin(tbl, vals)[l][j] == u128_bytes(
        x,
    )[j] by {
        u128_byte(x, j);
    }

    assert(promote_batch_64_twin(tbl, vals)[l] =~= u128_bytes(x));
}

fn main() {
}

}
