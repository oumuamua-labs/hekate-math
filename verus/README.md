# verus/

Standalone [Verus](https://github.com/verus-lang/verus) proofs for
`hekate-math`. They are **not** part of the crate, `cargo build`, `test`,
and `clippy` never compile them, and they are excluded from the published
package. Verify one with the Verus driver:

```
verus verus/tower/block256.rs
```

Each `tower/blockN.rs` proves that production `BlockN::mul`'s Karatsuba
refines the naive schoolbook GF(2^k) product, and pulls in the level below
via `#[path]`. Verifying `tower/block256.rs` therefore verifies the whole
cascade down to `tower/block8.rs`, which discharges its base case
exhaustively (2^16 pairs) by bit-vector.

| File                                    | Contents                                                                                                                                                                                               |
|-----------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `gf_model.rs`                           | Abstract `nat` GF(2^k) / tower spec; the bilinear extension (`linear_determined_field`: single-bit basis homomorphism ⇒ full field iso); Frobenius order, `k % BITS` cycle, trace idempotence.         |
| `axioms_t.rs`                           | The trusted base: the `external_body` axioms (`phi_roundtrip`, `phi_mult_gen`, `norm_nonzero`, `frobenius_order_gen`), each build-discharged; `#[path]`-child of `gf_model.rs`, not a standalone unit. |
| `tower/block8.rs` … `tower/block256.rs` | Per-level `mul == schoolbook` cascade.                                                                                                                                                                 |
| `tower/bridge.rs`                       | Ties the `uN` block cascade to the `nat` model via per-op reflection lemmas; `#[path]`-pulls `gf_model.rs` and `block256.rs`.                                                                          |
| `matrix.rs`                             | SpMV loop memory safety, index bounds + output-init, twinning production `process_chunk`.                                                                                                              |
| `algebra.rs`                            | `BinaryFieldExtras` twins at GF(2^16): `square` split, default `frobenius` and `trace` loops, tied to the tower model via `tower/bridge.rs`.                                                           |
| `fft.rs`                                | Additive-FFT twin and semantics: level-pass index safety, constructor twiddle schedule, `inverse ∘ forward == id` (twiddle-agnostic), and forward = novel-basis evaluation over the Cantor chain.         |
| `neon/model_t.rs`                       | Per-instruction spec of the NEON surface (PMULL, EOR, AND, TBL, TRN/UZP, shifts, moves, the LE transmute view), definitions only, each citing DDI 0487.                                                |
| `neon/bridge.rs`                        | PMULL ↔ `clmul` reflection at 8/64 bits, the generic double-fold congruence (`fold_step`), limb Karatsuba at the `clmul` level, xor/pack reflections.                                                  |
| `neon/flat.rs`                          | Scalar flat-multiply twins proven equal to `gf_mul`: `mul_8`, `mul_flat_16/32/64`, and the 128-bit limb Karatsuba with its two-stage 0x87 fold.                                                        |
| `neon/packed.rs`                        | Packed kernels per lane == `gf_mul`: byte-Karatsuba + shift-decomposed fold at 16, the TBL reduction at 8 (table bytes proven), the 32/64/128 lane loops.                                              |
| `neon/convert.rs`                       | `map_ct_*` / `lift_ct` twins == the φ column map (`bit_comb`); the non-aarch64 multiply fallback and the flat-256 pair Karatsuba as φ-composition lemmas.                                              |
| `TRUSTED_AXIOMS.md`                     | What the proofs take on trust.                                                                                                                                                                         |

The `_t` suffix marks a trusted file: definitions taken on trust with
zero proof content, per the register in `TRUSTED_AXIOMS.md`. Every
other unit is verified, relative to the `_t` rows and the seam rows
registered there.

`tests/tower_oracle.rs` transcribes the `schoolbook*` oracles from these files
and checks production `mul` against them, tying the shipped code to the
verified algorithm.
