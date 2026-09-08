# Verus proofs

Standalone [Verus](https://github.com/verus-lang/verus) proofs for
`hekate-math`. `cargo build`, `test`, and `clippy` never compile them.
`verus/scripts/verify.sh` verifies every unit, or the units named on
its command line, and prints one line per discharged function plus
the verified/error counts. It takes the binary from `$VERUS` or
`verus` on `PATH` and needs `jq`. The scripts run from the repo root
wherever they are invoked from:

```
verus/scripts/verify.sh
verus/scripts/verify.sh verus/tower/block256.rs
VERUS_SEED=3 verus/scripts/verify.sh
verus/scripts/negative_controls.sh
verus/scripts/oracle_sync.sh
```

Each `tower/blockN.rs` proves that production `BlockN::mul`'s Karatsuba
refines the naive schoolbook GF(2^k) product, and pulls in the level below
via `#[path]`. Verifying `tower/block256.rs` therefore verifies the whole
cascade down to `tower/block8.rs`, which discharges its base case
exhaustively (2^16 pairs) by bit-vector.

Under `pmull`, `Block64::mul` and (with `table-math`) `Block128::mul`
take the flat route instead of that Karatsuba: φ⁻¹(φ(a)·φ(b)) through
`mul_iso_N`, carried by `neon/flat.rs` and the `mul_iso` seam row in
`TRUSTED_AXIOMS.md`.

| File                                    | Contents                                                                                                                                                                                                             |
|-----------------------------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `gf_model.rs`                           | Abstract `nat` GF(2^k) / tower spec; the bilinear extension (`linear_determined_field`: single-bit basis homomorphism ⇒ full field iso); Frobenius order, `k % BITS` cycle, trace idempotence.                       |
| `axioms_t.rs`                           | The trusted base: the `external_body` axioms (`phi_roundtrip`, `phi_mult_gen`, `norm_nonzero`, `frobenius_order_gen`), each build-discharged; `#[path]`-child of `gf_model.rs`, not a standalone unit.               |
| `tower/block8.rs` … `tower/block256.rs` | Per-level `mul == schoolbook` cascade.                                                                                                                                                                               |
| `tower/bridge.rs`                       | Ties the `uN` block cascade to the `nat` model via per-op reflection lemmas; `#[path]`-pulls `gf_model.rs` and `block256.rs`.                                                                                        |
| `algebra.rs`                            | `BinaryFieldExtras` twins at GF(2^16): `square` split, default `frobenius` and `trace` loops, tied to the tower model via `tower/bridge.rs`.                                                                         |
| `inverse.rs`                            | `invert` twins: the norm recursion at 16..256 over `quad_ext_inverse`, the Fermat chain `a^254` at 8 over `frobenius_order` and exhaustive zero-divisor freedom; `#[path]`-pulls `algebra.rs`.                       |
| `fft.rs`                                | Additive-FFT twin and semantics: level-pass index safety, constructor twiddle schedule, `inverse ∘ forward == id` (twiddle-agnostic), and forward = novel-basis evaluation over the Cantor chain.                    |
| `neon/model_t.rs`                       | Per-instruction spec of the NEON surface (PMULL, EOR, AND, TBL, TRN/UZP, shifts, moves, the LE transmute view), definitions only, each citing DDI 0487.                                                              |
| `neon/bridge.rs`                        | PMULL ↔ `clmul` reflection at 8/64 bits, the generic double-fold congruence (`fold_step`), limb schoolbook and Karatsuba at the `clmul` level, xor/pack reflections.                                                 |
| `neon/flat.rs`                          | Scalar flat-multiply twins proven equal to `gf_mul`: `mul_8`, `mul_flat_16/32/64`, and the 128-bit limb schoolbook with its two-stage 0x87 fold.                                                                     |
| `neon/packed.rs`                        | Packed kernels per lane == `gf_mul`: byte-Karatsuba + shift-decomposed fold at 16, the TBL reduction at 8 (table bytes proven), the 32/128 lane loops, the packed-64 lane pipeline.                                  |
| `neon/convert.rs`                       | `map_ct_*` / `lift_ct_*` twins == the φ column map (`bit_comb`), `tower_bit_N` parity folds == one bit of it; `mul_iso_N`, the non-aarch64 multiply fallback, and the flat-256 pair Karatsuba as composition lemmas. |
| `neon/promote.rs`                       | `promote_batch_{8,16,32,64}_to_128` twins: UZP deinterleave, nibble TBL planes, and the 16×16 TRN transpose over the model; each lane == the bytes of `bit_comb`.                                                       |
| `TRUSTED_AXIOMS.md`                     | What the proofs take on trust.                                                                                                                                                                                       |

The `_t` suffix marks a trusted file: definitions taken on trust with
zero proof content, per the register in `TRUSTED_AXIOMS.md`. Every
other unit is verified, relative to the `_t` rows and the seam rows
registered there.

`tests/tower_oracle.rs` transcribes the `schoolbook*` oracles from these files
and checks production `mul` against them, tying the shipped code to the
verified algorithm.
