# verus/

Standalone [Verus](https://github.com/verus-lang/verus) proofs for
`hekate-math`. They are **not** part of the crate, `cargo build`, `test`,
and `clippy` never compile them, and they are excluded from the published
package. Verify one with the Verus driver:

```
verus verus/block256.rs
```

Each `blockN.rs` proves that production `BlockN::mul`'s Karatsuba refines the
naive schoolbook GF(2^k) product, and pulls in the level below via `#[path]`.
Verifying `block256.rs` therefore verifies the whole cascade down to
`block8.rs`, which discharges its base case exhaustively (2^16 pairs) by
bit-vector.

| File                        | Contents                                                                                                                                 |
|-----------------------------|------------------------------------------------------------------------------------------------------------------------------------------|
| `gf_model.rs`               | Abstract `nat` GF(2^k) / tower spec; the bilinear extension (`linear_determined_field`: single-bit basis homomorphism ⇒ full field iso); Frobenius order, `k % BITS` cycle, trace idempotence. |
| `block8.rs` … `block256.rs` | Per-level `mul == schoolbook` cascade.                                                                                                   |
| `tower_bridge.rs`           | Ties the `uN` block cascade to the `nat` model via per-op reflection lemmas; `#[path]`-pulls `gf_model.rs` and `block256.rs`.            |
| `matrix.rs`                 | SpMV loop memory safety, index bounds + output-init, twinning production `process_chunk`.                                                |
| `algebra.rs`                | `BinaryFieldExtras` twins at GF(2^16): `square` split, default `frobenius` and `trace` loops, tied to the tower model via `tower_bridge`. |
| `fft.rs`                    | Additive-FFT twin and semantics: strided index safety, constructor twiddle schedule, `inverse ∘ forward == id` (twiddle-agnostic), and forward = novel-basis evaluation over the Cantor chain. |
| `TRUSTED_AXIOMS.md`         | What the proofs take on trust.                                                                                                           |

`tests/tower_oracle.rs` transcribes the `schoolbook*` oracles from these files
and checks production `mul` against them, tying the shipped code to the
verified algorithm.