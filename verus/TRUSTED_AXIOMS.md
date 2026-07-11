# Trusted axioms

Facts the Verus proofs take without proof, and the obligations not yet
discharged. If it is not proven in Verus, it is here with the reason it
is trusted. The trusted base must stay smaller than the verified base.

## Outside Verus's language

Discharged by argument, by the Rust type system, or by a non-Verus check.

| Trusted fact                                                                                                                                                                                                                                                                   | Location                                  | Basis                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                        |
|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| NEON intrinsics compute their ARM semantics (`vmull_p64` = GF(2) carry-less multiply, `veorq_u8` = XOR, `vqtbl1q_u8` = table lookup, and the `transmute`s in each `mod neon`)                                                                                                  | `towers/*.rs`                             | ARM architecture reference                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   |
| The `asm!` prefetch (`prfm` / `prefetcht0`) is a cache hint that never faults; its pointer is never dereferenced                                                                                                                                                               | `matrix.rs`                               | Prefetch semantics                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| The generated change-of-basis matrices are mutually inverse GF(2)-linear maps inducing a field isomorphism; `POLY_8..POLY_128` are the reduction polynomials                                                                                                                   | `build/main.rs`                           | Exhaustive build-time checks (`verify_isomorphism_128`): 128-bit mutual inverse + ring-homomorphism on all 128² generators; GF(2^16) squaring oracle                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                         |
| `tau_tower(m)` and `TAU_FLAT` equal the matching `EXTENSION_TAU`                                                                                                                                                                                                               | `build/main.rs`, `block256.rs`            | Build-time consistency checks                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                |
| `X² + X + tau_tower(m)` irreducible over GF(2^m), norm form anisotropic (carries `gf_model.rs::norm_nonzero`, the tower-inverse field fact)                                                                                                                                    | `build/main.rs`, `gf_model.rs`            | `verify_norm_anisotropy`: `Tr_{GF(2^m)/GF(2)}(EXTENSION_TAU) = 1` for `m ∈ {8,16,32,64,128}` on each `cargo build`                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| The products the two build checks run on equal their Verus spec fns: `gf_oracle::schoolbook*` = `verus/blockN.rs::schoolbook*` = `gf_mul_tower`, and `gf_mul_flat_128` = `pmod(clmul(·), x^128 + 0x87)` = `gf_mul`                                                             | `build/gf_oracle.rs`, `build/main.rs`     | `gf_oracle` is `include!`d verbatim by both `build/main.rs` (the isomorphism and anisotropy discharge) and `tests/tower_oracle.rs`, whose differential test pins `schoolbook == production mul`; Verus proves the transcribed Karatsuba `mulN_k == schoolbook == gf_mul_tower` (production `mul` enters the chain only through that differential test). The discharge runs on that shared, production-tested oracle, not a private `build/main.rs` copy. Residual: `gf_mul_flat_128` = `pmod(clmul(·))` is matched to `gf_mul` by transcription (`x^128 + 0x87` ↔ `modulus(128)`; the flat basis has no differential test), whereas the tower `schoolbook*` is itself differential-tested against production |
| Production `BlockN::mul` matches its Verus twin `verus/blockN.rs::mulN_k` (same Karatsuba structure, same `TAU` literals)                                                                                                                                                      | `src/towers/*.rs` <-> `verus/block*.rs`   | Transcription seam; drift caught by review + `tests/tower_oracle.rs` in release-mode CI (exhaustive at 8/16 bits, 2–20M randomized cases at 32–256)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                          |
| `#[repr(transparent)]` layout: `Flat<F>` ≡ `F`, `Bit` ≡ `u8`, packed slices                                                                                                                                                                                                    | `hardware.rs`, `packable.rs`, `bit.rs`    | Rust `repr(transparent)` guarantee                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                           |
| rayon `par_chunks_mut(CHUNK_SIZE).enumerate()` delivers each `(chunk_id, chunk)` of `chunks_mut(CHUNK_SIZE).enumerate()` exactly once                                                                                                                                          | `matrix.rs`                               | The twin proves the chunk offset arithmetic and per-chunk write confinement, scheduling order cannot change the result; only this partition contract is trusted. `spmv_parallel_bit_memory_safety` runs the real dispatch on two threads under Miri's race detector in CI                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| Production `process_chunk` matches its Verus twin, which models `Flat<F>` as `u128`, takes the whole output buffer plus the chunk range (production: a disjoint `&mut` subslice), and elides the field accumulation                                                            | `src/matrix.rs:250` <-> `verus/matrix.rs` | Path B twin; field values do not affect bounds/init; confinement substitutes for the subslice borrow; drift caught by review + `verus verus/matrix.rs` and the Miri SpMV tests, all in CI                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    |
| `Vec::set_len` extends within capacity; `Vec::from_raw_parts` reinterprets an all-initialized `Vec<MaybeUninit<T>>` as `Vec<T>`                                                                                                                                                | `matrix.rs:221,326`                       | `external_body` in the twin; the all-init precondition is discharged by the verified fill loop                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                               |
| Production `AdditiveFft` (`new` from the lift on, both scalar transforms) matches its Verus twin `verus/fft.rs::FftTwin`, which models `Flat<F>` as `u128` (k = 128), pins `usize` to 64 bits, uses `u64` for the constructor's `bits`, and gates length with `Result<(), ()>` | `src/fft/additive.rs` <-> `verus/fft.rs`  | Path B twin; drift caught by review + `tests/fft.rs` (round-trip, Horner differential, coset variants) in CI. The packed transforms share the scalar index shape verbatim; their element ops land on the NEON row and the lane-wise packed-vs-scalar differential (`tests/fft.rs::additive_fft_lanewise_*`) checks them on real silicon                                                                                                                                                                                                                                                                                                                                                                      |
| The twin's `mul_flat` stub ensures `r == gf_mul(a, b, 128)`: the production flat multiply computes the model product                                                                                                                                                           | `verus/fft.rs::mul_flat`                  | The existing flat-multiply row, restated as the single trusted seam every FFT theorem is relative to; the stub is never executed (`unimplemented!()`). `add_flat` is proven (`xor128_reflect`), not trusted                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| The Cantor chain fed to `AdditiveFft::new` satisfies `fwd_semantics`' hypotheses: flat `beta[0] = 1`, `sigma_flat(beta[j]) = beta[j-1]`, and `solve_quadratic` returns a root of `x^2 + x = c` iff `Tr(c) = 0`                                                                 | `build/main.rs::write_algebra_extras_16`  | Exhaustive build-time checks on the real constants: tower chain + flat-basis chain (`sigma_flat` descent, `beta_0 = 1`) each `cargo build`; Artin–Schreier solvability round-trip on all 2^15 trace-zero inputs; the constructor twin proves the twiddle schedule is the point map of the lift (`tw_sum_is_point`), so only the lift values themselves rest on this row                                                                                                                                                                                                                                                                                                                                      |
| Verus, `vstd`, and Z3 are sound                                                                                                                                                                                                                                                | tooling                                   | Trusted computing base                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                       |

## Not modeled

- Constant-time / side-channel behavior, timing is not a functional
  property; it needs a separate analysis.
- Circuit / arithmetization soundness, not in this crate.

## Open obligations

`pmod` is now a concrete spec fn, polynomial long division over GF(2), with a
`decreases_by` termination proof (`sub_step_lt`: one division step strictly
lowers the value). `ax_pmod_deg` is retired: the degree bound is the proven
theorem `pmod_deg`. GF(2)[x] under (`xor`, `clmul`) is proven a commutative
ring, and reduction is proven a ring homomorphism onto the quotient
(`pmod_additive`, `pmod_of_multiple`, `pmod_mul_congr`, via the
unique-representative lemmas `pmod_congruent` / `pmod_unique`).

Proven in `gf_model.rs` (no `admit()`, no uninterpreted algebraic axiom):

- `gf_add_assoc`, `gf_mul_comm`, `gf_mul_assoc`, `gf_distrib`, `gf_mul_closed`.
- `gf_mul_assoc` / `gf_distrib` / `gf_mul_closed` carry `k ∈ {8,16,32,64,128}`:
  for other `k`, `modulus(k) == 0` and closure/associativity are false, the
  original preconditions (`k > 0`, or `in_field` alone) were unsound.

Tower lift (`gf_mul_tower`): commutativity, **associativity**, both
distributivities, `karatsuba_refines_schoolbook`, the zero laws, the
reduced-ness bound, and the pack `unfold` helper are all proven, the recursive
tower is a **fully verified commutative ring**. `is_correct_inverse` was
corrected from the flat `gf_mul` to `gf_mul_tower` (the inverse is a tower-basis
operation) and now also requires `in_field(r, k)` (reduced representative).

No `admit()` remains in `gf_model.rs` (94 verified, 0 errors). The former three:

- `tlo_assoc`, `thi_assoc`, the base-ring monomial identities (5-term and
  8-term) tower associativity reduces to, are **proven** by explicit
  monomial-by-monomial expansion under `hide(gf_mul_tower)`, the
  associativity `forall` e-matches only on introduced monomials and Z3 does not
  blow up. `gf_mul_tower_assoc` is therefore fully proven (`k ∈ {8,…,128}`);
  `gf_mul_tower_unfold` was extended to `k = 256`.
- `quad_ext_inverse`, the norm-inverse identity, is **proven** modulo the one
  trusted axiom below. The reduction `a · (conj(a) · ninv) == N(a) · ninv` is
  proven algebra (`thi`-part = 0, `tlo`-part = `N·ninv`, tau-generic).
- `karatsuba_refines_schoolbook` is **proven** (generic, `m ∈ {8,…,128}`).

Norm anisotropy (`norm_nonzero`), one `external_body` axiom, **build-discharged**:
for `a ≠ 0` in field, `N(a) = ext_norm(lo, hi, m) ≠ 0`, anisotropy of the norm
form, i.e. `X² + X + tau_tower(m)` irreducible over the level-`m` field
(Artin–Schreier `Tr(tau) = 1`). `build/main.rs::verify_norm_anisotropy` checks
`Tr_{GF(2^m)/GF(2)}(tau_m) = 1` for every generated `EXTENSION_TAU`
(`m ∈ {8,16,32,64,128}`) on each `cargo build`, squaring through the same shared
`gf_oracle::schoolbook*`, exactly as `verify_isomorphism_128`
discharges the `phi_*` axioms. **False for a generic uninterpreted `tau_tower`**,
it cannot be a Verus theorem in this model; it is the sole field-theoretic (vs.
ring-theoretic) fact `quad_ext_inverse` needs, everything else is machine-checked.

Frobenius order (`frobenius_order_gen`), one `external_body` axiom,
**build-discharged**: `e_i^(2^k) == e_i` on every single-bit generator of every
level (`k ∈ {8,16,32,64,128}`), checked by `build/main.rs::verify_frobenius_order`
through the same shared `gf_oracle::schoolbook*` on each `cargo build`. From it,
`frobenius_order` (all field elements, via `linear_determined_field` over the
proven squaring additivity), `frobenius_mod_cycle` (the `k % BITS` reduction),
and `trace_idempotent` (`Tr(x)^2 == Tr(x)`) are **proven** in `gf_model.rs`.
`verus/algebra.rs` ties the production `BinaryFieldExtras` shapes to these:
the `Block16::square` split (`square16_twin_correct`, via `bridge16`), the
default frobenius loop (`frobenius16_semantics`), and the default trace loop
(`trace_iter16_reflect`, `trace16_idempotent`). Trace membership in `{0, 1}`
additionally needs zero-divisor freedom, which stays with the exhaustive
16-bit build check in `write_algebra_extras_16`.

Additive FFT (`verus/fft.rs`), all relative to the `mul_flat` row: index
safety and panic-freedom of the strided recursion and the constructor's
`trailing_zeros` loop are proven exec twins; the twins' functional ensures
tie them to `fwd_spec` / `inv_spec` / `tw_sum`. `roundtrip` proves
`inverse ∘ forward == id` for **arbitrary** twiddle values and any `k`
(the multiply is never unfolded — a consistently wrong twiddle still
round-trips, and the negative control confirms only `fwd_semantics`
catches it). `fwd_semantics` proves the forward transform evaluates the
novel polynomial basis (`X_t = ∏ sigma^j`) at `coset + point(beta, i)`
over any Cantor chain satisfying the build-discharged hypotheses, for
every depth and coset; `sigma_point` carries the two-to-one descent.
Inverse semantics follow by composition with `roundtrip`.

Basis isomorphism discharged: `verify_isomorphism_128` checks, on the real
128-bit matrices, mutual inverse + the ring homomorphism on all 128² single-bit
generators (exhaustive), the tower product from the shared `gf_oracle::schoolbook128`,
the flat product from `pmod(clmul(·), x^128 + 0x87)` (the build-check row above ties
both to the Verus spec). That generator homomorphism is the axiom `phi_mult_gen`,
from which `phi_multiplicative` (all inputs) is now **proven** in `gf_model.rs`,
`linear_determined_field` extends it over the proven bilinearity of `gf_mul` /
`gf_mul_tower` and `phi_additive`. The old `verus/iso_ext.rs`, which proved the
same extension over disconnected uninterpreted symbols (11 axioms), is **deleted**.
Still trusted: `phi_roundtrip`, `phi_additive` (`phi` linear by construction), and
`phi_mult_gen` (generators, build-checked).

SpMV memory safety: the chunked loop is proven in `matrix.rs`, index
bounds, output-init before `set_len`, per-chunk write confinement, and
the `chunk_id * CHUNK_SIZE` dispatch arithmetic. The parallel path
shares all of it; only rayon's partition contract stays trusted (above).