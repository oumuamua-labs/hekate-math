# hekate-math

[![Crates.io](https://img.shields.io/crates/v/hekate-math.svg)](https://crates.io/crates/hekate-math)
[![Docs.rs](https://docs.rs/hekate-math/badge.svg)](https://docs.rs/hekate-math)
[![CI](https://github.com/oumuamua-labs/hekate-math/actions/workflows/ci.yml/badge.svg)](https://github.com/oumuamua-labs/hekate-math/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache2-yellow.svg)](./LICENSE)

*Copyright (c) Andrei Kochergin and Oumuamua Labs.*

Formally verified, hardware-accelerated binary tower fields for zero-knowledge proofs.

`hekate-math` runs the tower to 𝔽(2^256) for Sumcheck, GKR-based provers, and Binius
protocols. A basis isomorphism maps tower elements onto CPU carry-less multiply
instructions: PMULL (ARMv8 NEON) and PCLMULQDQ (x86_64 AVX2).

`no-std` compatible. Default execution paths are constant-time (unproved) against side-channel
attacks. The type system separates canonical (tower) from polynomial (flat/hardware) representations.

This is the mathematical core of the [Hekate ZK Engine](https://github.com/oumuamua-labs/hekate).

---

## ⚠️ Security Warning

This crate has not been independently audited and may contain bugs and security flaws.

USE AT YOUR OWN RISK!

---

## Performance Metrics

> [!NOTE]
> Tables below are the `table-math` build. That feature uses lookup
> tables for basis conversion, lifting, and the GF(2^8) leaf arithmetic.
> Tower rows are slower under the default constant-time build;
> flat/hardware rows are identical. Private witness data: use the default.

Benchmarks executed on *Apple M3 Max*.

### Micro-Benchmarks (Block128)

| Operation                | Basis             | Latency  | Implementation                      |
|:-------------------------|:------------------|:---------|:------------------------------------|
| **Multiplication**       | Polynomial (Flat) | 0.90 ns  | `PMULL` (Pipelined)                 |
| **Multiplication**       | Tower (Canonical) | 16.6 ns  | Basis isomorphism + `PMULL`         |
| **Addition**             | Any               | 1.15 ns  | Vectorized XOR                      |
| **Inversion** (Single)   | Tower             | 106.2 ns | Itoh-Tsujii / Fermat Little Theorem |
| **Inversion** (Batch)    | Tower             | 15.6 ns  | Montgomery's Trick (SIMD)           |
| **Basis Conv** (Default) | Tower ↔ Flat      | 84.9 ns  | Bit-Slicing (Constant-Time)         |
| **Basis Conv** (Fast)    | Tower ↔ Flat      | 3.68 ns  | Look-Up Table (Variable-Time)       |

*Flat multiplication is ~18× faster than the canonical path.*

### Polynomial Arithmetic (Poly ALU)

Efficiency of polynomial operations in 𝔽(2^128).

| Operation                 | Scenario / Size | Time     | Throughput   |
|:--------------------------|:----------------|:---------|:-------------|
| **Dense Eval (Tower)**    | 2²⁰ coeffs      | 23.7 ms  | 675 MiB/s    |
| **Dense Eval (Hardware)** | 2²⁰ coeffs      | 8.37 ms  | 1.87 GiB/s   |
| **Batch Eval (SIMD)**     | 256 × 16384     | 4.44 ms  | 945 Melem/s  |
| **Additive FFT (scalar)** | 2¹⁶ · Block16   | 477.7 µs | 137 Melem/s  |
| **Additive FFT (packed)** | 2¹⁶ · ×8 lanes  | 1.75 ms  | 300 Melem/s  |
| **Interpolate MSM**       | 65536 points    | 106.5 µs | 616 Melem/s  |
| **MLE Evaluation**        | 20 variables    | 1.00 ms  | 1.04 Gelem/s |

Reproduce with `cargo bench --features table-math`, or `cargo bench` for the default.

## Installation

```toml
[dependencies]
hekate-math = "0.11"
```

## Examples

### The Isomorphic Workflow

Most ZK protocols require transitioning between the **Canonical Basis** (for recursive
folding/sumcheck) and the **Polynomial Basis** (for heavy arithmetic).

```rust
use hekate_math::{Block128, HardwareField, TowerField};

fn example_isomorphism() {
    // Canonical Basis (Tower)
    let a_tower = Block128::from_uniform_bytes(&[0xaa; 32]);
    let b_tower = Block128::from_uniform_bytes(&[0xbb; 32]);

    // Basis Conversion -> Polynomial (Flat)
    let a_flat = a_tower.to_hardware();
    let b_flat = b_tower.to_hardware();

    // Hardware-Accelerated Arithmetic
    let c_flat = a_flat * b_flat;
    let d_flat = a_flat + b_flat;

    // Return to Canonical
    let c_tower = c_flat.to_tower();
    let d_tower = d_flat.to_tower();

    assert_eq!(
        c_tower,
        a_tower * b_tower,
        "Multiplication Homomorphism failed"
    );
    assert_eq!(d_tower, a_tower + b_tower, "Addition Homomorphism failed");
}
```

### SIMD Vectorization

For throughput-critical paths, `hekate-math` provides explicit SIMD packing via the `PackableField` trait.

```rust
use hekate_math::{Block32, Flat, HardwareField, PackableField, TowerField};

fn process_simd(data: &[Flat<Block32>]) {
    // Pack hardware-basis scalars into SIMD registers
    // PackedBlock32 holds 4 elements (128 bits total).
    let chunk_a = Flat::<Block32>::pack(&data[0..4]);
    let chunk_b = Flat::<Block32>::pack(&data[4..8]);

    // Vectorized Arithmetic:
    // Performs 4 parallel field
    // multiplications in the hardware basis.
    let result_packed = chunk_a * chunk_b;

    let mut out_flat = [Block32::ZERO.to_hardware(); 4];
    Flat::<Block32>::unpack(result_packed, &mut out_flat);

    for i in 0..4 {
        // Convert back to Canonical
        let res_tower = out_flat[i].to_tower();

        let a_tower = data[i].to_tower();
        let b_tower = data[4 + i].to_tower();

        assert_eq!(res_tower, a_tower * b_tower, "SIMD multiplication mismatch");
    }
}

fn example_simd() {
    let data: Vec<Flat<Block32>> = (0..8)
        .map(|i| Block32::from(i as u32 + 1).to_hardware())
        .collect();

    process_simd(&data);
}
```

### Additive FFT (Gao–Mateer, Cantor Basis)

In-place transforms over the 2^log_n-point subspace W_log_n,
`F: BinaryFieldExtras + HardwareField` (Block16 through Block128): forward evaluates
novel-basis coefficients, inverse interpolates. Scalar and packed (`F::WIDTH` lanes)
variants, each with a coset form. Buffers of 1 MiB and up run on Rayon (`parallel`
feature), bit-identical to serial.

`ReedSolomon<F>` builds systematic RS[n, k, n−k+1] on these transforms:
`encode(msg)[..k] == msg`.

```rust
use hekate_math::{AdditiveFft, Block16, Flat, HardwareField, TowerField};

fn example_fft() {
    let log_n = 10u32;
    let fft = AdditiveFft::<Block16>::new(log_n);

    // Novel-basis coefficients, hardware (flat) basis
    let coeffs: Vec<Flat<Block16>> = (0..1u32 << log_n)
        .map(|i| Block16::from(i).to_hardware())
        .collect();

    // Coefficients -> evaluations on W_10, in place
    let mut data = coeffs.clone();
    fft.forward_scalar(&mut data).unwrap();

    // Evaluations -> coefficients
    fft.inverse_scalar(&mut data).unwrap();

    assert_eq!(data, coeffs);
}
```

## Tower Construction

𝔽(2^(2^(i+1))) ≅ 𝔽(2^(2^i))[v] / (v² + v + βᵢ), where βᵢ is that level's
`EXTENSION_TAU`. Each block is a (Low, High) pair of the level below. The
tower is rooted at 𝔽(2^8) (AES field), not 𝔽₂: `Bit` is an embedded subfield,
making this a hybrid tower.

| Height | Field     | Implementation | Extension Constant (β)                        |
|:-------|:----------|:---------------|:----------------------------------------------|
| 0      | 𝔽₂       | `Bit`          | N/A                                           |
| 3      | 𝔽(2^8)   | `Block8`       | *Base field* (AES poly)                       |
| 4      | 𝔽(2^16)  | `Block16`      | 0x20 ∈ Block8                                 |
| 5      | 𝔽(2^32)  | `Block32`      | 0x2000 ∈ Block16                              |
| 6      | 𝔽(2^64)  | `Block64`      | 0x20000000 ∈ Block32                          |
| 7      | 𝔽(2^128) | `Block128`     | 0x2000000000000000 ∈ Block64                  |
| 8      | 𝔽(2^256) | `Block256`     | 0x20000000000000000000000000000000 ∈ Block128 |

## The Two Bases

φ: 𝔽(Tower) ↔ 𝔽(Hardware). Canonical values stay in `F`, hardware values in
`Flat<F>`. The two are distinct types; mixing them is a compile error.
Recursion is cheap in the first basis, CLMUL in the second. Change-of-basis
matrices are constant-time bit-sliced by default, cached lookups under `table-math`.

## Security Model

Timing behaviour is a build-time choice. Pick per deployment.

| Feature Flag       | Behavior                | Use Case                 | Security                          |
|:-------------------|:------------------------|:-------------------------|:----------------------------------|
| `default-features` | Bitsliced Constant-Time | Private Key / Prover     | **High** (Side-Channel Resistant) |
| `table-math`       | Cached Lookup Tables    | Public Verifier / Rollup | Low (Variable Access Time)        |
| `table-math`       | Cached Lifting Tables   | Public Data Ingestion    | Low (Variable Access Time)        |
| `table-math`       | GF(2^8) Log/Exp Tables  | Public Verifier / Rollup | Low (Index + Zero Branch)         |

* **Basis Conversion**: By default, φ and φ⁻¹ are computed using constant-time bit-sliced matrix
  multiplication, independent of the input value.
* **Hardware Arithmetic**: carry-less multiply (`PMULL`, `PCLMULQDQ`), constant-latency on current
  microarchitectures. `Block64::mul` takes it in every build, `Block128::mul` under `table-math`.
* **Tower Arithmetic**: `table-math` replaces `Block8::mul`, `square` and `mul_tau` with lookup
  tables and a zero-operand branch.

## Formal Verification

[`verus/`](verus/README.md) holds standalone [Verus](https://github.com/verus-lang/verus) proofs:
2079 obligations, 0 errors, 15 units. The tower `mul` cascade refines schoolbook GF(2^k) at every
level, the NEON flat kernels and constant-time basis conversions are proven equal to `gf_mul`, and
the additive FFT round-trips. Excluded from the crate build; run `verus/verify.sh`.

Trust boundary: four `external_body` axioms, each discharged by an exhaustive `build/main.rs`
check on every `cargo build`, plus the kernel↔twin transcription seams. `tests/neon_differential.rs`
covers the seams on silicon. Registered in [`verus/TRUSTED_AXIOMS.md`](verus/TRUSTED_AXIOMS.md).

## Hardware Support

| Architecture | Feature Requirement | Instructions Used                            | Status      |
|:-------------|:--------------------|:---------------------------------------------|:------------|
| **aarch64**  | `neon`, `aes`       | `pmull`/`pmull2`, `eor`, `ext`, `uzp`, `tbl` | Production  |
| **x86_64**   | N/A                 | `xor`, `sw_mul`                              | Development |

PMULL sits behind the `aes` target feature, off by default on
`aarch64-unknown-linux-gnu`. Without it the flat kernels take the
software path (constant-time under default features): same results,
lower throughput.

```bash
RUSTFLAGS="-C target-feature=+aes" cargo build --release
```

*Note: Native AVX2/PCLMULQDQ implementation for x86_64 is on the roadmap.*

## License

Licensed under Apache 2.0. See the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.
