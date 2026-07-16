# hekate-math

[![Crates.io](https://img.shields.io/crates/v/hekate-math.svg)](https://crates.io/crates/hekate-math)
[![Docs.rs](https://docs.rs/hekate-math/badge.svg)](https://docs.rs/hekate-math)
[![CI](https://github.com/oumuamua-labs/hekate-math/actions/workflows/ci.yml/badge.svg)](https://github.com/oumuamua-labs/hekate-math/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache2-yellow.svg)](./LICENSE)

*Copyright (c) Andrei Kochergin and Oumuamua Labs.*

Hardware-accelerated binary tower fields for zero-knowledge proofs.

`hekate-math` provides a high-performance, constant-time implementation of binary tower fields (𝔽(2^k))
optimized for Sumcheck, GKR-based provers, and Binius protocols. The library implements a rigorous algebraic tower
construction up to 𝔽(2^256), leveraging basis isomorphism to utilize native CPU hardware instructions:
PMULL (ARMv8 NEON) and PCLMULQDQ (x86_64 AVX2).

Designed for low-level cryptographic engineering, the crate is `no-std` compatible and defaults to constant-time
(unproved yet) execution paths to mitigate side-channel attacks. It enforces strict type safety between canonical
(tower) and polynomial (flat/hardware) representations.

This is the mathematical core of the [Hekate ZK Engine](https://github.com/oumuamua-labs/hekate).

---

## ⚠️ Security Warning

This crate has not been independently audited and may contain bugs and security flaws.

USE AT YOUR OWN RISK!

---

## Performance Metrics

> [!NOTE]
> Current benchmarks are reported with the `table-math` feature enabled
> to reflect peak performance for public-data scenarios. For private-key
> operations, use the default constant-time backend.

Benchmarks executed on *Apple M3 Max*. The library achieves near-native memory
bandwidth saturation and single-cycle throughput for hardware-accelerated operations.

### Micro-Benchmarks (Block128)

| Operation                | Basis             | Latency  | Implementation                      |
|:-------------------------|:------------------|:---------|:------------------------------------|
| **Multiplication**       | Polynomial (Flat) | 1.08 ns  | `PMULL` (Pipelined)                 |
| **Multiplication**       | Tower (Canonical) | 98.3 ns  | Recursive Karatsuba                 |
| **Addition**             | Any               | 1.14 ns  | Vectorized XOR                      |
| **Inversion** (Single)   | Tower             | 246.6 ns | Itoh-Tsujii / Fermat Little Theorem |
| **Inversion** (Batch)    | Tower             | 15.7 ns  | Montgomery's Trick (SIMD)           |
| **Basis Conv** (Default) | Tower ↔ Flat      | 90.0 ns  | Bit-Slicing (Constant-Time)         |
| **Basis Conv** (Fast)    | Tower ↔ Flat      | 3.80 ns  | Look-Up Table (Variable-Time)       |

*Impact: Flat basis multiplication is approximately 100x faster than the canonical recursive implementation.*

### Polynomial Arithmetic (Poly ALU)

Efficiency of polynomial operations in 𝔽(2^128).

| Operation                 | Scenario / Size | Time     | Throughput  |
|:--------------------------|:----------------|:---------|:------------|
| **Dense Eval (Tower)**    | 2²⁰ coeffs      | 91.93 ms | 174 MiB/s   |
| **Dense Eval (Hardware)** | 2²⁰ coeffs      | 8.34 ms  | 1.87 GiB/s  |
| **Batch Eval (SIMD)**     | 256 × 16384     | 5.43 ms  | 772 Melem/s |
| **Additive FFT (scalar)** | 2¹⁶ · Block16   | 482.2 µs | 136 Melem/s |
| **Additive FFT (packed)** | 2¹⁶ · ×8 lanes  | 1.61 ms  | 326 Melem/s |
| **Interpolate MSM**       | 65536 points    | 77.12 µs | 850 Melem/s |
| **MLE Evaluation**        | 20 variables    | 1.27 ms  | 822 Melem/s |

Reproduce with `cargo bench` (constant-time default) or `cargo bench --features table-math`
(LUT basis conversion; hardware arithmetic is identical under both).

## Installation

```toml
[dependencies]
hekate-math = "0.9.0"
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

## Theoretical Foundation

`hekate-math` implements a binary tower field architecture. The field 𝔽(2^128)
is constructed via recursive quadratic extensions using the reduction polynomial v² + v + βᵢ.

The construction follows a strict recursive data layout. Higher-order blocks are composed
of two lower-order blocks (Low, High).

```plaintext
                    Block256 (GF(2^256))
                    /              \
              Block128              Block128 (GF(2^128))
                /    \              /     \
          Block64   Block64       ...     ...
           /    \
       Block32  Block32
        /    \
    Block16  Block16
     /    \
 Block8   Block8  (Base Field GF(2^8))
    |
  [Bit; 8]        (Atomic Unit GF(2))
```

The extension defines 𝔽(2^(2^(i+1))) ≅ 𝔽(2^(2^i))[v] / (v² + v + βᵢ),
where βᵢ is the extension constant (`EXTENSION_TAU`) for that level.

| Height | Field     | Implementation | Extension Constant (β)                        | Arithmetic            |
|:-------|:----------|:---------------|:----------------------------------------------|:----------------------|
| 0      | 𝔽₂       | `Bit`          | N/A                                           | Boolean (XOR/AND)     |
| 3      | 𝔽(2^8)   | `Block8`       | *Base Field* (AES Poly)                       | Recursive / Karatsuba |
| 4      | 𝔽(2^16)  | `Block16`      | 0x20 ∈ Block8                                 | Recursive / Karatsuba |
| 5      | 𝔽(2^32)  | `Block32`      | 0x2000 ∈ Block16                              | Recursive / Karatsuba |
| 6      | 𝔽(2^64)  | `Block64`      | 0x20000000 ∈ Block32                          | Recursive / Karatsuba |
| 7      | 𝔽(2^128) | `Block128`     | 0x2000000000000000 ∈ Block64                  | Recursive / Karatsuba |
| 8      | 𝔽(2^256) | `Block256`     | 0x20000000000000000000000000000000 ∈ Block128 | Recursive / Karatsuba |

*Note: The tower is rooted at F(2^8) (AES Field) for hardware compatibility. Lower fields (Bit)
are subfields embedded via isomorphism, making this a Hybrid Tower construction.*

## The Isomorphic Basis Architecture

To bridge the gap between algebraic recursion and CPU pipeline efficiency, `hekate-math` implements a hybrid basis
system. Canonical values stay in `F`, while hardware/polynomial values are represented explicitly as `Flat<F>`.

### Canonical Basis (Tower)

The default representation optimized for recursive algebraic operations. Elements
are structured as linear polynomials A(v) = a₁v + a₀ over the subfield.

* Recursive coefficients (a_hi, a_lo).
* Karatsuba Multiplication (3 sub-multiplications).
* Standard layout (Little-Endian).

### Polynomial Basis (Flat)

An isomorphic representation mapping the tower structure to a dense polynomial
basis (1, x, x²...) optimized for specific CPU instruction sets (AES-NI, PMULL, PCLMULQDQ).

* Linear bit-packed integers (`u8`, `u64`, `u128`).
* Single-cycle Carry-Less Multiplication (`CLMUL`) with hardware-accelerated reduction.
* 1.17ns per multiplication (Block128 on modern architectures).

### Isomorphism & Interop

The crate strictly enforces basis separation through the type system to prevent mixing representations.

The Isomorphism φ is defined as: φ: 𝔽(Tower) ↔ 𝔽(Hardware)

```rust
pub trait HardwareField: TowerField + PackableField {
    fn to_hardware(self) -> Flat<Self>;
    fn from_hardware(value: Flat<Self>) -> Self;
    fn add_hardware(lhs: Flat<Self>, rhs: Flat<Self>) -> Flat<Self>;
    fn mul_hardware(lhs: Flat<Self>, rhs: Flat<Self>) -> Flat<Self>;
    fn tower_bit_from_hardware(value: Flat<Self>, bit_idx: usize) -> u8;
}
```

*Change-of-basis matrices are pre-computed constant-time bit-sliced operations by default, with an optional
`table-math` feature for cached lookups.*

## Security Model

The crate operates under a configurable security model designed for cryptographic contexts where secret-dependent
execution time is catastrophic.

| Feature Flag       | Behavior                | Use Case                 | Security                          |
|:-------------------|:------------------------|:-------------------------|:----------------------------------|
| `default-features` | Bitsliced Constant-Time | Private Key / Prover     | **High** (Side-Channel Resistant) |
| `table-math`       | Cached Lookup Tables    | Public Verifier / Rollup | Low (Variable Access Time)        |
| `table-math`       | Cached Lifting Tables   | Public Data Ingestion    | Low (Variable Access Time)        |

* **Basis Conversion**: By default, φ and φ⁻¹ are computed using constant-time bit-sliced matrix
  multiplication, independent of the input value.
* **Hardware Arithmetic**: `Block128` multiplication utilizes carry-less multiplication instructions (`PMULL` on ARMv8,
  `PCLMULQDQ` on x86_64), which are constant-latency on modern microarchitectures.

## Hardware Support

| Architecture | Feature Requirement | Instructions Used       | Status            |
|:-------------|:--------------------|:------------------------|:------------------|
| **aarch64**  | `neon`, `pmull`     | `vmull_p64`, `veorq_u8` | Production        |
| **x86_64**   | N/A                 | `xor`, `sw_mul`         | Development       |
| **WASM**     | `simd128`           | `v128.xor`, `sw_mul`    | Software Fallback |

*Note: Native AVX2/PCLMULQDQ implementation for x86_64 is on the roadmap.*

## Roadmap

- **x86_64 Hardware Acceleration (0 -> 1)**
    - Replace software fallbacks with hand-tuned assembly/intrinsics for AVX2 and PCLMULQDQ.
    - Goal: Path to x86_64 Supremacy.

## License

Licensed under Apache 2.0. See the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.
