# hekate-math

[![Crates.io](https://img.shields.io/crates/v/hekate-math.svg)](https://crates.io/crates/hekate-math)
[![Docs.rs](https://docs.rs/hekate-math/badge.svg)](https://docs.rs/hekate-math)
[![CI](https://github.com/oumuamua-labs/hekate-math/actions/workflows/ci.yml/badge.svg)](https://github.com/oumuamua-labs/hekate-math/actions/workflows/ci.yml)
[![License: Apache 2.0](https://img.shields.io/badge/License-Apache2-yellow.svg)](./LICENSE)

*Copyright (c) Andrei Kochergin and Oumuamua Labs.*

Hardware-accelerated binary tower fields for zero-knowledge proofs.

`hekate-math` provides a high-performance, constant-time implementation of binary tower fields (𝔽(2^k))
optimized for GKR-based provers, Sumcheck, and Binius protocols. The library implements a rigorous algebraic tower
construction up to 𝔽(2^256), leveraging basis isomorphism to utilize native CPU hardware instructions:
PMULL (ARMv8 NEON) and PCLMULQDQ (x86_64 AVX2).

Designed for low-level cryptographic engineering, the crate is `no-std` compatible and defaults to constant-time
execution paths to mitigate side-channel attacks. It enforces strict type safety between canonical (tower) and
polynomial (flat/hardware) representations.

This is the mathematical core of the Hekate ZK Engine.

## Performance Metrics

> [!NOTE]
> Current benchmarks are reported with the `table-math` feature enabled
> to reflect peak performance for public-data scenarios. For private-key
> operations, use the default constant-time backend.

Benchmarks executed on **Apple M3 Max** (aarch64). The library achieves near-native memory
bandwidth saturation and single-cycle throughput for hardware-accelerated operations.

### Micro-Benchmarks (Block128)

| Operation                | Basis             | Latency     | Implementation                      |
|:-------------------------|:------------------|:------------|:------------------------------------|
| **Multiplication**       | Polynomial (Flat) | **1.08 ns** | `PMULL` (Pipelined)                 |
| **Multiplication**       | Tower (Canonical) | 98.3 ns     | Recursive Karatsuba                 |
| **Addition**             | Any               | 1.14 ns     | Vectorized XOR                      |
| **Inversion** (Single)   | Tower             | 246.6 ns    | Itoh-Tsujii / Fermat Little Theorem |
| **Inversion** (Batch)    | Tower             | 15.7 ns     | Montgomery's Trick (SIMD)           |
| **Basis Conv** (Default) | Tower ↔ Flat      | 90.0 ns     | Bit-Slicing (Constant-Time)         |
| **Basis Conv** (Fast)    | Tower ↔ Flat      | 3.80 ns     | Look-Up Table (Variable-Time)       |

*Impact: Flat basis multiplication is approximately **100x faster** than the canonical recursive implementation.*

### Polynomial Arithmetic (Poly ALU)

Efficiency of polynomial operations in 𝔽(2^128).

| Operation                 | Scenario / Size | Time        | Throughput     |
|:--------------------------|:----------------|:------------|:---------------|
| **Dense Eval (Tower)**    | 2²⁰ coeffs      | 91.93 ms    | 174 MiB/s      |
| **Dense Eval (Hardware)** | 2²⁰ coeffs      | **8.34 ms** | **1.87 GiB/s** |
| **Batch Eval (SIMD)**     | 256 × 16384     | 5.43 ms     | 772 Melem/s    |
| **FFT Layer (RAM)**       | 2²⁰ elements    | 909 µs      | 1.15 Gelem/s   |
| **FFT Layer (L1)**        | 256 elements    | 241 ns      | 1.06 Gelem/s   |
| **Interpolate MSM**       | 65536 points    | 77.12 µs    | 850 Melem/s    |
| **MLE Evaluation**        | 20 variables    | 1.27 ms     | 822 Melem/s    |

### Sparse Matrix-Vector Multiplication (SpMV)

Benchmarks for `Block128` SpMV with fixed degree 16 (typical for Brakedown/Binius).

| Matrix Size   | Time (M3 Max) | Throughput   | Memory Bandwidth (est.) |
|:--------------|:--------------|:-------------|:------------------------|
| **64K Rows**  | ~171 µs       | 6.14 Gelem/s | ~98 GB/s                |
| **256K Rows** | ~628 µs       | 6.68 Gelem/s | ~107 GB/s               |
| **1M Rows**   | ~5.17 ms      | 3.25 Gelem/s | ~52 GB/s                |

## Installation

```toml
[dependencies]
hekate-math = "0.5.0"
```

## Examples

### Basics: Field Arithmetic

* **Addition** is equivalent to XOR (`^`).
* **Subtraction** is identical to Addition (since -x = x).
* **1 + 1 = 0**. This is the defining property of Characteristic 2 fields.

```rust
use hekate_math::{Block128, TowerField};

fn example_basics() {
    // Initialize elements (Block128 represents GF(2^128))
    let a = Block128::from(5u128); // 101
    let b = Block128::from(3u128); // 011

    // 1. Addition is XOR
    // 5 XOR 3 = 6 (110)
    let sum = a + b;
    assert_eq!(sum, Block128::from(6u128));

    // 2. Characteristic 2 Property
    // Adding an element to itself results in Zero.
    let zero = a + a;
    assert_eq!(zero, Block128::ZERO);
    assert_eq!(Block128::from(5u128) - a, Block128::ZERO); // Subtraction is also XOR

    // 3. Multiplication
    // This uses Galois Field arithmetic
    // (carrying over the irreducible polynomial).
    let product = a * b;

    // In normal integers 5*3=15, but in GF(2^128)
    // it behaves differently based on reduction.
    println!("Basics: 5 * 3 in GF(2^128) = {:?}", product);
}
```

### The Isomorphic Workflow

Most ZK protocols require transitioning between the **Canonical Basis** (for recursive
folding/sumcheck) and the **Polynomial Basis** (for heavy arithmetic).

```rust
use hekate_math::{Block128, HardwareField, TowerField};

fn example_isomorphism() {
    // 1. Canonical Basis (Tower)
    let a_tower = Block128::from_uniform_bytes(&[0xaa; 32]);
    let b_tower = Block128::from_uniform_bytes(&[0xbb; 32]);

    // 2. Basis Conversion -> Polynomial (Flat)
    let a_flat = a_tower.to_hardware();
    let b_flat = b_tower.to_hardware();

    // 3. Hardware-Accelerated Arithmetic
    let c_flat = a_flat * b_flat;
    let d_flat = a_flat + b_flat;

    // 4. Return to Canonical Basis
    let c_tower = c_flat.to_tower();
    let d_tower = d_flat.to_tower();

    // 5. Verify Homomorphism
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
    // 1. Pack hardware-basis scalars into SIMD registers
    // PackedBlock32 holds 4 elements (128 bits total).
    // The data must already be in the Flat/Hardware
    // basis for hardware-accelerated operations
    // to be algebraically correct.
    let chunk_a = Flat::<Block32>::pack(&data[0..4]);
    let chunk_b = Flat::<Block32>::pack(&data[4..8]);

    // 2. Vectorized Arithmetic
    // Performs 4 parallel field
    // multiplications in the hardware basis.
    let result_packed = chunk_a * chunk_b;

    // 3. Unpack back to scalars
    let mut out_flat = [Block32::ZERO.to_hardware(); 4];
    Flat::<Block32>::unpack(result_packed, &mut out_flat);

    // 4. Verification
    for i in 0..4 {
        // Convert back to verify
        // against standard multiplication.
        let res_tower = out_flat[i].to_tower();

        // Manual tower multiplication for comparison
        let a_tower = data[i].to_tower();
        let b_tower = data[4 + i].to_tower();

        assert_eq!(res_tower, a_tower * b_tower, "SIMD multiplication mismatch");
    }
}

fn example_simd() {
    // Initialize data and immediately
    // transform to Hardware Basis.
    let data: Vec<Flat<Block32>> = (0..8)
        .map(|i| Block32::from(i as u32 + 1).to_hardware())
        .collect();

    process_simd(&data);
}
```

### Sparse Matrix-Vector Multiplication (SpMV)

A core primitive for Brakedown, Binius, and linear-code based commitments. The engine efficiently
promotes `u8` matrix weights to `Block128` on the fly using typed flat promotion (`FlatPromote`).

```rust
use hekate_math::matrix::ByteSparseMatrix;
use hekate_math::{Block128, Flat, HardwareField, TowerField};

fn example_spmv() {
    let rows = 1 << 20; // 1 Million Rows
    let cols = 1 << 20;
    let degree = 16; // Expansion factor (non-zeros per row)
    let seed = [42u8; 32];

    // 1. Generate Expander Graph
    // Weights are stored as u8 (1 byte)
    // to minimize RAM usage.
    let matrix = ByteSparseMatrix::generate_random(rows, cols, degree, seed);

    // 2. Prepare Input Vector (Hardware Basis)
    // Input must be in the flat basis
    // for hardware acceleration.
    let input: Vec<Flat<Block128>> = vec![Block128::ZERO.to_hardware(); cols];

    // 3. Execute SpMV
    // The engine handles lifting
    // u8 -> Block128 implicitly.
    let output = matrix.spmv(input.as_slice());

    assert_eq!(output.len(), rows);
}
```

## Roadmap

The immediate engineering focus is establishing absolute
hardware supremacy across both ARM and x86 backends.

- [ ] **x86_64 Hardware Acceleration (Beta → Prod)**
    - Replace software fallbacks with hand-tuned assembly/intrinsics for AVX2 and PCLMULQDQ.
    - **Goal**: Path to x86_64 Supremacy.

- [ ] **Formal Verification & Execution Path Auditing**
    - Mathematical modeling of execution boundaries and DoS-resistant state transitions.
    - **Goal**: Enforce strict `Result` propagation across all public interfaces for
      enterprise-grade fault tolerance.

## Theoretical Foundation

`hekate-math` implements a binary tower field architecture. The field 𝔽(2^128)
is constructed via recursive quadratic extensions using the reduction polynomial v² + v + βᵢ.

### The Tower Hierarchy

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

### Algebraic Construction

The extension defines 𝔽(2^(2^(i+1))) ≅ 𝔽(2^(2^i))[v] / (v² + v + βᵢ),
where βᵢ is the extension constant (`EXTENSION_TAU`) for that level.

| Height | Field     | Implementation | Extension Constant (β)                        | Arithmetic            |
|:-------|:----------|:---------------|:----------------------------------------------|:----------------------|
| h=0    | 𝔽₂       | `Bit`          | N/A                                           | Boolean (XOR/AND)     |
| h=3    | 𝔽(2^8)   | `Block8`       | *Base Field* (AES Poly)                       | Recursive / Karatsuba |
| h=4    | 𝔽(2^16)  | `Block16`      | 0x20 ∈ Block8                                 | Recursive / Karatsuba |
| h=5    | 𝔽(2^32)  | `Block32`      | 0x2000 ∈ Block16                              | Recursive / Karatsuba |
| h=6    | 𝔽(2^64)  | `Block64`      | 0x20000000 ∈ Block32                          | Recursive / Karatsuba |
| h=7    | 𝔽(2^128) | `Block128`     | 0x2000000000000000 ∈ Block64                  | Recursive / Karatsuba |
| h=8    | 𝔽(2^256) | `Block256`     | 0x20000000000000000000000000000000 ∈ Block128 | Recursive / Karatsuba |

*Note: The tower is rooted at F(2^8) (AES Field) for hardware compatibility. Lower fields (Bit)
are subfields embedded via isomorphism, making this a Hybrid Tower construction.*

## The Isomorphic Basis Architecture

To bridge the gap between algebraic recursion and CPU pipeline efficiency, `hekate-math` implements a hybrid basis
system. Canonical values stay in `F`, while hardware/polynomial values are represented explicitly as `Flat<F>`.

### Canonical Basis (Tower)

The default representation optimized for recursive algebraic operations (e.g., Sumcheck, GKR Layer folding). Elements
are structured as linear polynomials A(v) = a₁v + a₀ over the subfield.

* **Structure:** Recursive coefficients (a_hi, a_lo).
* **Operation:** Karatsuba Multiplication (3 sub-multiplications).
* **Memory:** Standard layout (Little-Endian).

### Polynomial Basis (Flat)

An isomorphic representation mapping the tower structure to a dense polynomial
basis (1, x, x²...) optimized for specific CPU instruction sets (AES-NI, PMULL, PCLMULQDQ).

* **Structure:** Linear bit-packed integers (`u8`, `u64`, `u128`).
* **Operation:** Single-cycle Carry-Less Multiplication (`CLMUL`) with hardware-accelerated reduction.
* **Throughput:** 1.17ns per multiplication (Block128 on modern architectures).

### Isomorphism & Interop

The library strictly enforces basis separation through the type system to prevent mixing representations.

The Isomorphism φ is defined as: φ: 𝔽(Tower) ↔ 𝔽(Hardware)

```rust
pub trait HardwareField: TowerField + PackableField {
    /// Transform Canonical -> Flat
    fn to_hardware(self) -> Flat<Self>;

    /// Transform Flat -> Canonical
    fn from_hardware(value: Flat<Self>) -> Self;

    /// Sum two elements assuming they
    /// are already in hardware basis.
    fn add_hardware(lhs: Flat<Self>, rhs: Flat<Self>) -> Flat<Self>;

    /// Multiply two elements assuming
    /// they are already in hardware basis.
    fn mul_hardware(lhs: Flat<Self>, rhs: Flat<Self>) -> Flat<Self>;

    /// Extract a bit of the Tower representation
    /// directly from the Hardware basis.
    fn tower_bit_from_hardware(value: Flat<Self>, bit_idx: usize) -> u8;
}
```

*Change-of-basis matrices are pre-computed constant-time bit-sliced operations by default, with an optional
`table-math` feature for cached lookups.*

## Implementation Details & Safety

`hekate-math` prioritizes correctness and side-channel resistance over "naive" speed, enforcing strict memory layouts
and algorithmic choices.

### Memory Layout & Type Safety

Field elements are zero-cost wrappers around native integer types, ensuring ABI compatibility and predictable register
usage.

* **Scalar Storage**: `#[repr(transparent)]` structs wrapping `u8`, `u16`, `u32`, `u64`, `u128`.
* **Vector Storage**: `#[repr(C, align(N))]` SIMD-packed structs (e.g., `PackedBlock128` is 32-byte aligned for
  AVX2/NEON compliance).
* **Safe Rust**: `unsafe` is restricted to SIMD intrinsics and bounds-checked lookups. Isomorphisms are checked via the
  `HardwareField` trait system.

### Security Model

The library operates under a configurable security model designed for cryptographic contexts where secret-dependent
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

## Reproduce benchmarks

> [!IMPORTANT]
> Hardware arithmetic performance (e.g., mul_hardware, add_hardware) remains identical
> regardless of the `table-math` feature. This feature specifically optimizes the Isomorphism
> (basis conversion) and Lifting operations. The actual field arithmetic in the flat basis
> always utilizes the fastest available hardware instructions (PMULL / PCLMULQDQ).

### Secure (Default)

Uses constant-time bitsliced matrix multiplication for basis conversion and lifting:

```bash
cargo bench
```

### Fast (table-math)

Uses precomputed lookup tables for basis conversion:

```bash
cargo bench --features table-math
```

## Security & Audits

> [!WARNING]
> This implementation is currently UNAUDITED.
>
> It is provided "AS IS" with ABSOLUTELY NO WARRANTY under the terms
> of the Apache 2.0 License. The authors assume zero liability for
> any damages arising from its use in production environments.

## License

Licensed under Apache 2.0. See the [LICENSE](LICENSE) and [NOTICE](NOTICE) files for details.
