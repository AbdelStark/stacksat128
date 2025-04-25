# STACKSAT-128 Hash Function

[![Crates.io](https://img.shields.io/crates/v/stacksat128.svg)](https://crates.io/crates/stacksat128)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**STACKSAT-128** is a 256-bit cryptographic hash function designed for resource-constrained environments, specifically **Bitcoin Script**. It aims to provide **128-bit security** against standard attacks (collision, preimage) while exclusively using operations efficient and available on the Bitcoin mainnet today.

## Motivation

Advanced Bitcoin protocols like BitVM, zero-knowledge proof verifiers often require cryptographic hashing directly within Bitcoin Script. However, Bitcoin Script lacks many fundamental operations (bitwise logic like XOR, shifts/rotations, concatenation) used by standard hashes like SHA-256, SHA-3, or BLAKE3. Emulating these operations in Script leads to extremely large and inefficient scripts (hundreds of kilobytes), hindering practical deployment. Conversely, ZK-friendly hashes (Poseidon, Rescue) rely heavily on finite field multiplication, also unavailable in Script.

STACKSAT-128 bridges this gap by constructing a secure hash function using _only_ the primitive operations available:

- Modular addition on small integers (4-bit nibbles).
- Small table lookups (16-entry S-box via `OP_PICK`).
- Stack manipulations (for data permutation).

## Design Highlights

STACKSAT-128 is built upon well-understood cryptographic principles (Sponge, SPN) but tailored for Script:

- **Sponge Construction:** Uses a 256-bit state with a 128-bit rate and 128-bit capacity. Absorbs padded message nibbles via `add16` (addition mod 16).
- **Nibble-Based:** Operates entirely on 4-bit nibbles, making operations map cleanly to small lookups and simple arithmetic.
- **SPN Permutation:** Employs a 16-round Substitution-Permutation Network. Each round consists of:
  1. **SubNibbles:** Applies a cryptographically strong 4-bit S-box (from PRESENT) to all 64 nibbles.
  2. **PermuteNibbles:** Shuffles nibble positions using a combination of row rotations (different for each row) and a full 8x8 matrix transpose.
  3. **MixColumns:** Provides diffusion using modular addition. Each nibble is updated based on the sum (`add16`) of 4 nibbles in its column from the state before this step (`y[r] = x[r] + x[r+1] + x[r+2] + x[r+3] mod 16`).
  4. **AddConstant:** Adds a round-specific 4-bit constant (derived from an LFSR) to the last nibble of the state to break symmetry.
- **Padding:** Uses standard 10\*1 multi-rate padding adapted for nibbles.
- **Output:** Produces a 256-bit (32-byte) digest.

## Bitcoin Script Focus

The primary goal is efficient implementation within Bitcoin Script (specifically Taproot scripts):

- `add16` maps to `OP_ADD`, `OP_LESSTHAN`, `OP_IF`, `OP_SUB`, `OP_ENDIF`.
- The 16-entry S-box maps to pushing 16 small constants and using `OP_PICK`.
- The permutation layer maps to sequences of stack operations (`OP_SWAP`, `OP_ROLL`, `OP_PICK`).
- The column mixing requires careful use of `OP_PICK` to access previous state values during computation.
- All rounds are unrolled, avoiding loops.

The target is for a full hash computation script to be significantly smaller and faster than scripted versions of SHA-256/BLAKE3, aiming for well under the 10KB Taproot limit. _Note: A full, optimized Bitcoin Script implementation is future work and necessary to confirm final size and performance._

## Security

- **Target:** 128-bit resistance against collision and (second) preimage attacks.
- **Principles:** Based on robust SPN and Sponge principles. Uses a well-analyzed S-box.
- **Diffusion:** Initial empirical tests on the reference implementation show good diffusion properties. Input differences applied to the first 16 bits result in an average of **43 out of 64 nibbles** differing after just 4 rounds (minimum found over all $2^{16}$ such differences). This suggests strong avalanche characteristics.
- **Disclaimer:** STACKSAT-128 is a **new cryptographic design**. While based on established principles and showing promising initial results, it **requires thorough public cryptanalysis** by experts to validate its security claims against all known and future attack vectors. **Use in production systems is not recommended without such review.**

## Status

- [x] Conceptual Design & Specification V0.1
- [x] Rust Reference Implementation (`no_std` compatible)
- [x] Basic Diffusion Testing (passing)
- [x] Test Vectors Generation (basic examples generated)
- [ ] Comprehensive Cryptanalysis (Seeking Review)
- [ ] Bitcoin Script Implementation & Benchmarking
- [ ] Further Optimizations

## Usage (Rust Crate)

Add the crate to your `Cargo.toml`:

```toml
[dependencies]
stacksat128 = "0.1.0" # Check crates.io for latest version
```

Example:

```rust
use stacksat128::stacksat_hash;

fn main() {
    let message = b"Hello, Bitcoin Script!";
    let digest = stacksat_hash(message);

    // Print as hex (requires `hex` crate)
    // println!("Message: {:?}", message);
    // println!("Digest: {}", hex::encode(digest));

    // Example Output (will change if algorithm updated):
    // Hash(''):       3d6a580b16379e75b15cf86e2a42189e634f5bd2b63fe18658891a24005f8dc0
    // Hash('abc'):     1eb95ba9134591818b1f4c6c2d1e6ea3562802812d8bf744f90ac513075db275

    // Use digest...
}
```

## Specification

The detailed algorithmic specification can be found in [SPECIFICATION.md](SPECIFICATION.md).

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
