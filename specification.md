# STACKSAT-128 Cryptographic Hash Function Specification

**Version:** 0.1-draft

**Date:** April 25, 2025

**Authors/Designers:** @AbdelStark

## 1. Introduction

STACKSAT-128 is a cryptographic hash function designed specifically for environments with highly constrained execution capabilities, particularly **Bitcoin Script** as implemented on the Bitcoin mainnet. It aims to provide **128-bit security** against both collision and (second) preimage attacks while using only operations readily available and efficient within Bitcoin Script, such as 4-bit modular addition, table lookups via stack indexing, and stack element manipulation.

The function produces a **256-bit (32-byte)** digest. It is based on the **sponge construction**, utilizing an internal **256-bit permutation** structured as a Substitution-Permutation Network (SPN).

This document provides a complete specification for implementation and analysis.

## 2. Definitions and Notation

- **Nibble:** A 4-bit unsigned integer (value 0-15).
- **Byte:** An 8-bit unsigned integer.
- **State:** The internal 256-bit state (`st`) is represented as an array of 64 nibbles, indexed from 0 to 63.
  `st = [st_0, st_1, ..., st_63]`
- **State Matrix:** For some operations, the state `st` is viewed as an 8x8 matrix of nibbles, where `st[r][c]` refers to the nibble at row `r` (0-7) and column `c` (0-7). The mapping from the linear index `i` (0-63) to matrix indices `(r, c)` is:
  `r = i / 8`
  `c = i % 8`
  `i = r * 8 + c`
- **Little-Endian Convention:** When converting between byte sequences and multi-byte words (though not heavily used internally), the least significant byte comes first. Input messages are treated as sequences of bytes.
- **Bit Ordering:** Within a byte, the most significant bit is considered bit 7, and the least significant bit is bit 0. When converting a byte to two nibbles, the high nibble corresponds to bits 7-4, and the low nibble corresponds to bits 3-0.
- `⊕`: Bitwise XOR operation (Note: Not used internally by STACKSAT-128, only for conceptual description or analysis).
- `+`: Addition of integers.
- `add16(a, b)`: Addition of two nibbles `a` and `b` modulo 16. Defined in Section 6.1.

## 3. Parameters

- **State Size:** 256 bits ( `STATE_NIBBLES = 64` nibbles).
- **Rate:** 128 bits ( `RATE_NIBBLES = 32` nibbles).
- **Capacity:** 128 bits ( `STATE_NIBBLES - RATE_NIBBLES = 32` nibbles).
- **Digest Size:** 256 bits ( `DIGEST_BYTES = 32` bytes).
- **Number of Rounds:** `ROUNDS = 16`.

## 4. Algorithm Specification

STACKSAT-128 uses the sponge construction. The core component is a 16-round permutation function, `StacksatPermutation`, applied to the 256-bit state.

### 4.1. Padding Scheme

Input messages are byte strings of arbitrary length. Before processing, the message `M` is converted into a sequence of nibbles and padded using a **multi-rate scheme (10\*1 padding)** adapted for nibbles:

1. **Byte-to-Nibble Conversion:** Convert the input byte string `M` into a nibble string `N`. For each byte `b` in `M`, append two nibbles to `N`: first `b >> 4` (high nibble), then `b & 0xF` (low nibble).
2. **Padding Application:**
    - Append a single nibble with value `0x8` (representing the '1' bit followed by three '0's) to the nibble string `N`.
    - Append zero or more nibbles with value `0x0` until the length of `N` is congruent to `RATE_NIBBLES - 1` (i.e., 31) modulo `RATE_NIBBLES` (32).
    - Append a single nibble with value `0x1` (representing the final '1' marker bit preceded by three '0's).
3. The resulting padded nibble string `P` will have a length that is a multiple of `RATE_NIBBLES` (32).

### 4.2. Sponge Construction

The hash computation proceeds as follows:

1. **Initialization:**

    - Initialize the 256-bit state `st` (64 nibbles) to all zeros.
      `st = [0, 0, ..., 0]`

2. **Absorbing Phase:**

    - Process the padded nibble string `P` in blocks of `RATE_NIBBLES` (32) nibbles. Let the blocks be $P_0, P_1, ..., P_{k-1}$.
    - For each block $P_j$:
      - Modify the first `RATE_NIBBLES` of the state by adding the block nibbles modulo 16:
        `st_i = add16(st_i, P_j[i])` for $i = 0$ to $RATE_NIBBLES - 1$.
      - Apply the core permutation to the entire state:
        `st = StacksatPermutation(st)`

3. **Squeezing Phase:**
    - After processing all blocks, the final state `st` contains the hash result.
    - Extract the full 256-bit state as the digest. Convert the 64 nibbles `st_0, ..., st_63` back into a 32-byte digest `D`. For $i = 0$ to $DIGEST_BYTES - 1$:
      `D[i] = (st_{2i} << 4) | st_{2i+1}`

### 4.3. Core Permutation: `StacksatPermutation`

The core permutation maps a 256-bit state to a 256-bit state by iterating the `round` function 16 times.

`StacksatPermutation(st)`:
For `r` from 0 to `ROUNDS - 1` (i.e., 0 to 15):
`st = round(st, r)`
Return `st`

### 4.4. Round Function: `round(st, r)`

Each round `r` (where `r` is the 0-indexed round number) applies four sequential transformations to the state `st`:

1. **`SubNibbles(st)`:** Apply the S-box substitution to each nibble of the state.
2. **`PermuteNibbles(st)`:** Apply a fixed permutation to the nibble positions.
3. **`MixColumns(st)`:** Apply an additive mixing operation across state columns.
4. **`AddConstant(st, r)`:** Add the round constant `RC[r]` to a specific nibble.

#### 4.4.1. SubNibbles Layer

This layer applies a fixed 4-bit S-box, `SBOX`, to each of the 64 nibbles in the state `st`.

`st_i = SBOX[st_i]` for $i = 0$ to 63.

The `SBOX` table contains a permutation of the values 0-15:

```text
Index: 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
Value: C  5  6  B  9  0  A  D  3  E  F  8  4  7  1  2
```

_(This is the S-box used in the PRESENT cipher)._

#### 4.4.2. PermuteNibbles Layer

This layer rearranges the positions of the 64 nibbles in the state according to a fixed permutation, achieved in two steps:

1. **Row Rotation:** View the state as an 8x8 matrix `st[row][col]`. Rotate the nibbles in row `r` left cyclically by `r` positions. The destination index `dest_idx` for a nibble currently at `current_idx = r * 8 + c` is given by:
    `dest_col = (c + r) % 8` (Note: Corrected from code which used `c - r`)
    `dest_idx = r * 8 + dest_col`
    Let `st'` be the state after row rotation. `st'[dest_idx] = st[current_idx]`.
    _(Alternatively, using the precomputed `PERM_ROW_ROT` table from the code: `st'[PERM_ROW_ROT[i]] = st[i]`)_
2. **Matrix Transpose:** Swap the rows and columns of the state matrix resulting from step 1. Let `st''` be the final state after transpose.
    `st''[c][r] = st'[r][c]` for all $r, c$ from 0 to 7.
    (Equivalent linear index form: `st''[c * 8 + r] = st'[r * 8 + c]`)

The final state after `PermuteNibbles` is `st''`.

#### 4.4.3. MixColumns Layer

This layer provides diffusion by mixing nibbles within columns using modular addition. It reads from the state _before_ modification within this layer (`prev_st`).

View the state `st` as an 8x8 matrix. For each column `c` (0-7):
For each row `r` (0-7):
Let `idx0 = r * 8 + c`
Let `idx1 = ((r + 1) % 8) * 8 + c`
Let `idx2 = ((r + 2) % 8) * 8 + c`
Let `idx3 = ((r + 3) % 8) * 8 + c`

Calculate the sum:
`sum1 = add16(prev_st[idx0], prev_st[idx1])`
`sum2 = add16(prev_st[idx2], prev_st[idx3])`
`mixed_val = add16(sum1, sum2)`

Update the state:
`st[idx0] = mixed_val`

_(Note: The `prev_st` implies that all reads for a column happen before any writes update that column, or that a temporary copy is used)._

#### 4.4.4. AddConstant Layer

A round-dependent constant `RC[r]` is added modulo 16 to the last nibble of the state.

`st[63] = add16(st[63], RC[r])`

The round constants `RC[0...15]` are generated using a 4-bit LFSR with polynomial $x^4 + x + 1$ (implemented via right shift and MSB feedback) starting from state 1. Any generated constant with value 0 is replaced by 0xF (15). The sequence is:

`RC = [1, 8, 12, 14, 15, 7, 11, 5, 10, 13, 6, 3, 9, 4, 2, 1]`

## 5. Helper Functions

### 5.1. `add16(a, b)`

Takes two nibbles `a` and `b` (integers 0-15) as input.
Returns `(a + b) mod 16`.

## 6. Test Vectors

> Calculated using the provided Rust reference implementation.

```json
[
  {
    "input": "",
    "output": "bb04e59e240854ee421cdabf5cdd0416beaaaac545a63b752792b5a41dd18b4e"
  },
  {
    "input": "616263",
    "output": "b96399c969ceea1288b30c1e82677189847c3c97d411eb4eb52cc942bb7854d8"
  },
  {
    "input": "54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f67",
    "output": "85a916269250cc717cd87dd1611842e9d173b056c4cc0a0bea4459abf5048494"
  }
]
```

Find the test vectors in the `test_vectors` directory of the repository.

Test vectors can be dynamically generated using the provided Rust reference implementation. The test vectors are generated by hashing the input strings and converting the output to hexadecimal format.

Generate test vectors using the following command:

```bash
cargo run --example test_vectors
```

## 7. Security Considerations

- **Target:** STACKSAT-128 targets 128-bit security against collision and (second) preimage attacks. The 256-bit state and output size provide the generic resistance levels for this target.
- **Design Principles:** The design follows the sponge construction and Substitution-Permutation Network (SPN) principles, which are well-studied.
- **Components:** The S-box is adopted from the PRESENT cipher and exhibits good resistance against standard differential and linear cryptanalysis. The permutation layer combines row rotation and matrix transpose for diffusion. The mixing layer uses modular addition, providing non-linearity via carries. Round constants are used to break symmetry.
- **Diffusion:** Preliminary empirical tests (checking the minimum number of differing nibbles after 4 rounds for 16-bit input differences) indicate good avalanche properties for the chosen 16-round structure with the specified mixing layer (`min_diff = 43/64`).
- **Further Analysis:** As a new design, STACKSAT-128 requires thorough third-party cryptanalysis to confirm its security against all known attack vectors, particularly focusing on the novel additive mixing layer combined with the specific permutation.
- **Side Channels:** This specification does not define countermeasures against side-channel attacks (e.g., timing, power analysis). Implementations in vulnerable environments may require additional masking or constant-time techniques.

## 8. Bitcoin Script Implementation Notes

STACKSAT-128 is designed for feasible implementation within Bitcoin Script limitations:

- **State Representation:** The 64 nibbles can be stored as 64 individual numbers (0-15) on the stack.
- **`add16`:** Implemented using `OP_ADD`, `<16>`, `OP_LESSTHAN`, `OP_IF`, `<16>`, `OP_SUB`, `OP_ENDIF`. This is compact.
- **`SubNibbles`:** Requires pushing the 16-entry `SBOX` table (using `OP_PUSHBYTES_1` or `OP_1`...`OP_16` if possible) and using `OP_PICK` based on the input nibble value. Optimization involves reusing the pushed table for multiple lookups via stack manipulation.
- **`PermuteNibbles`:** Requires implementing the Row Rotation and Matrix Transpose using sequences of stack manipulation opcodes (`OP_SWAP`, `OP_ROLL`, `OP_PICK`, potentially `OP_TUCK`, `OP_DUP`). This will be a significant part of the script size and requires careful optimization.
- **`MixColumns`:** Requires reading nibble values from the previous state (using `OP_PICK`) before they are overwritten. This necessitates careful stack management or potentially using the alternate stack (`OP_TOALTSTACK`/`OP_FROMALTSTACK`) for temporary storage during the column mixing calculation. It involves 3 `add16` calls per nibble (192 total per round).
- **`AddConstant`:** Requires pushing the specific `RC[r]` value and applying `add16` to the nibble at stack position corresponding to `st[63]`.
- **Control Flow:** The overall hash and the 16 rounds must be fully unrolled in the script, as loops are not available.
- **Size Target:** The estimated size per round needs careful implementation and optimization to fit 16 rounds within the ~10KB Taproot script limit.

---
