//! STACKSAT-128
//! -------------
//! A 256-bit sponge hash specifically tailored for Bitcoin-Script friendliness.
//! Only 4-bit additions (mod 16), a 16-entry S-box and fixed stack shuffles are
//! required. No XOR, rotate, multiply, CAT, etc.
//!
//! • State  : 64 × 4-bit nibbles  (256 bit)
//! • Rate   : 32 nibbles          (128 bit)
//! • Rounds : 16
//!
//! Security target: >=128-bit collision & pre-image resistance.
//!
//! The design is an SPN: S-box -> Permute (RowRot+Transpose) -> Mix (Col Adds v3) -> Const.

/// PRESENT-style 4-bit S-box. Good differential/linear properties.
/// http://lightweightcrypto.org/present/
/// Andrey Bogdanov, Lars R. Knudsen, Gregor Leander, Christof Paar, Axel Poschmann, Matthew J. B. Robshaw,
/// Yannick Seurin, and C. Vikkelsoe. PRESENT: An Ultra-Lightweight Block Cipher.
/// #        0   1   2   3   4   5   6   7   8   9   a   b   c   d   e   f
const SBOX: [u8; 16] = [
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
];

/// 8x8 Row Rotation Permutation: Nibble at index `idx` moves to position `PERM_ROW_ROT[idx]`.
/// Row `r` is left-rotated by `r` positions.
const PERM_ROW_ROT: [usize; 64] = {
    let mut fwd_p = [0usize; 64];
    let mut idx = 0;
    while idx < 64 {
        let row = idx / 8;
        let col = idx % 8;
        // Calculate destination column after left-rotating row `r` by `r` positions.
        let dest_col = (col + 8 - row) % 8; // Position a nibble moves *to*
        let dest_idx = row * 8 + dest_col;
        fwd_p[idx] = dest_idx; // p[current_idx] = destination_idx
        idx += 1;
    }
    fwd_p
};

// Constants
const RATE_NIBBLES: usize = 32; // 128-bit rate (32 nibbles)
const STATE_NIBBLES: usize = 64; // 256-bit state (64 nibbles)
const ROUNDS: usize = 16; // Number of rounds
const DIGEST_BYTES: usize = 32; // 256-bit output digest

/// Add two 4-bit values modulo 16. Script: OP_ADD  OP_LESSTHAN OP_IF  OP_SUB OP_ENDIF
#[inline(always)]
fn add16(a: u8, b: u8) -> u8 {
    (a.wrapping_add(b)) & 0xF
}

/// 4-bit round-constant sequence (derived from x^4 + x + 1 LFSR, period 15).
const RC: [u8; ROUNDS] = {
    let mut rc = [0u8; ROUNDS];
    let mut lfsr_state = 1u8; // Start at 1 (non-zero)
    let mut i = 0;
    while i < ROUNDS {
        rc[i] = lfsr_state & 0xF; // Output the LFSR state bits
                                  // Advance LFSR state using x^4 + x + 1 feedback (Right shift style)
        let bit = ((lfsr_state >> 3) ^ (lfsr_state & 1)) & 1; // Feedback bit
        let next_state = (lfsr_state >> 1) | (bit << 3); // Shift right, insert feedback at MSB
        lfsr_state = if next_state == 0 { 1 } else { next_state }; // Avoid zero state
        i += 1;
    }
    // Ensure no zero constants (replace with 0xF if generated)
    i = 0;
    while i < ROUNDS {
        if rc[i] == 0 {
            rc[i] = 0xF;
        }
        i += 1;
    }
    rc
};

/// Apply one STACKSAT-128 round to the internal 64-nibble state.
fn round(st: &mut [u8; STATE_NIBBLES], r: usize) {
    // --- 1. S-box Layer ---------------------------------------------------
    // Script: Loop 64 times. Inside: stack ops to get nibble, push 16 SBOX vals, OP_PICK, cleanup.
    for b in st.iter_mut() {
        *b = SBOX[*b as usize];
    }

    // --- 2. Permutation Layer (Row Rotation + Matrix Transpose) -----------
    // Script: Needs careful stack manipulation sequences for RowRot then Transpose.
    // 2a. Apply Row Rotation permutation
    let mut permuted_state = [0u8; STATE_NIBBLES];
    for i in 0..STATE_NIBBLES {
        permuted_state[PERM_ROW_ROT[i]] = st[i]; // Apply forward permutation
    }

    // 2b. Apply Matrix Transpose (st[r][c] <=> st[c][r])
    let mut transposed_state = [0u8; STATE_NIBBLES];
    for r_idx in 0..8 {
        for c_idx in 0..8 {
            transposed_state[c_idx * 8 + r_idx] = permuted_state[r_idx * 8 + c_idx];
        }
    }
    *st = transposed_state; // State is now permuted

    // --- 3. Mixing Layer (Column Additive Mix) ----------------------------
    // Script: Loop 8 columns. Inner loop 8 rows. Needs stack ops (OP_PICK)
    // to read previous state values for calculation without consuming them yet.
    // Pattern: y[r][c] = x[r][c] + x[r+1][c] + x[r+2][c] + x[r+3][c] (indices mod 8)
    let prev_state = *st; // Read from state before this mixing step
    for c_idx in 0..8 {
        // Iterate through columns
        for r_idx in 0..8 {
            // Iterate through rows
            let idx0 = r_idx * 8 + c_idx;
            let idx1 = ((r_idx + 1) % 8) * 8 + c_idx;
            let idx2 = ((r_idx + 2) % 8) * 8 + c_idx;
            let idx3 = ((r_idx + 3) % 8) * 8 + c_idx;

            // Calculate sum: x[r] + x[r+1] + x[r+2] + x[r+3] (mod 16)
            let sum1 = add16(prev_state[idx0], prev_state[idx1]);
            let sum2 = add16(prev_state[idx2], prev_state[idx3]);
            let mixed_val = add16(sum1, sum2); // Total 3 additions per output nibble

            st[idx0] = mixed_val; // Write the new value into the state
        }
    }

    // --- 4. Round Constant Addition ---------------------------------------
    // Script: Get RC[r] (e.g., push const), get st[63] (e.g. OP_PICK), call add16 sub-script, store result.
    st[STATE_NIBBLES - 1] = add16(st[STATE_NIBBLES - 1], RC[r]);
}

/// Multi-rate padding: append 0x8 (nibble), zeros, then 0x1 (nibble).
/// Takes ownership and returns a new padded Vec.
fn pad(mut nibbles: Vec<u8>) -> Vec<u8> {
    nibbles.push(0x8); // Add padding byte
    while (nibbles.len() % RATE_NIBBLES) != (RATE_NIBBLES - 1) {
        nibbles.push(0x0); // Pad with zeros
    }
    nibbles.push(0x1); // Add final terminator byte
    debug_assert!(nibbles.len() % RATE_NIBBLES == 0);
    nibbles
}

/// Compute STACKSAT-128 hash of input message bytes; returns 32-byte digest.
pub fn stacksat_hash(msg: &[u8]) -> [u8; DIGEST_BYTES] {
    // --- 1. Message -> Nibble Vector ---
    let mut v: Vec<u8> = Vec::with_capacity(msg.len() * 2 + RATE_NIBBLES); // Pre-allocate rough size
    for &byte in msg {
        v.push(byte >> 4);
        v.push(byte & 0xF);
    }
    // Pad takes ownership and returns the padded vector
    let padded_nibbles = pad(v);

    // --- 2. Initialise State ---
    let mut st = [0u8; STATE_NIBBLES]; // All zeros IV

    // --- 3. Absorb Padded Message Blocks ---
    let mut chunk_start = 0;
    while chunk_start < padded_nibbles.len() {
        // Absorb one block (RATE_NIBBLES)
        // Script: Loop 32 times, OP_PICK msg nibble, OP_PICK state nibble, add16, store state nibble.
        for i in 0..RATE_NIBBLES {
            st[i] = add16(st[i], padded_nibbles[chunk_start + i]);
        }
        chunk_start += RATE_NIBBLES;

        // Apply the permutation rounds
        // Script: Unroll 16 rounds. Each round is a sequence of opcodes.
        for r in 0..ROUNDS {
            round(&mut st, r);
        }
    }

    // --- 4. Squeeze 256-bit Digest ---
    // Script: Loop 32 times, OP_PICK st[2i],  OP_LSHIFT, OP_PICK st[2i+1], OP_OR. Collect bytes.
    let mut out_digest = [0u8; DIGEST_BYTES];
    for (i, item) in out_digest.iter_mut().enumerate().take(DIGEST_BYTES) {
        let nibble_idx1 = i * 2;
        let nibble_idx2 = i * 2 + 1;
        *item = (st[nibble_idx1] << 4) | st[nibble_idx2];
    }
    out_digest
}

// -----------------------------------------------------------------------
//  TESTS
// -----------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sbox_metrics() {
        // Ensure SBOX is a permutation
        let mut seen = [false; 16];
        for &val in SBOX.iter() {
            assert!(
                !seen[val as usize],
                "SBOX is not a permutation, {} repeated",
                val
            );
            seen[val as usize] = true;
        }

        // Differential Uniformity
        let mut max_delta_count = 0u8;
        for input_diff in 1..16u8 {
            let mut counts = [0u8; 16];
            for x in 0..16u8 {
                let output_diff = SBOX[x as usize] ^ SBOX[(x ^ input_diff) as usize];
                counts[output_diff as usize] += 1;
            }
            if let Some(&max_for_input) = counts.iter().max() {
                max_delta_count = max_delta_count.max(max_for_input);
            }
        }
        assert_eq!(
            max_delta_count, 4,
            "S-box maximum differential count (delta) should be 4"
        );

        // Linearity
        let mut max_walsh_abs = 0i16;
        for a_mask in 1..16u8 {
            for b_mask in 1..16u8 {
                let mut bias: i16 = 0;
                for x in 0..16u8 {
                    let input_parity = (a_mask & x).count_ones() % 2;
                    let output_parity = (b_mask & SBOX[x as usize]).count_ones() % 2;
                    if input_parity == output_parity {
                        bias += 1;
                    } else {
                        bias -= 1;
                    }
                }
                max_walsh_abs = max_walsh_abs.max(bias.abs());
            }
        }
        assert_eq!(
            max_walsh_abs, 8,
            "S-box maximum Walsh spectrum value (abs) should be 8"
        );
    }

    // --- Diffusion Test Helpers ---
    const ROUNDS_EVAL: usize = 4; // Evaluate diffusion over 4 rounds

    /// Calculates the minimum number of differing output nibbles after ROUNDS_EVAL rounds,
    /// considering all single 16-bit input differences applied to the first 4 nibbles.
    fn min_final_diff_nibbles_after_4() -> usize {
        let mut min_diff_count = STATE_NIBBLES;

        for diff16bit in 1..=0xFFFFu16 {
            let mut st_a = [0u8; STATE_NIBBLES];
            let mut st_b = [0u8; STATE_NIBBLES];

            st_b[0] = (diff16bit & 0xF) as u8;
            st_b[1] = ((diff16bit >> 4) & 0xF) as u8;
            st_b[2] = ((diff16bit >> 8) & 0xF) as u8;
            st_b[3] = ((diff16bit >> 12) & 0xF) as u8;

            // Run both states through ROUNDS_EVAL rounds using the main round function
            for r in 0..ROUNDS_EVAL {
                round(&mut st_a, r);
                round(&mut st_b, r);
            }

            let mut final_diff_count = 0;
            for k in 0..STATE_NIBBLES {
                if st_a[k] != st_b[k] {
                    final_diff_count += 1;
                }
            }
            min_diff_count = min_diff_count.min(final_diff_count);
            if min_diff_count == 0 {
                break;
            }
        }
        min_diff_count
    }

    /// Diffusion test using the main round function.
    #[test]
    fn improved_round_diffusion_test() {
        let min_diff = min_final_diff_nibbles_after_4();
        // Assert minimum difference > half the state size for good avalanche.
        assert!(
            min_diff > (STATE_NIBBLES / 2),
            "Diffusion potentially too low: minimum differing nibbles ({}) <= half state size ({}) after {} rounds",
            min_diff,
            STATE_NIBBLES / 2,
            ROUNDS_EVAL
        );
        // Check the result from the previous successful run
        assert!(
            min_diff >= 43, // Keep the original check
            "Diffusion result ({}) is lower than previous successful run (43)",
            min_diff
        );
    }

    /// Basic hash functionality tests
    #[test]
    fn test_basic_hash() {
        let msg1 = b"";
        let msg2 = b"abc";
        let msg3 = b"The quick brown fox jumps over the lazy dog";

        let digest1 = stacksat_hash(msg1);
        let digest2 = stacksat_hash(msg2);
        let digest3 = stacksat_hash(msg3);

        assert_ne!(digest1, digest2, "Hash('') should differ from Hash('abc')");
        assert_ne!(
            digest2, digest3,
            "Hash('abc') should differ from Hash('long...')"
        );
    }

    #[test]
    fn test_empty_message() {
        let msg = b"";
        let digest = stacksat_hash(msg);
        let expected_hash = "bb04e59e240854ee421cdabf5cdd0416beaaaac545a63b752792b5a41dd18b4e";
        assert_eq!(hex::encode(digest), expected_hash);
    }

    /// Check the generated round constants
    #[test]
    fn test_lfsr_constants() {
        assert_eq!(RC.len(), ROUNDS);
        // Check against the sequence *actually* generated by the LFSR code:
        // 1, 8, 12, 14, 15, 7, 11, 5, 10, 13, 6, 3, 9, 4, 2, (repeats 1)
        let expected_sequence = [1, 8, 12, 14, 15, 7, 11, 5, 10, 13, 6, 3, 9, 4, 2, 1];
        for i in 0..ROUNDS {
            assert_eq!(
                RC[i], expected_sequence[i],
                "Mismatch in LFSR constant at round {}: expected {}, got {}",
                i, expected_sequence[i], RC[i]
            );
        }
        // Check for zero constants (should have been avoided)
        assert!(RC.iter().all(|&c| c != 0), "Zero constant found in RC");
    }
}
