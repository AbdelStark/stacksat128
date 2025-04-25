//! STACKSAT-128
//! -------------
//! A 256-bit sponge hash specifically tailored for Bitcoin-Script friendliness.
//! Only 4-bit additions (mod 16), a 16-entry S-box and fixed stack shuffles are
//! required. No XOR, rotate, multiply, CAT, etc.
//!
//! • State  : 64 × 4-bit nibbles  (256 bit)
//! • Rate   : 32 nibbles          (128 bit)
//! • Rounds : 16                  (Increased for better margin)
//!
//! Security target: >=128-bit collision & pre-image resistance.
//!
//! The design is an SPN: S-box -> Permute (RowRot+Transpose) -> Mix (Col Adds v3) -> Const.

//#![no_std]

/// PRESENT-style 4-bit S-box.
const SBOX: [u8; 16] = [
    // 0  1  2  3  4  5  6  7  8  9  A  B  C  D  E  F
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
];

/// 8x8 row-rotation permutation table (nibble indices).
/// Nibble at index `idx` moves to position `PERM_ROW_ROT[idx]`.
const PERM_ROW_ROT: [usize; 64] = {
    let mut fwd_p = [0usize; 64];
    let mut idx = 0;
    while idx < 64 {
        let row = idx / 8;
        let col = idx % 8;
        // Calculate destination column after left-rotating row `r` by `r` positions.
        let dest_col = (col + 8 - row) % 8; // Corrected left rotation by row index
        let dest_idx = row * 8 + dest_col;
        fwd_p[idx] = dest_idx; // p[current_idx] = destination_idx
        idx += 1;
    }
    fwd_p // Use the forward permutation
};

// Constants
const RATE_NIBBLES: usize = 32; // 128-bit rate
const STATE_NIBBLES: usize = 64; // 256-bit state
const ROUNDS: usize = 16; // Keep 16 rounds for now
const DIGEST_BYTES: usize = 32; // 256-bit output

/// Add two 4-bit values modulo 16.
#[inline(always)]
fn add16(a: u8, b: u8) -> u8 {
    (a.wrapping_add(b)) & 0xF // Use wrapping_add for clarity, then mask
}

/// 4-bit round-constant sequence (x^4 + x + 1 LFSR => period 15).
const RC: [u8; ROUNDS] = {
    let mut rc = [0u8; ROUNDS];
    let mut lfsr_state = 1u8; // Start at 1 (non-zero)
    let mut i = 0;
    while i < ROUNDS {
        rc[i] = lfsr_state & 0xF; // Output the LFSR state bits
        // Advance LFSR state (primitive polynomial x^4 + x + 1 over GF(2))
        let bit = ((lfsr_state >> 3) ^ (lfsr_state & 1)) & 1; // Feedback bit
        let next_state = (lfsr_state >> 1) | (bit << 3); // Shift right, insert feedback
        // Handle the all-zero state case if the polynomial is reducible (it isn't here)
        lfsr_state = if next_state == 0 { 1 } else { next_state }; // Should not happen for period 15 LFSR starting at 1
        i += 1;
    }
    // Ensure no zero constants if LFSR state happened to be zero (belt-and-braces)
    i = 0;
    while i < ROUNDS {
        if rc[i] == 0 {
            rc[i] = 0xF;
        } // Replace 0 with 15
        i += 1;
    }
    rc
};

/// Apply one improved round (v3) to the internal 64-nibble state.
fn stacksat_round(st: &mut [u8; STATE_NIBBLES], r: usize) {
    // --- 1. S-box Layer (unchanged) ---------------------------------------
    for b in st.iter_mut() {
        *b = SBOX[*b as usize];
    }

    // --- 2. Permutation Layer (Row Rotation + Matrix Transpose) -----------
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

    // --- 3. Mixing Layer (AES MixColumns inspired Additive version) -------
    // Update each nibble based on a sum of 4 nibbles in its column from the
    // state *before* this mixing step began.
    // Pattern: y[r] = x[r] + x[r+1] + x[r+2] + x[r+3] (indices mod 8)
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

    // --- 4. Round Constant Addition (unchanged) ---------------------------
    // Add RC[r] to the last nibble st[63]
    st[STATE_NIBBLES - 1] = add16(st[STATE_NIBBLES - 1], RC[r]);
}

/// Multi-rate padding: append 0x8 (nibble), zeros, then 0x1 (nibble).
/// Input `nibbles` is the message converted to nibbles.
/// Output is padded nibble vector.
fn pad(mut nibbles: heapless::Vec<u8, 512>) -> heapless::Vec<u8, 512> {
    // Append the '1' bit (using 0x8 nibble)
    let _ = nibbles.push(0x8); // Error ignored assuming capacity is sufficient

    // Pad with 0x0 nibbles until length is 1 nibble short of a multiple of RATE
    while (nibbles.len() % RATE_NIBBLES) != (RATE_NIBBLES - 1) {
        let _ = nibbles.push(0x0);
    }

    // Append the final '1' bit marker (using 0x1 nibble)
    let _ = nibbles.push(0x1);

    debug_assert!(nibbles.len() % RATE_NIBBLES == 0); // Length must be multiple of rate
    nibbles
}

/// Compute STACKSAT-128 hash of input message bytes; returns 32-byte digest.
pub fn stacksat_hash(msg: &[u8]) -> [u8; DIGEST_BYTES] {
    // --- 1. Message -> Nibble Vector ---
    let mut v = heapless::Vec::<u8, 512>::new();
    for &byte in msg {
        v.push(byte >> 4).expect("Vec capacity exceeded"); // High nibble
        v.push(byte & 0xF).expect("Vec capacity exceeded"); // Low nibble
    }
    let padded_nibbles = pad(v);

    // --- 2. Initialise State ---
    let mut st = [0u8; STATE_NIBBLES]; // All zeros IV

    // --- 3. Absorb Padded Message Blocks ---
    let mut chunk_start = 0;
    while chunk_start < padded_nibbles.len() {
        // Absorb one block (RATE_NIBBLES)
        for i in 0..RATE_NIBBLES {
            st[i] = add16(st[i], padded_nibbles[chunk_start + i]);
        }
        chunk_start += RATE_NIBBLES;

        // Apply the permutation rounds (using v3)
        for r in 0..ROUNDS {
            stacksat_round(&mut st, r);
        }
    }

    // --- 4. Squeeze 256-bit Digest ---
    let mut out_digest = [0u8; DIGEST_BYTES];
    for i in 0..DIGEST_BYTES {
        // Combine two nibbles from the state into one byte
        let nibble_idx1 = i * 2;
        let nibble_idx2 = i * 2 + 1;
        // Output uses the entire state since output size = state size
        out_digest[i] = (st[nibble_idx1] << 4) | st[nibble_idx2];
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

        // Differential Uniformity (Max count for any input/output diff pair)
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

        // Linearity (Max bias of linear approximations) |sum((-1)^(a.x + b.S(x)))|
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
        let mut min_diff_count = STATE_NIBBLES; // Initialize to max possible

        // Iterate through all possible non-zero 16-bit differences (applied to nibbles 0-3)
        for diff16bit in 1..=0xFFFFu16 {
            let mut st_a = [0u8; STATE_NIBBLES]; // Reference state (all zeros)
            let mut st_b = [0u8; STATE_NIBBLES]; // State with initial difference

            // Apply the 16-bit difference to the first 4 nibbles of st_b
            st_b[0] = (diff16bit & 0xF) as u8;
            st_b[1] = ((diff16bit >> 4) & 0xF) as u8;
            st_b[2] = ((diff16bit >> 8) & 0xF) as u8;
            st_b[3] = ((diff16bit >> 12) & 0xF) as u8;

            // Run both states through ROUNDS_EVAL rounds using v3 round function
            for r in 0..ROUNDS_EVAL {
                stacksat_round(&mut st_a, r);
                stacksat_round(&mut st_b, r);
            }

            // Count the number of differing nibbles in the final state
            let mut final_diff_count = 0;
            for k in 0..STATE_NIBBLES {
                if st_a[k] != st_b[k] {
                    final_diff_count += 1;
                }
            }

            // Update the minimum count found so far
            min_diff_count = min_diff_count.min(final_diff_count);

            if min_diff_count == 0 {
                eprintln!(
                    "Error: Found zero difference propagation for input diff {:04x}",
                    diff16bit
                );
                break;
            }
        }
        min_diff_count
    }

    /// Diffusion test using the improved round function v3.
    #[test]
    fn improved_round_diffusion_test() {
        // Warning: This test takes significant time (~1-2 minutes in release mode).
        // Run with: cargo test --release improved_round_diffusion_test -- --nocapture
        let min_diff = min_final_diff_nibbles_after_4();

        println!(
            "\nDiffusion Test v3 ({} Rounds): Minimum differing output nibbles = {} / {}",
            ROUNDS_EVAL, min_diff, STATE_NIBBLES
        );

        // Assert minimum difference > half the state size for good avalanche.
        assert!(
            min_diff > (STATE_NIBBLES / 2),
            "Diffusion potentially too low: minimum differing nibbles ({}) <= half state size ({}) after {} rounds",
            min_diff,
            STATE_NIBBLES / 2,
            ROUNDS_EVAL
        );
    }

    /// Basic hash functionality tests
    #[test]
    fn test_basic_hash() {
        // Use a fixed message for reproducibility if needed later
        let msg1 = b"";
        let msg2 = b"abc";
        let msg3 = b"The quick brown fox jumps over the lazy dog";

        let digest1 = stacksat_hash(msg1);
        let digest2 = stacksat_hash(msg2);
        let digest3 = stacksat_hash(msg3);

        println!("Hash(''):       {:02x?}", digest1);
        println!("Hash('abc'):     {:02x?}", digest2);
        println!("Hash('long...'): {:02x?}", digest3);

        // Basic sanity checks
        assert_ne!(digest1, digest2, "Hash('') should differ from Hash('abc')");
        assert_ne!(
            digest2, digest3,
            "Hash('abc') should differ from Hash('long...')"
        );

        // Example of checking against a known value (if available)
        // let expected_hex = "c31f..."; // Replace with actual expected hex
        // let calculated_hex = digest1.iter().map(|b| format!("{:02x}", b)).collect::<String>();
        // assert_eq!(calculated_hex, expected_hex, "Hash('') mismatch");
    }

    /// Check the generated round constants
    #[test]
    fn test_lfsr_constants() {
        println!("Round Constants ({} rounds): {:?}", ROUNDS, RC);
        assert_eq!(RC.len(), ROUNDS);
        // Check properties of the chosen LFSR sequence (period 15 for x^4+x+1)
        let expected_lfsr_seq_15 = [1, 2, 4, 8, 3, 6, 12, 11, 5, 10, 7, 14, 15, 13, 9];
        for i in 0..ROUNDS {
            // Compare against the expected sequence, wrapping around if ROUNDS > 15
            let expected_val = expected_lfsr_seq_15[i % 15];
            assert_eq!(
                RC[i], expected_val,
                "Mismatch in LFSR constant at round {}: expected {}, got {}",
                i, expected_val, RC[i]
            );
        }
        // Check for zero constants (should have been avoided by the logic)
        assert!(RC.iter().all(|&c| c != 0), "Zero constant found in RC");
    }
}
