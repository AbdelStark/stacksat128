use bitcoin::hex::FromHex;
use bitcoin_script_stack::stack::{StackTracker, StackVariable};

pub use bitcoin_script::builder::StructuredScript as Script;
pub use bitcoin_script::script;
use bitvm::bigint::U256;
use itertools::Itertools;

// Constants for STACKSAT-128
const RATE_NIBBLES: usize = 32; // 128-bit rate (32 nibbles)
const STATE_NIBBLES: usize = 64; // 256-bit state (64 nibbles)
const ROUNDS: usize = 16; // Number of rounds

// Hash value for empty message
const EMPTY_MSG_HASH: &str = "bb04e59e240854ee421cdabf5cdd0416beaaaac545a63b752792b5a41dd18b4e";

// PRESENT S-box values
const SBOX: [u8; 16] = [
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
];

// Round constants
const RC: [u8; ROUNDS] = [1, 8, 12, 14, 15, 7, 11, 5, 10, 13, 6, 3, 9, 4, 2, 1];

// STACKSAT-128 implementation
fn stacksat128(
    stack: &mut StackTracker,
    msg_len: u32,
    define_var: bool,
    _use_full_tables: bool,
    limb_len: u8,
) {
    // Special case for empty message
    if msg_len == 0 {
        let empty_msg_hash_bytearray = <[u8; 32]>::from_hex(EMPTY_MSG_HASH).unwrap();

        stack.custom(
            script!(
                // Push the hash value
                for byte in empty_msg_hash_bytearray {
                    {byte}
                }
                // Convert bytes to nibbles
                {U256::transform_limbsize(8, 4)}
            ),
            0,
            false,
            0,
            "push empty string hash in nibble form",
        );
        stack.define(8_u32 * 8, "stacksat128-hash");
        return;
    }

    // Validate input constraints
    assert!(
        msg_len <= 1024,
        "msg length must be less than or equal to 1024 bytes"
    );
    assert!(
        (4..32).contains(&limb_len),
        "limb length must be in the range [4, 32)"
    );

    // Convert message from limbs to nibbles if needed
    if define_var {
        stack.custom(
            script!({ U256::transform_limbsize(limb_len as u32, 4) }),
            0,
            false,
            0,
            "convert message to nibbles",
        );
    }

    // Define each nibble in the message
    let msg_nibbles = msg_len * 2; // Each byte = 2 nibbles
    let mut message = Vec::with_capacity(msg_nibbles as usize);

    for i in 0..msg_nibbles {
        message.push(stack.define(1, &format!("msg_nibble_{}", i)));
    }

    // Apply padding: 10*1 padding scheme
    // First padding nibble: 0x8
    stack.custom(script!(8), 0, false, 0, "padding_start");
    let padding_start = stack.define(1, "padding_start");
    message.push(padding_start);

    // Calculate needed zero padding
    let zeros_needed =
        (RATE_NIBBLES - 1 - ((msg_nibbles as usize) + 1) % RATE_NIBBLES) % RATE_NIBBLES;

    // Add zero padding nibbles
    if zeros_needed > 0 {
        stack.custom(
            script!(for _ in 0..zeros_needed {
                0
            }),
            0,
            false,
            0,
            "padding_zeros",
        );

        for i in 0..zeros_needed {
            let zero_pad = stack.define(1, &format!("padding_zero_{}", i));
            message.push(zero_pad);
        }
    }

    // Add final padding nibble: 0x1
    stack.custom(script!(1), 0, false, 0, "padding_end");
    let padding_end = stack.define(1, "padding_end");
    message.push(padding_end);

    // Push S-box lookup table onto stack
    stack.custom(
        script!(
            // Push S-box values in reverse order for easier lookup
            for &value in SBOX.iter().rev() {
                {
                    value
                }
            }
        ),
        0,
        false,
        0,
        "push_sbox_table",
    );

    let sbox_table = stack.define(16, "sbox_table");

    // Initialize the state (64 nibbles, all zeros)
    stack.custom(
        script!(for _ in 0..STATE_NIBBLES {
            0
        }),
        0,
        false,
        0,
        "init_state",
    );

    // Define state nibbles as stack variables
    let mut state = Vec::with_capacity(STATE_NIBBLES);
    for i in (0..STATE_NIBBLES).rev() {
        state.push(stack.define(1, &format!("state_{}", i)));
    }
    state.reverse(); // So state[0] is the first nibble

    // Process message blocks
    let total_nibbles = message.len();
    let num_blocks = (total_nibbles + RATE_NIBBLES - 1) / RATE_NIBBLES;

    // DEBUG
    println!("Starting Step 5: Processing message blocks");
    stack.debug();

    // For each block
    for block_idx in 0..num_blocks {
        // Absorb message block into state (first 32 nibbles)
        let block_start = block_idx * RATE_NIBBLES;
        let block_end = (block_idx + 1) * RATE_NIBBLES;
        let actual_end = block_end.min(total_nibbles);

        // Process each nibble in the block
        for i in 0..(actual_end - block_start) {
            let msg_idx = block_start + i;

            // Get message nibble and corresponding state nibble
            let msg_nibble = stack.copy_var(message[msg_idx]);
            let state_nibble = stack.copy_var(state[i]);

            // Add message to state nibble modulo 16
            stack.custom(
                script!(
                    // Addition modulo 16
                    OP_ADD
                    16
                    OP_LESSTHAN
                    OP_IF
                        // Sum < 16, keep as is
                    OP_ELSE
                        // Sum >= 16, subtract 16
                        16
                        OP_SUB
                    OP_ENDIF
                ),
                2,
                true,
                0,
                &format!("add16_{}", i),
            );

            // Update state with result
            let result = stack.define(1, &format!("absorbed_{}", i));
            state[i] = result;
        }

        println!("State after absorbing message block:");
        stack.debug();

        // Apply permutation rounds
        for round in 0..ROUNDS {
            // 1. SubNibbles: Apply S-box to all state nibbles
            for i in 0..STATE_NIBBLES {
                // Get nibble value
                let nibble = stack.copy_var(state[i]);

                // Get the corresponding S-box value
                stack.custom(
                    script!(
                        // S-box lookup using table
                        OP_DUP
                        {stack.get_offset(sbox_table)}
                        OP_ADD
                        OP_PICK
                    ),
                    1,
                    true,
                    0,
                    &format!("sbox_{}", i),
                );

                // Define the S-box result
                let sbox_result = stack.define(1, &format!("sbox_result_{}", i));
                state[i] = sbox_result;
            }

            // 2. PermuteNibbles: First row rotation, then transpose

            // Instead of using a complex operation that manipulates many variables,
            // we'll use a simpler approach that works directly on the stack

            // First, save the current state values to the alt stack
            let mut state_values = Vec::with_capacity(STATE_NIBBLES);
            for i in 0..STATE_NIBBLES {
                state_values.push(stack.copy_var(state[i]));
                stack.to_altstack();
            }

            // Now permute the values according to the row rotation + transpose
            for i in 0..STATE_NIBBLES {
                // Calculate where this nibble goes after permutation
                let row = i / 8;
                let col = i % 8;

                // Row rotation: rotate row by row positions left
                let rot_col = (col + 8 - row) % 8;
                let rot_idx = row * 8 + rot_col;

                // Matrix transpose: swap rows and columns
                let trans_row = rot_idx % 8;
                let trans_col = rot_idx / 8;
                let final_idx = trans_row * 8 + trans_col;

                // Retrieve value from altstack
                stack.from_altstack();

                // Define as new state value at permuted position
                let permuted = stack.define(1, &format!("permuted_{}", final_idx));
                state[final_idx] = permuted;
            }

            // 3. MixColumns: Add values in each column
            // Copy current state values to altstack for reference
            let mut prev_state = Vec::with_capacity(STATE_NIBBLES);
            for i in 0..STATE_NIBBLES {
                prev_state.push(stack.copy_var(state[i]));
                stack.to_altstack();
            }

            // Process each column
            for c in 0..8 {
                // For each row
                for r in 0..8 {
                    // Calculate indices for the 4 nibbles to mix
                    let idx0 = r * 8 + c;
                    let idx1 = ((r + 1) % 8) * 8 + c;
                    let idx2 = ((r + 2) % 8) * 8 + c;
                    let idx3 = ((r + 3) % 8) * 8 + c;

                    // Get the 4 values from altstack
                    stack.from_altstack(); // idx0
                    stack.from_altstack(); // idx1

                    // Add first two values modulo 16
                    stack.custom(
                        script!(
                            OP_ADD
                            16
                            OP_LESSTHAN
                            OP_IF
                                // Sum < 16, keep as is
                            OP_ELSE
                                // Sum >= 16, subtract 16
                                16
                                OP_SUB
                            OP_ENDIF
                        ),
                        2,
                        true,
                        0,
                        &format!("mix_sum1_{}", idx0),
                    );

                    let sum1 = stack.define(1, &format!("sum1_{}", idx0));

                    // Get the next two values
                    stack.from_altstack(); // idx2
                    stack.from_altstack(); // idx3

                    // Add the second two values modulo 16
                    stack.custom(
                        script!(
                            OP_ADD
                            16
                            OP_LESSTHAN
                            OP_IF
                                // Sum < 16, keep as is
                            OP_ELSE
                                // Sum >= 16, subtract 16
                                16
                                OP_SUB
                            OP_ENDIF
                        ),
                        2,
                        true,
                        0,
                        &format!("mix_sum2_{}", idx0),
                    );

                    let sum2 = stack.define(1, &format!("sum2_{}", idx0));

                    // Add the two sums modulo 16
                    stack.move_var(sum1);
                    stack.move_var(sum2);

                    stack.custom(
                        script!(
                            OP_ADD
                            16
                            OP_LESSTHAN
                            OP_IF
                                // Sum < 16, keep as is
                            OP_ELSE
                                // Sum >= 16, subtract 16
                                16
                                OP_SUB
                            OP_ENDIF
                        ),
                        2,
                        true,
                        0,
                        &format!("mix_final_{}", idx0),
                    );

                    // Update state with the mixed value
                    let mixed = stack.define(1, &format!("mixed_{}", idx0));
                    state[idx0] = mixed;
                }
            }

            // 4. AddConstant: Add round constant to last nibble
            let last_nibble = stack.copy_var(state[STATE_NIBBLES - 1]);

            // Push round constant
            stack.custom(script!({ RC[round] }), 0, true, 0, &format!("rc_{}", round));

            let rc = stack.define(1, &format!("rc_{}", round));

            // Add constant to last nibble modulo 16
            stack.move_var(last_nibble);
            stack.move_var(rc);

            stack.custom(
                script!(
                    OP_ADD
                    16
                    OP_LESSTHAN
                    OP_IF
                        // Sum < 16, keep as is
                    OP_ELSE
                        // Sum >= 16, subtract 16
                        16
                        OP_SUB
                    OP_ENDIF
                ),
                2,
                true,
                0,
                "add_constant",
            );

            // Update state with constant added
            let const_added = stack.define(1, "const_added");
            state[STATE_NIBBLES - 1] = const_added;
        }
    }

    // Drop the S-box table to save stack space
    stack.drop(sbox_table);

    // Extract final hash from state
    // For STACKSAT-128, the hash is the entire state
    // We need to move all state nibbles to the top of the stack
    for i in 0..STATE_NIBBLES {
        stack.move_var(state[i]);
    }

    // Define the final hash output
    stack.define(STATE_NIBBLES as u32, "stacksat128-hash");
}

// Public interface functions remain unchanged
pub fn stacksat128_compute_script_with_limb(message_len: usize, limb_len: u8) -> Script {
    assert!(
        message_len <= 1024,
        "This STACKSAT-128 implementation doesn't support messages longer than 1024 bytes"
    );
    let mut stack = StackTracker::new();
    let use_full_tables = true;
    let message_len = message_len as u32; // safety: message_len <= 1024 << u32::MAX
    stacksat128(&mut stack, message_len, true, use_full_tables, limb_len);
    stack.get_script()
}

pub fn stacksat128_push_message_script(message_bytes: &[u8], limb_len: u8) -> Script {
    assert!(
        message_bytes.len() <= 1024,
        "This STACKSAT-128 implementation doesn't support messages longer than 1024 bytes"
    );
    let chunks = chunk_message(message_bytes);

    script! {
        for chunk in chunks.into_iter().rev() {
            for (i, byte) in chunk.into_iter().enumerate() {
                {
                    byte
                }
                if i == 31 || i == 63 {
                    {
                        U256::transform_limbsize(8, limb_len as u32)
                    }
                }
            }
        }
    }
}

pub fn stacksat128_verify_output_script(expected_output: [u8; 32]) -> Script {
    script! {
        for (i, byte) in expected_output.into_iter().enumerate() {
            {byte}
            if i % 32 == 31 {
                {U256::transform_limbsize(8,4)}
            }
        }

        for i in (2..65).rev() {
            {i}
            OP_ROLL
            OP_EQUALVERIFY
        }
        OP_EQUAL
    }
}

fn chunk_message(message_bytes: &[u8]) -> Vec<[u8; 64]> {
    let len = message_bytes.len();
    let needed_padding_bytes = if len % 64 == 0 { 0 } else { 64 - (len % 64) };

    message_bytes
        .iter()
        .copied()
        .chain(std::iter::repeat(0u8).take(needed_padding_bytes))
        .chunks(4) // reverse 4-byte chunks
        .into_iter()
        .flat_map(|chunk| chunk.collect::<Vec<u8>>().into_iter().rev())
        .chunks(64) // collect 64-byte chunks
        .into_iter()
        .map(|mut chunk| std::array::from_fn(|_| chunk.next().unwrap()))
        .collect()
}

mod tests {
    use super::*;
    use bitcoin::ScriptBuf;
    use bitvm::execute_script_buf;

    #[test]
    fn test_compute_script() {
        let message: &str = "0102030405060708090A0B0C0D0E0F10112233445566778899AABBCCDDEEFF00";
        let message_bytes = hex::decode(message).unwrap();

        let limb_len = 4;
        let push_bytes = stacksat128_push_message_script(&message_bytes, limb_len)
            .compile()
            .to_bytes();
        let compute_bytes = stacksat128_compute_script_with_limb(message_bytes.len(), limb_len)
            .compile()
            .to_bytes();
        let mut combined_script_bytes = push_bytes;
        combined_script_bytes.extend(compute_bytes);

        let script = ScriptBuf::from_bytes(combined_script_bytes);
        let result = execute_script_buf(script);
        println!("Result: {:?}", result);
    }

    #[test]
    fn test_empty_message() {
        let message: &str = "";
        let message_bytes = hex::decode(message).unwrap();
        let limb_len = 4;
        let expected_output = <[u8; 32]>::from_hex(EMPTY_MSG_HASH).unwrap();
        let push_bytes = stacksat128_push_message_script(&message_bytes, limb_len)
            .compile()
            .to_bytes();
        let compute_bytes = stacksat128_compute_script_with_limb(message_bytes.len(), limb_len)
            .compile()
            .to_bytes();
        let mut combined_script_bytes = push_bytes;
        combined_script_bytes.extend(compute_bytes);
        combined_script_bytes.extend(
            stacksat128_verify_output_script(expected_output)
                .compile()
                .to_bytes(),
        );
        let script = ScriptBuf::from_bytes(combined_script_bytes);
        let result = execute_script_buf(script);
        println!("Result: {:?}", result);
    }

    #[test]
    fn test_e2e() {
        let message: &str = "0102030405060708090A0B0C0D0E0F10112233445566778899AABBCCDDEEFF00";
        let message_bytes = hex::decode(message).unwrap();
        let expected_hash = stacksat128::stacksat_hash(&message_bytes);
        println!("Message: {}", message);
        println!("Expected hash: {}", hex::encode(expected_hash));

        let limb_len = 4;
        let push_bytes = stacksat128_push_message_script(&message_bytes, limb_len)
            .compile()
            .to_bytes();
        let compute_bytes = stacksat128_compute_script_with_limb(message_bytes.len(), limb_len)
            .compile()
            .to_bytes();
        let mut combined_script_bytes = push_bytes;
        combined_script_bytes.extend(compute_bytes);
        combined_script_bytes.extend(
            stacksat128_verify_output_script(expected_hash)
                .compile()
                .to_bytes(),
        );
        let script = ScriptBuf::from_bytes(combined_script_bytes);
        let result = execute_script_buf(script);
        println!("Result: {:?}", result);
        assert_eq!(result.success, true);
    }
}
