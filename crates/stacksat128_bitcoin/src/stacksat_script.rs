//! STACKSAT-128 Bitcoin Script Implementation

use bitcoin::hex::FromHex;
// Only import opcodes used directly in script! macros outside helpers
use bitcoin_script_stack::stack::{StackTracker, StackVariable};

pub use bitcoin_script::builder::StructuredScript as Script;
pub use bitcoin_script::script;
use bitvm::bigint::U256;
use itertools::Itertools;

// --- Constants ---
const STACKSATSCRIPT_RATE_NIBBLES: usize = 32;
const STACKSATSCRIPT_STATE_NIBBLES: usize = 64;
const STACKSATSCRIPT_ROUNDS: usize = 16;
const STACKSATSCRIPT_EMPTY_MSG_HASH: &str =
    "bb04e59e240854ee421cdabf5cdd0416beaaaac545a63b752792b5a41dd18b4e";
const STACKSATSCRIPT_SBOX: [u8; 16] = [
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
];
const STACKSATSCRIPT_RC: [u8; STACKSATSCRIPT_ROUNDS] =
    [1, 8, 12, 14, 15, 7, 11, 5, 10, 13, 6, 3, 9, 4, 2, 1];

// --- Helper Scripts ---
fn add16_script() -> Script {
    script! { OP_ADD  OP_2DUP OP_LESSTHAN OP_IF OP_DROP OP_ELSE OP_SUB OP_ENDIF OP_DROP }
}

// --- Permutation Maps ---
const STACKSATSCRIPT_FINAL_PERM: [usize; STACKSATSCRIPT_STATE_NIBBLES] = {
    const PERM_ROW_ROT: [usize; STACKSATSCRIPT_STATE_NIBBLES] = {
        let mut fwd_p = [0usize; STACKSATSCRIPT_STATE_NIBBLES];
        let mut idx = 0;
        while idx < STACKSATSCRIPT_STATE_NIBBLES {
            let row = idx / 8;
            let col = idx % 8;
            let dest_col = (col + 8 - row) % 8;
            let dest_idx = row * 8 + dest_col;
            fwd_p[idx] = dest_idx;
            idx += 1;
        }
        fwd_p
    };
    let mut temp_state = [0usize; STACKSATSCRIPT_STATE_NIBBLES];
    let mut i = 0;
    while i < STACKSATSCRIPT_STATE_NIBBLES {
        temp_state[PERM_ROW_ROT[i]] = i;
        i += 1;
    }
    let mut current_perm_source = [0usize; STACKSATSCRIPT_STATE_NIBBLES];
    let mut r_idx = 0;
    while r_idx < 8 {
        let mut c_idx = 0;
        while c_idx < 8 {
            current_perm_source[c_idx * 8 + r_idx] = temp_state[r_idx * 8 + c_idx];
            c_idx += 1;
        }
        r_idx += 1;
    }
    let mut final_perm_calc = [0usize; STACKSATSCRIPT_STATE_NIBBLES];
    let mut dest_idx = 0;
    while dest_idx < STACKSATSCRIPT_STATE_NIBBLES {
        final_perm_calc[current_perm_source[dest_idx]] = dest_idx;
        dest_idx += 1;
    }
    final_perm_calc
};
const STACKSATSCRIPT_INV_FINAL_PERM: [usize; STACKSATSCRIPT_STATE_NIBBLES] = {
    /* ... unchanged ... */
    let mut inv_perm = [0usize; STACKSATSCRIPT_STATE_NIBBLES];
    let mut i = 0;
    while i < STACKSATSCRIPT_STATE_NIBBLES {
        inv_perm[STACKSATSCRIPT_FINAL_PERM[i]] = i;
        i += 1;
    }
    inv_perm
};

/// STACKSAT-128 implementation using StackTracker.
fn stacksat128(
    stack: &mut StackTracker,
    msg_len: u32,
    define_var: bool,
    _use_full_tables: bool,
    limb_len: u8,
) {
    // --- 0. Handle Empty Message Case --- (Unchanged)
    if msg_len == 0 {
        let empty_msg_hash_bytearray = <[u8; 32]>::from_hex(STACKSATSCRIPT_EMPTY_MSG_HASH).unwrap();

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

    // --- 1. Message Preparation and Padding --- (Unchanged)
    let msg_bytes_count = msg_len;
    let msg_nibbles_count = msg_len * 2;
    let mut message_vars: Vec<StackVariable>;
    println!("Debugging stack after step: 1. Message Preparation and Padding");
    stack.debug();
    let mut initial_byte_vars = Vec::with_capacity(msg_bytes_count as usize);
    for i in 0..msg_bytes_count {
        initial_byte_vars.push(stack.define(1, &format!("msg_byte_{}", msg_bytes_count - 1 - i)));
    }
    initial_byte_vars.reverse();
    let mut output_nibble_defs = Vec::new();
    for i in 0..msg_nibbles_count {
        output_nibble_defs.push((1u32, format!("msg_nibble_{}", i)));
    }
    output_nibble_defs.reverse();
    let transform_script = script!({ U256::transform_limbsize(limb_len as u32, 4) });
    message_vars = stack.custom_ex(transform_script, msg_bytes_count, output_nibble_defs, 0);
    message_vars.reverse();
    stack.number(8);
    message_vars.push(stack.define(1, "padding_start"));
    let current_len_after_8 = msg_nibbles_count as usize + 1;
    let len_including_final_1 = current_len_after_8 + 1;
    let zeros_needed_for_pad = (STACKSATSCRIPT_RATE_NIBBLES
        - (len_including_final_1 % STACKSATSCRIPT_RATE_NIBBLES))
        % STACKSATSCRIPT_RATE_NIBBLES;
    for i in 0..zeros_needed_for_pad {
        stack.number(0);
        message_vars.push(stack.define(1, &format!("padding_zero_{}", i)));
    }
    stack.number(1);
    message_vars.push(stack.define(1, "padding_end"));
    assert!(
        message_vars.len() % STACKSATSCRIPT_RATE_NIBBLES == 0,
        "Padding error: Total nibbles {} not divisible by rate {}",
        message_vars.len(),
        STACKSATSCRIPT_RATE_NIBBLES
    );
    let num_message_vars_total = message_vars.len();
    let num_blocks = message_vars.len() / STACKSATSCRIPT_RATE_NIBBLES;

    // --- 2. Initialize State and S-Box --- (Unchanged)
    stack.custom(
        script!(for &value in STACKSATSCRIPT_SBOX.iter() {
            {
                value
            }
        }),
        0,
        false,
        0,
        "push_sbox_table",
    );
    let sbox_table = stack.define(16, "sbox_table");
    let mut state_vars = Vec::with_capacity(STACKSATSCRIPT_STATE_NIBBLES);
    for i in 0..STACKSATSCRIPT_STATE_NIBBLES {
        stack.number(0);
        state_vars.push(stack.define(1, &format!("state_{}", i)));
    }
    state_vars.reverse();
    println!("Debugging stack after step: 2. Initialize State and S-Box");
    stack.debug();

    // --- 3. Process Message Blocks (Absorb -> Permute) ---
    for block_idx in 0..num_blocks {
        // --- 3a. Absorb Phase ---
        let mut absorbed_values = Vec::with_capacity(STACKSATSCRIPT_RATE_NIBBLES);
        for i in 0..STACKSATSCRIPT_RATE_NIBBLES {
            /* ... absorb calculation ... */
            let msg_idx = block_idx * STACKSATSCRIPT_RATE_NIBBLES + i;
            stack.copy_var(message_vars[msg_idx]);
            stack.copy_var(state_vars[i]);
            stack.custom(
                add16_script(),
                2,
                true,
                0,
                &format!("absorb_add_{}_{}", block_idx, i),
            );
            absorbed_values.push(stack.define(1, &format!("absorbed_{}_{}", block_idx, i)));
        }

        // *** Absorb Cleanup using move_var ***
        let mut next_state_vars_temp = absorbed_values.clone(); // Start building next state vector
        let old_state_capacity = state_vars.split_off(STACKSATSCRIPT_RATE_NIBBLES); // Isolate original capacity handles
                                                                                    // state_vars now holds handles for original rate [0..31]
        next_state_vars_temp.extend(old_state_capacity); // Add original capacity handles to new vector

        // Drop the original state rate nibbles using their original handles (now in state_vars)
        for i in (0..STACKSATSCRIPT_RATE_NIBBLES).rev() {
            stack.move_var(state_vars[i]); // Bring original state[i] to top
            stack.op_drop(); // Drop it
        }
        // Stack: ... msg ... sbox ... state_vars[32..63] absorbed_values[0..31] (top)

        state_vars = next_state_vars_temp; // Update main state_vars vector

        // Reorder stack: Move capacity block above rate block
        for i in 0..STACKSATSCRIPT_RATE_NIBBLES {
            stack.custom(
                script!(OP_ROLL),
                1,
                true,
                0,
                &format!("absorb_reorder_{}", i),
            );
        }
        // Stack: ... capacity[32..63] rate[0..31] (top = rate[31])

        // --- 3b. Permutation Phase (16 Rounds) ---
        for r in 0..STACKSATSCRIPT_ROUNDS {
            let initial_round_state_vars = state_vars.clone(); // *** Store handles at round start ***
            let mut next_state_vars = vec![StackVariable::null(); STACKSATSCRIPT_STATE_NIBBLES];

            // --- Round Step 1: SubNibbles --- (Unchanged)
            let mut sboxed_vars = Vec::with_capacity(STACKSATSCRIPT_STATE_NIBBLES);
            for i in 0..STACKSATSCRIPT_STATE_NIBBLES {
                let _ = stack.copy_var(state_vars[i]);
                stack.custom(
                    script! {  OP_SUB OP_PICK OP_SWAP OP_DROP },
                    1,
                    true,
                    0,
                    &format!("sbox_{}_{}", r, i),
                );
                sboxed_vars.push(stack.define(1, &format!("sbox_res_{}_{}", r, i)));
            }

            // --- Round Step 2: PermuteNibbles --- (Unchanged)
            let mut permuted_vars = vec![StackVariable::null(); STACKSATSCRIPT_STATE_NIBBLES];
            for dest_idx in 0..STACKSATSCRIPT_STATE_NIBBLES {
                let source_idx = STACKSATSCRIPT_INV_FINAL_PERM[dest_idx];
                let pick_depth = (STACKSATSCRIPT_STATE_NIBBLES - 1 - source_idx) as u32;
                let adjusted_pick_depth = pick_depth + (dest_idx as u32);
                stack.custom(
                    script!({ adjusted_pick_depth } OP_PICK),
                    0,
                    true,
                    0,
                    &format!("perm_pick_{}", dest_idx),
                );
                permuted_vars[dest_idx] = stack.define(1, &format!("perm_val_{}_{}", r, dest_idx));
            }

            // --- Round Step 3: MixColumns --- *** SIMPLIFIED ***
            let mut mixed_vars = vec![StackVariable::null(); STACKSATSCRIPT_STATE_NIBBLES];
            // No temporary result tracking needed
            for c_idx in 0..8 {
                for r_idx in 0..8 {
                    let current_target_idx = r_idx * 8 + c_idx;
                    let idx0 = r_idx * 8 + c_idx;
                    let idx1 = ((r_idx + 1) % 8) * 8 + c_idx;
                    let idx2 = ((r_idx + 2) % 8) * 8 + c_idx;
                    let idx3 = ((r_idx + 3) % 8) * 8 + c_idx;
                    let depth0 = (STACKSATSCRIPT_STATE_NIBBLES - 1 - idx0) as u32;
                    let depth1 = (STACKSATSCRIPT_STATE_NIBBLES - 1 - idx1) as u32;
                    let depth2 = (STACKSATSCRIPT_STATE_NIBBLES - 1 - idx2) as u32;
                    let depth3 = (STACKSATSCRIPT_STATE_NIBBLES - 1 - idx3) as u32;
                    let final_items_pushed =
                        mixed_vars.iter().filter(|v| !v.is_null()).count() as u32;

                    // Perform picks and adds implicitly, only define final result
                    stack.custom(script!({depth0+final_items_pushed} OP_PICK), 0, true, 0, ""); // p0
                    stack.custom(
                        script!({depth1+final_items_pushed+1} OP_PICK),
                        0,
                        true,
                        0,
                        "",
                    ); // p1
                    stack.custom(
                        script!({depth2+final_items_pushed+2} OP_PICK),
                        0,
                        true,
                        0,
                        "",
                    ); // p2
                    stack.custom(
                        script!({depth3+final_items_pushed+3} OP_PICK),
                        0,
                        true,
                        0,
                        "",
                    ); // p3
                       // Stack: ... mixed_vars[...] p0 p1 p2 p3 (top)
                    stack.custom(add16_script(), 2, true, 0, ""); // p2+p3 -> sum23 (on stack)
                    stack.custom(add16_script(), 2, true, 0, ""); // p0+p1 -> sum01 (on stack)
                                                                  // Stack: ... mixed_vars[...] sum23 sum01 (top)
                    stack.custom(add16_script(), 2, true, 0, ""); // sum01+sum23 -> final_mix (on stack)
                    let final_mix_val =
                        stack.define(1, &format!("mixed_{}_{}_{}", r, c_idx, r_idx)); // Define final result
                    mixed_vars[current_target_idx] = final_mix_val;
                }
            }
            // Stack: ... permuted ... mixed_vars[0..63] (top=mixed[63])
            // *** No cleanup needed for mix temps ***

            // --- Round Step 4: AddConstant --- (Unchanged)
            stack.number(STACKSATSCRIPT_RC[r] as u32);
            stack.custom(add16_script(), 2, true, 0, &format!("add_const_{}", r));
            let const_added_result = stack.define(1, &format!("const_added_{}", r));

            // Prepare next_state_vars vector (Unchanged)
            for i in 0..(STACKSATSCRIPT_STATE_NIBBLES - 1) {
                next_state_vars[i] = mixed_vars[i];
            }
            next_state_vars[STACKSATSCRIPT_STATE_NIBBLES - 1] = const_added_result;

            // --- Cleanup Intermediate States --- *** USE move_var ***
            // Drop permuted_vars block
            for i in (0..STACKSATSCRIPT_STATE_NIBBLES).rev() {
                stack.move_var(permuted_vars[i]);
                stack.op_drop();
            }
            // Drop sboxed_vars block
            for i in (0..STACKSATSCRIPT_STATE_NIBBLES).rev() {
                stack.move_var(sboxed_vars[i]);
                stack.op_drop();
            }
            // Drop original state_vars block (from round start)
            for i in (0..STACKSATSCRIPT_STATE_NIBBLES).rev() {
                stack.move_var(initial_round_state_vars[i]); // Use stored handles
                stack.op_drop();
            }
            // Stack: ... sbox ... mixed_result[0..63] (top = mixed_result[63])

            state_vars = next_state_vars; // Update state_vars for the next round
        } // End of round loop
    } // End of block processing loop

    println!("Debugging stack after step: 3. Process Message Blocks (Absorb -> Permute)");
    stack.debug();

    // --- 4. Finalize --- *** Use move_var for message, ROLL+DROP for SBox ***
    // Stack: ... msg_vars ... sbox_table ... final_state_vars[0..63] (top)
    // Drop sbox_table (Using ROLL+DROP as move_var on block handle is uncertain)
    let sbox_base_depth = STACKSATSCRIPT_STATE_NIBBLES as u32;
    for i in (0..16).rev() {
        let depth = sbox_base_depth + i as u32;
        stack.custom(
            script!({depth} OP_ROLL OP_DROP),
            1,
            false,
            0,
            &format!("finalize_drop_sbox_{}", i),
        );
    }

    // Drop message vars using move_var
    for i in (0..num_message_vars_total).rev() {
        // Drop msg[0]..msg[total-1]
        stack.move_var(message_vars[i]); // Use stored handles
        stack.op_drop();
    }
    // Stack: final_state_vars[0..63] (top = state_vars[63])
}

// --- Public Interface Functions --- (Remain Unchanged) ---

pub fn stacksat128_compute_script_with_limb(message_len: usize, limb_len: u8) -> Script {
    assert!(
        message_len <= 1024,
        "STACKSAT-128: Message length > 1024 bytes not supported"
    );
    let mut stack = StackTracker::new();
    stacksat128(&mut stack, message_len as u32, true, true, limb_len);
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

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::script::ScriptBuf;
    use bitvm::execute_script_buf;

    const STACKSAT_EMPTY_MSG_HASH: &str =
        "bb04e59e240854ee421cdabf5cdd0416beaaaac545a63b752792b5a41dd18b4e";
    /// Test empty message hash
    #[test]
    fn test_empty_message() {
        let expected_hash = <[u8; 32]>::from_hex(STACKSAT_EMPTY_MSG_HASH).unwrap();

        // Create compute script for empty message
        let compute_script = stacksat128_compute_script_with_limb(0, 8);
        let verify_script = stacksat128_verify_output_script(expected_hash);

        // Combine scripts
        let mut script_bytes = compute_script.compile().to_bytes();
        script_bytes.extend(verify_script.compile().to_bytes());

        // Execute combined script
        let script = ScriptBuf::from_bytes(script_bytes);
        let result = execute_script_buf(script);

        if !result.success {
            println!(
                "Empty message test failed:\nError: {:?}\nFinal Stack: {:?}",
                result.error, result.final_stack
            );
        }

        assert!(result.success, "Empty message test failed");
    }

    /// Test short message hash
    #[test]
    fn test_e2e() {
        let message =
            &hex::decode("0102030405060708090A0B0C0D0E0F10112233445566778899AABBCCDDEEFF00")
                .unwrap();
        let expected_hash = stacksat128::stacksat_hash(message);

        // Create scripts
        let push_script = stacksat128_push_message_script(message, 8);
        let compute_script = stacksat128_compute_script_with_limb(message.len(), 8);
        let verify_script = stacksat128_verify_output_script(expected_hash);

        // Combine scripts
        let mut script_bytes = push_script.compile().to_bytes();
        script_bytes.extend(compute_script.compile().to_bytes());
        script_bytes.extend(verify_script.compile().to_bytes());

        // Execute combined script
        let script = ScriptBuf::from_bytes(script_bytes);
        let result = execute_script_buf(script);

        if !result.success {
            println!(
                "Short message test failed:\nError: {:?}\nFinal Stack: {:?}",
                result.error, result.final_stack
            );
        }

        assert!(result.success, "Short message test failed");
    }

    /// Test one-block message hash
    #[test]
    fn test_one_block_message() {
        let message = b"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F";
        let expected_hash = [
            0x58, 0xa5, 0x4a, 0x30, 0xf1, 0x71, 0xc4, 0xce, 0x18, 0xf0, 0xa7, 0x54, 0xe5, 0xd0,
            0x96, 0x48, 0xde, 0x3e, 0x5c, 0xcb, 0xf3, 0xb9, 0xa7, 0x3a, 0x7a, 0x8e, 0x35, 0xe1,
            0x31, 0xfb, 0x60, 0x1e,
        ];

        // Create scripts
        let push_script = stacksat128_push_message_script(message, 8);
        let compute_script = stacksat128_compute_script_with_limb(message.len(), 8);
        let verify_script = stacksat128_verify_output_script(expected_hash);

        // Combine scripts
        let mut script_bytes = push_script.compile().to_bytes();
        script_bytes.extend(compute_script.compile().to_bytes());
        script_bytes.extend(verify_script.compile().to_bytes());

        // Execute combined script
        let script = ScriptBuf::from_bytes(script_bytes);
        let result = execute_script_buf(script);

        if !result.success {
            println!(
                "One block message test failed:\nError: {:?}\nFinal Stack: {:?}\nLast Opcode: {:?}",
                result.error, result.final_stack, result.last_opcode
            );
        }

        assert!(result.success, "One block message test failed");
    }

    /// Test standard vector from the spec
    #[test]
    fn test_standard_vector() {
        let message = b"The quick brown fox jumps over the lazy dog";
        let expected_hash = [
            0x85, 0xa9, 0x16, 0x26, 0x92, 0x50, 0xcc, 0x71, 0x7c, 0xd8, 0x7d, 0xd1, 0x61, 0x18,
            0x42, 0xe9, 0xd1, 0x73, 0xb0, 0x56, 0xc4, 0xcc, 0x0a, 0x0b, 0xea, 0x44, 0x59, 0xab,
            0xf5, 0x04, 0x84, 0x94,
        ];

        // Create scripts
        let push_script = stacksat128_push_message_script(message, 8);
        let compute_script = stacksat128_compute_script_with_limb(message.len(), 8);
        let verify_script = stacksat128_verify_output_script(expected_hash);

        // Combine scripts
        let mut script_bytes = push_script.compile().to_bytes();
        script_bytes.extend(compute_script.compile().to_bytes());
        script_bytes.extend(verify_script.compile().to_bytes());

        // Execute combined script
        let script = ScriptBuf::from_bytes(script_bytes);
        let result = execute_script_buf(script);

        if !result.success {
            println!(
                "Standard vector test failed:\nError: {:?}\nFinal Stack: {:?}\nLast Opcode: {:?}",
                result.error, result.final_stack, result.last_opcode
            );
        }

        assert!(result.success, "Standard vector test failed");
    }
}
