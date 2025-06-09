//! Fixed Optimized STACKSAT-128 Bitcoin Script Implementation
//! This version fixes compilation errors and works within your bitcoin_script constraints
use bitcoin::hex::FromHex;
use bitcoin_script_stack::stack::{StackTracker};

pub use bitcoin_script::builder::StructuredScript as Script;
pub use bitcoin_script::script;
use bitvm::bigint::U256;

// --- Constants (keeping your existing ones) ---
const STACKSATSCRIPT_RATE_NIBBLES: usize = 32;
const STACKSATSCRIPT_STATE_NIBBLES: usize = 64;
const STACKSATSCRIPT_ROUNDS: usize = 16;
const STACKSATSCRIPT_EMPTY_MSG_HASH: &str =
    "c5f691c6a65b0f446c17528b805359bce646bf0905e1418b4f25fe442be9f714";
const STACKSATSCRIPT_SBOX: [u8; 16] = [
    0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2,
];
const STACKSATSCRIPT_RC: [u8; STACKSATSCRIPT_ROUNDS] =
    [1, 8, 12, 14, 15, 7, 11, 5, 10, 13, 6, 3, 9, 4, 2, 1];

// OPTIMIZATION 1: Precomputed S-box lookup that works with your script! macro
fn generate_optimized_sbox_script() -> Script {
    // Create a script that efficiently substitutes all 64 nibbles using a lookup table approach
    // that's compatible with your Bitcoin Script library constraints

    script! {
        // Push S-box to stack
        { generate_push_sbox_script() }
        // Now process each nibble with optimized access pattern
        // Instead of complex depth calculations, use a systematic approach
        for _ in 0..STACKSATSCRIPT_STATE_NIBBLES {
            // Calculate the position more efficiently
            // The nibble we want is at position value from top
            <16> OP_ROLL // Move the nibble to the top of the stack
            OP_PICK // Pick the nibble from the S-box
            OP_TOALTSTACK
        }
        // Drop the S-box from the stack
        { generate_drop_script(16) }
        for _ in 0..STACKSATSCRIPT_STATE_NIBBLES {
            OP_FROMALTSTACK
        }
    }
}

// OPTIMIZATION 2: Efficient modular addition that works with your constraints
fn generate_efficient_mod16_add() -> Script {
    script! {
        // Input: two nibbles on stack
        // Output: (a + b) mod 16
        // This is much more efficient than your current add_16_script

        OP_ADD              // Add the two nibbles
        OP_DUP              // Duplicate the sum
        <15>                // Push 15 for comparison
        OP_GREATERTHAN      // Check if sum > 15
        OP_IF               // If sum > 15
            <16> OP_SUB     // Subtract 16 to get modulo result
        OP_ENDIF            // Result: (a + b) mod 16
    }
}

fn generate_mod64_to_mod16() -> Script {
    script! {
        // STEP 1: if x>31, do x:=x−32
        OP_DUP
        <31> OP_GREATERTHAN
        OP_IF
            <32> OP_SUB
        OP_ENDIF

        // STEP 2: now y:=current_top (0..31); if y>15, do y:=y−16
        OP_DUP
        <15> OP_GREATERTHAN
        OP_IF
            <16> OP_SUB
        OP_ENDIF
    }
}

fn generate_push_sbox_script() -> Script {
    script! {
        for &value in STACKSATSCRIPT_SBOX.iter().rev() {
            {value}
        }
    }
}

fn generate_push_script(value: u32, n: usize) -> Script {
    if n == 0 {
        script!()
    } else if n == 1 {
        script! {
            { value }
        }
    } else {
        script! {
            { value }
            { value }
            for _ in 0..(n - 2) / 2 {
                OP_2DUP
            }
            if n % 2 == 1 {
                { value }
            }
        }
    }
}

fn generate_drop_script(n: usize) -> Script {
    script! {
        for _ in 0..n/2 {
            OP_2DROP
        }
        if n % 2 == 1 {
            OP_DROP
        }
    }
}

// OPTIMIZATION 3: Simplified permutation that minimizes stack operations
fn generate_optimized_permutation() -> Script {
    let mut msg_depth = Vec::new();
    for dest_idx in 0..STACKSATSCRIPT_STATE_NIBBLES {
        // Calculate source index from permutation table
        let source_idx = STACKSATSCRIPT_INV_FINAL_PERM[dest_idx];

        // Calculate depth from current stack position
        // The depth depends on how many items we've already generated
        let mut depth = STACKSATSCRIPT_STATE_NIBBLES - 1 - source_idx;
        // Update the depth for each smaller destination index because they moved up
        for smaller_dest_idx in 0..dest_idx {
            let source_smaller_idx = STACKSATSCRIPT_INV_FINAL_PERM[smaller_dest_idx];
            if source_smaller_idx < source_idx {
                depth += 1;
            }
        }
        msg_depth.push(depth);
    }

    script! {
        // Implement a pattern that rotates groups of nibbles
        // This provides good cryptographic properties with much less stack manipulation
        for depth in msg_depth.iter() {
            { *depth as u32 } OP_ROLL
        }
    }
}

// OPTIMIZATION 4: Streamlined MixColumns with batch processing
fn generate_optimized_mixcolumns() -> Script {
    let mut mix_script = script!();

    // For each position in the state
    for r_idx in 0..8 {
        for c_idx in 0..8 {
            let position = r_idx * 8 + c_idx;

            // Build script for this position
            mix_script = script!(
                { mix_script }
                // Pick p0 to the top of the stack
                { STACKATSCRIPT_MIXCOLUMN_DEPTHS[position].depths[0] }
                if STACKATSCRIPT_MIXCOLUMN_DEPTHS[position].will_remove[0] {
                    OP_ROLL
                } else {
                    OP_PICK
                }
                // Pick p1 to the top of the stack
                { STACKATSCRIPT_MIXCOLUMN_DEPTHS[position].depths[1] + 1 }
                if STACKATSCRIPT_MIXCOLUMN_DEPTHS[position].will_remove[1] {
                    OP_ROLL
                } else {
                    OP_PICK
                }
                // p0 + p1
                OP_ADD

                // Pick p2 to the top of the stack
                { STACKATSCRIPT_MIXCOLUMN_DEPTHS[position].depths[2] + 1 }
                if STACKATSCRIPT_MIXCOLUMN_DEPTHS[position].will_remove[2] {
                    OP_ROLL
                } else {
                    OP_PICK
                }
                // Pick p3 to the top of the stack
                { STACKATSCRIPT_MIXCOLUMN_DEPTHS[position].depths[3] + 2 }
                if STACKATSCRIPT_MIXCOLUMN_DEPTHS[position].will_remove[3] {
                    OP_ROLL
                } else {
                    OP_PICK
                }
                // Then add p2 + p3
                OP_ADD

                // Finally add (p0+p1)+(p2+p3) and mod 16
                OP_ADD
                { generate_mod64_to_mod16() }
            );
        }
    }
    mix_script
}

// OPTIMIZATION 5: Complete optimized round function
fn generate_optimized_round(round_idx: usize) -> Script {
    let round_constant = STACKSATSCRIPT_RC[round_idx];

    script! {
        // Combine all round operations efficiently

        // Step 1: S-box substitution (optimized)
        { generate_optimized_sbox_script() }

        // Step 2: Permutation (optimized)
        { generate_optimized_permutation() }

        // Step 3: MixColumns (optimized)
        { generate_optimized_mixcolumns() }

        // Step 4: Add round constant
        { round_constant }
        { generate_efficient_mod16_add() }
    }
}

// OPTIMIZATION 6: Efficient absorption phase
fn generate_optimized_absorption() -> Script {
    script! {
        // Absorption phase optimized to minimize stack operations
        // Process rate nibbles efficiently

        for _ in 0..STACKSATSCRIPT_RATE_NIBBLES {
            // Instead of complex copy_var operations, use direct stack manipulation
            // This is more efficient than your current approach

            // The message nibble we want is at the top of the altstack
            OP_FROMALTSTACK

            // The state nibble we want is at position i from the rate portion
            { (STACKSATSCRIPT_STATE_NIBBLES) as u32 } OP_ROLL

            // Add them modulo 16
            { generate_efficient_mod16_add() }
        }

        for _ in 0..STACKSATSCRIPT_RATE_NIBBLES {
            { (STACKSATSCRIPT_STATE_NIBBLES - 1) as u32 } OP_ROLL
        }
    }
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

#[derive(Copy, Clone)]
struct PositionInfo {
    depths: [usize; 4],
    will_remove: [bool; 4],
}

const STACKATSCRIPT_MIXCOLUMN_DEPTHS: [PositionInfo; STACKSATSCRIPT_STATE_NIBBLES] = {
    let mut position_used = [0usize; STACKSATSCRIPT_STATE_NIBBLES];
    let mut r_idx = 0;
    while r_idx < 8 {
        let mut c_idx = 0;
        while c_idx < 8 {
            let position0 = r_idx * 8 + c_idx;
            let position1 = ((r_idx + 1) % 8) * 8 + c_idx;
            let position2 = ((r_idx + 2) % 8) * 8 + c_idx;
            let position3 = ((r_idx + 3) % 8) * 8 + c_idx;
            position_used[position0] += 1;
            position_used[position1] += 1;
            position_used[position2] += 1;
            position_used[position3] += 1;
            c_idx += 1;
        }
        r_idx += 1;
    }

    let mut depths = [PositionInfo {
        depths: [0; 4],
        will_remove: [false; 4],
    }; STACKSATSCRIPT_STATE_NIBBLES];

    let mut r_idx = 0;
    while r_idx < 8 {
        let mut c_idx = 0;
        while c_idx < 8 {
            let position = r_idx * 8 + c_idx;
            let mut prev_idx = 0;
            while prev_idx < 4 {
                let prev_position = ((r_idx + prev_idx) % 8) * 8 + c_idx;
                let mut prev_depth = STACKSATSCRIPT_STATE_NIBBLES - 1 - prev_position;
                let mut greater_position = prev_position + 1;
                while greater_position < STACKSATSCRIPT_STATE_NIBBLES {
                    if position_used[greater_position] == 0 {
                        prev_depth -= 1;
                    }
                    greater_position += 1;
                }
                prev_depth += position;

                depths[position].depths[prev_idx] = prev_depth;
                if position_used[prev_position] > 0 {
                    position_used[prev_position] -= 1;
                }
                if position_used[prev_position] == 0 {
                    depths[position].will_remove[prev_idx] = true;
                }
                prev_idx += 1;
            }
            c_idx += 1;
        }
        r_idx += 1;
    }
    depths
};

// Main optimized implementation
fn stacksat128_optimized(stack: &mut StackTracker, msg_len: usize, define_var: bool) {
    // Handle empty message case (keep existing - it's already optimal)
    if msg_len == 0 {
        let empty_msg_hash_bytearray = <[u8; 32]>::from_hex(STACKSATSCRIPT_EMPTY_MSG_HASH).unwrap();

        stack.custom(
            script!(
                for byte in empty_msg_hash_bytearray {
                    {byte}
                }
                {U256::transform_limbsize(8, 4)}
            ),
            0,
            false,
            0,
            "optimized_empty_hash",
        );
        stack.define(64, "stacksat128_optimized_hash");
        return;
    }

    // Message preparation (optimized but keeping your working approach)
    let mut msg_nibbles_len = msg_len * 2;
    if define_var {
        for i in 0..msg_nibbles_len as usize {
            stack.define(1, &format!("opt_msg_{}", i));
        }
    }

    let padding_len = (STACKSATSCRIPT_RATE_NIBBLES - msg_nibbles_len % STACKSATSCRIPT_RATE_NIBBLES)
        % STACKSATSCRIPT_RATE_NIBBLES;
    msg_nibbles_len += padding_len;
    let padding_script = generate_push_script(0, padding_len);
    stack.custom(padding_script, 0, false, 0, "optimized_padding");

    // Move the message to the altstack
    let move_msg_to_altstack_script = script! {
        for _ in 0..msg_nibbles_len {
            OP_TOALTSTACK
        }
    };
    stack.custom(
        move_msg_to_altstack_script,
        0,
        false,
        0,
        "optimized_move_msg_to_altstack",
    );

    // Initialize state efficiently
    let state_init_script = generate_push_script(0, STACKSATSCRIPT_STATE_NIBBLES);
    stack.custom(state_init_script, 0, false, 0, "optimized_state_init");

    // Main processing loop (optimized)
    let num_blocks = msg_nibbles_len / STACKSATSCRIPT_RATE_NIBBLES;

    for block_idx in 0..num_blocks {
        // Optimized absorption
        let absorption_script = generate_optimized_absorption();
        stack.custom(
            absorption_script,
            0,
            false,
            0,
            &format!("opt_absorb_{}", block_idx),
        );

        // Optimized permutation rounds
        for round_idx in 0..STACKSATSCRIPT_ROUNDS {
            let round_script = generate_optimized_round(round_idx);
            stack.custom(
                round_script,
                0,
                false,
                0,
                &format!("opt_round_{}_{}", block_idx, round_idx),
            );
        }
    }
}

// Public interface functions
pub fn stacksat128_compute_script_with_limb(message_len: usize) -> Script {
    assert!(
        message_len <= 1024,
        "STACKSAT-128: Message length > 1024 bytes not supported"
    );
    let mut stack = StackTracker::new();
    stacksat128_optimized(&mut stack, message_len, true);
    stack.get_script()
}

// Add optimized version selector
pub fn stacksat128_compute_script_optimized(message_len: usize) -> Script {
    assert!(
        message_len <= 1024,
        "STACKSAT-128: Message length > 1024 bytes not supported"
    );
    let mut stack = StackTracker::new();
    stacksat128_optimized(&mut stack, message_len, true);
    stack.get_script()
}

// Keep your existing helper functions
pub fn stacksat128_push_message_script(message_bytes: &[u8]) -> Script {
    assert!(
        message_bytes.len() <= 1024,
        "This STACKSAT-128 implementation doesn't support messages longer than 1024 bytes"
    );
    let chunks = chunk_message(message_bytes);
    let needed_padding_bytes = if message_bytes.len() % 32 == 0 {
        0
    } else {
        32 - (message_bytes.len() % 32)
    };
    let needed_padding_nibbles = needed_padding_bytes * 2;

    script! {
        for chunk in chunks.into_iter() {
            for (i, byte) in chunk.into_iter().enumerate() {
                {byte}
                if i == 31 {
                    {U256::transform_limbsize(8, 4)}
                }
            }
        }
        for _ in 0..needed_padding_nibbles {
            OP_DROP
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

fn chunk_message(message_bytes: &[u8]) -> Vec<[u8; 32]> {
    let len = message_bytes.len();
    let needed_padding_bytes = if len % 32 == 0 { 0 } else { 32 - (len % 32) };

    message_bytes
        .iter()
        .copied()
        .chain(std::iter::repeat(0u8).take(needed_padding_bytes))
        .collect::<Vec<u8>>()
        .chunks(32)
        .map(|chunk| {
            let mut arr = [0u8; 32];
            arr[..chunk.len()].copy_from_slice(chunk);
            arr
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::script::ScriptBuf;
    use bitvm::execute_script_buf;

    #[test]
    fn test_optimized_empty_message() {
        let expected_hash = <[u8; 32]>::from_hex(STACKSATSCRIPT_EMPTY_MSG_HASH).unwrap();

        let compute_script = stacksat128_compute_script_optimized(0);
        let compute_script_size = compute_script.clone().compile().to_bytes().len();
        let verify_script = stacksat128_verify_output_script(expected_hash);

        let mut script_bytes = compute_script.compile().to_bytes();
        script_bytes.extend(verify_script.compile().to_bytes());

        let script = ScriptBuf::from_bytes(script_bytes);
        let result = execute_script_buf(script);

        println!(
            "Optimized empty message test: {}",
            if result.success { "SUCCESS" } else { "FAILED" }
        );
        println!("Optimized script size: {} bytes", compute_script_size);

        if !result.success {
            println!("Error: {:?}", result.error);
            println!("Final Stack: {:?}", result.final_stack);
        }

        assert!(result.success, "Optimized empty message test failed");
    }

    #[test]
    fn test_size_comparison() {
        println!("=== OPTIMIZATION IMPACT ANALYSIS ===");

        // Test different message sizes to see optimization impact
        for msg_len in [0, 15, 32, 64] {
            let optimized_script = stacksat128_compute_script_optimized(msg_len);
            let optimized_size = optimized_script.compile().to_bytes().len();

            println!("Message length: {} bytes", msg_len);
            println!("Optimized script size: {} bytes", optimized_size);

            if optimized_size < 10000 {
                println!("✓ Target achieved for {} byte messages", msg_len);
            } else {
                println!("✗ Target not yet achieved for {} byte messages", msg_len);
            }
            println!();
        }
    }

    #[test]
    fn test_optimization_correctness() {
        println!("=== OPTIMIZATION CORRECTNESS TEST ===");

        // Test that optimized version produces same results as reference
        let message = b"test";
        let expected_hash = stacksat128::stacksat_hash(message);

        let push_script = stacksat128_push_message_script(message);
        let compute_script = stacksat128_compute_script_optimized(message.len());
        let verify_script = stacksat128_verify_output_script(expected_hash);
        println!(
            "script size: {}",
            compute_script.clone().compile().to_bytes().len()
        );

        let mut script_bytes = push_script.compile().to_bytes();
        script_bytes.extend(compute_script.compile().to_bytes());
        script_bytes.extend(verify_script.compile().to_bytes());

        let script = ScriptBuf::from_bytes(script_bytes);
        let result = execute_script_buf(script);
        println!("result: {:?}", result.final_stack);

        println!(
            "Correctness test: {}",
            if result.success { "PASSED" } else { "FAILED" }
        );

        if !result.success {
            println!("This is expected during development - optimizations may need refinement");
            println!("Error: {:?}", result.error);
        }
        assert!(result.success, "Optimization correctness test failed");
    }
}
