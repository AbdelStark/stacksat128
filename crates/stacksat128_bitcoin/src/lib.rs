use bitcoin_script::Script;

#[allow(dead_code)]
const STACKSAT_MAX_ELEMENT_COUNT: usize = 1000;
const MAX_STACKSAT_MSG_LEN_BYTES: usize = 1024;

/// Returns a script that computes the STACKSAT-128 hash of the message on the stack.
///
/// Placeholder: Currently returns an empty script.
///
/// ## Parameters
///
/// - `msg_len`: Length of the message in bytes (excluding padding).
/// - `limb_len`: Limb length (number of bits per element) for packed stack input (e.g., 29 or 30).
///
/// ## Message Format Requirements
///
/// - __The stack should contain only the message. Move other items to altstack.__ Empty stack for zero-length message.
/// - Input message assumed to be packed U256 elements using `limb_len` bits per limb.
/// - Input must unpack to a multiple of the required block size in nibbles (TBD for STACKSAT-128).
/// - __STACKSAT-128 script uses an estimated [`STACKSAT_MAX_ELEMENT_COUNT`] elements maximum.__
///   With the 1000 element limit, ensure `1000 - STACKSAT_MAX_ELEMENT_COUNT` is enough for your message + other stack items.
/// - A message of `n` blocks (structure TBD) is expected in reverse order on the stack.
///
/// ## Panics
///
/// - Placeholder: Panics if `msg_len` exceeds `MAX_STACKSAT_MSG_LEN_BYTES`.
/// - Placeholder: Panics if `limb_len` is outside a valid range (e.g., [4, 32)).
///
/// ## Implementation (Future)
///
/// 1. Define stack variables/layout.
/// 2. Move message to altstack if needed.
/// 3. Initialize STACKSAT-128 state/tables.
/// 4. Process message blocks (unpacking, hashing rounds).
/// 5. Finalize and leave the 256-bit hash (64 nibbles) on the stack.
///
/// ## Stack Effects (Future)
///
/// - Uses altstack for intermediate values/tables.
/// - Leaves the final 256-bit hash on the main stack.
pub fn stacksat128_compute_script_with_limb(message_len: usize, limb_len: u8) -> Script {
    assert!(
        message_len <= MAX_STACKSAT_MSG_LEN_BYTES,
        "STACKSAT-128 script placeholder does not support messages > {} bytes",
        MAX_STACKSAT_MSG_LEN_BYTES
    );
    assert!(
        (4..=31).contains(&limb_len),
        "Limb length must be between 4 and 31 (inclusive)"
    );

    // Placeholder implementation
    // TODO: Implement the actual STACKSAT-128 script generation logic
    // using bitvm, bitcoin-script, etc.

    Script::new("") // Provide empty debug string
}

/// Returns a script that computes the STACKSAT-128 hash using a default limb length of 29.
///
/// See [`stacksat128_compute_script_with_limb`] for details.
pub fn stacksat128_compute_script(message_len: usize) -> Script {
    stacksat128_compute_script_with_limb(message_len, 29)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stacksat128_compute_script() {
        let message_len = 32;
        let script = stacksat128_compute_script(message_len);
        println!("script: {:?}", script);
    }
}
