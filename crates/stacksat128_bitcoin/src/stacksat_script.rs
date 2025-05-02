use bitcoin::hex::FromHex;
use bitcoin_script_stack::stack::{StackTracker, StackVariable};

pub use bitcoin_script::builder::StructuredScript as Script;
pub use bitcoin_script::script;
use bitvm::bigint::U256;
use itertools::Itertools;

const DEFAULT_LIMB_LEN: u8 = 4;

const EMPTY_MSG_HASH: &str = "bb04e59e240854ee421cdabf5cdd0416beaaaac545a63b752792b5a41dd18b4e";

fn stacksat128(
    stack: &mut StackTracker,
    mut msg_len: u32,
    define_var: bool,
    use_full_tables: bool,
    limb_len: u8,
) {
    // this assumes that the stack is empty
    if msg_len == 0 {
        // bb04e59e240854ee421cdabf5cdd0416beaaaac545a63b752792b5a41dd18b4e
        let empty_msg_hash_bytearray = <[u8; 32]>::from_hex(EMPTY_MSG_HASH).unwrap();

        stack.custom(
            script!(
                // push the hash value
                for byte in empty_msg_hash_bytearray{
                    {byte}
                }
                //convert bytes to nibbles
                {U256::transform_limbsize(8,4)}
            ),
            0,
            false,
            0,
            "push empty string hash in nibble form",
        );
        stack.define(8_u32 * 8, "stacksat128-hash");
        return;
    }

    // We require message take atmost a chunk. i.e, 1024 bytes.
    assert!(
        msg_len <= 1024,
        "msg length must be less than or equal to 1024 bytes"
    );
    assert!(
        (4..32).contains(&limb_len),
        "limb length must be in the range [4, 32)"
    );

    // get the result hash
    stack.from_altstack_joined(8_u32 * 8, "stacksat128-hash");
}

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
    fn test_e2e() {
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
}
