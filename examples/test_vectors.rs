use serde::Serialize;
use stacksat128::stacksat_hash;

const TEST_VECTORS_INPUT: [&str; 3] = ["", "abc", "The quick brown fox jumps over the lazy dog"];
const TEST_VECTOR_OUTPUT_FILE: &str = "test_vectors/basic_test_vector.json";

#[derive(Serialize)]
struct TestVector {
    input: String,
    output: String,
}

fn main() {
    println!("Generating test vectors...");
    let test_vectors = TEST_VECTORS_INPUT
        .iter()
        .map(|input| TestVector {
            input: hex::encode(input.as_bytes()),
            output: hex::encode(stacksat_hash(input.as_bytes())),
        })
        .collect::<Vec<_>>();
    // Convert the test vectors to a json object, pretty print it
    let test_vectors_json = serde_json::to_string_pretty(&test_vectors).unwrap();
    println!("{}", test_vectors_json);
    std::fs::write(TEST_VECTOR_OUTPUT_FILE, test_vectors_json).unwrap();
    println!("Test vectors written to {}", TEST_VECTOR_OUTPUT_FILE);
}
