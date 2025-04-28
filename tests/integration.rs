use sha256::digest as sha256_digest;
use stacksat128::stacksat_hash;

// Helper function to calculate Hamming distance between two byte slices
fn hamming_distance(a: &[u8], b: &[u8]) -> u32 {
    assert_eq!(
        a.len(),
        b.len(),
        "Slices must have the same length for Hamming distance"
    );
    let mut distance = 0;
    for (byte_a, byte_b) in a.iter().zip(b.iter()) {
        distance += (byte_a ^ byte_b).count_ones();
    }
    distance
}

// --- Avalanche Effect Comparison Test ---
#[test]
fn test_avalanche_comparison() {
    // Use a reasonably sized input, e.g., 64 bytes
    let input_data = [0x5Au8; 64]; // Arbitrary pattern
    let num_bytes_to_flip = 16; // Limit flips to first 16 bytes (128 bits) for speed
    let num_bits_to_flip = num_bytes_to_flip * 8;

    // Calculate baseline hashes
    let baseline_stacksat = stacksat_hash(&input_data);
    let baseline_sha256_str = sha256_digest(input_data.as_slice());
    let baseline_sha256 = hex::decode(baseline_sha256_str).expect("SHA256 hex decode failed");
    let baseline_blake3 = blake3::hash(&input_data);

    // Accumulators for total Hamming distance
    let mut total_dist_stacksat: u64 = 0;
    let mut total_dist_sha256: u64 = 0;
    let mut total_dist_blake3: u64 = 0;

    for byte_index in 0..num_bytes_to_flip {
        for bit_index in 0..8 {
            let mut modified_input = input_data;
            modified_input[byte_index] ^= 1 << bit_index; // Flip the bit

            // Calculate hashes of modified input
            let modified_stacksat = stacksat_hash(&modified_input);
            let modified_sha256_str = sha256_digest(modified_input.as_slice());
            let modified_sha256 =
                hex::decode(modified_sha256_str).expect("SHA256 hex decode failed");
            let modified_blake3 = blake3::hash(&modified_input);

            // Calculate and accumulate Hamming distances
            total_dist_stacksat += hamming_distance(&baseline_stacksat, &modified_stacksat) as u64;
            total_dist_sha256 += hamming_distance(&baseline_sha256, &modified_sha256) as u64;
            total_dist_blake3 +=
                hamming_distance(baseline_blake3.as_bytes(), modified_blake3.as_bytes()) as u64;
        }
    }

    // Calculate average Hamming distances
    let avg_dist_stacksat = total_dist_stacksat as f64 / num_bits_to_flip as f64;
    let avg_dist_sha256 = total_dist_sha256 as f64 / num_bits_to_flip as f64;
    let avg_dist_blake3 = total_dist_blake3 as f64 / num_bits_to_flip as f64;

    println!(
        "\n--- Avalanche Test Results (Average Hamming Distance over {} bit flips) ---",
        num_bits_to_flip
    );
    println!("STACKSAT-128: {:.2}", avg_dist_stacksat);
    println!("SHA-256:      {:.2}", avg_dist_sha256);
    println!("BLAKE3:       {:.2}", avg_dist_blake3);
    println!("Ideal (256-bit output): 128.00");

    // Assert that STACKSAT's average distance is reasonably close to the ideal 128 bits
    // Allow roughly +/- 10% deviation from ideal (128 * 0.9 = 115.2, 128 * 1.1 = 140.8)
    assert!(avg_dist_stacksat > 115.0 && avg_dist_stacksat < 141.0,
            "STACKSAT-128 average Hamming distance ({:.2}) is outside the acceptable range (115.0 - 141.0)", avg_dist_stacksat);

    // Optional: Check if STACKSAT is not significantly worse than the others (e.g., within 5 bits)
    assert!(
        avg_dist_stacksat > avg_dist_sha256 - 5.0,
        "STACKSAT avg dist significantly lower than SHA256"
    );
    assert!(
        avg_dist_stacksat > avg_dist_blake3 - 5.0,
        "STACKSAT avg dist significantly lower than BLAKE3"
    );
}
