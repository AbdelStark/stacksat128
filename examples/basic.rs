use stacksat128::stacksat_hash;

fn main() {
    let input = "Hello, world!";
    let hash = stacksat_hash(input.as_bytes());
    println!("Input: {}", input);
    println!("Input hex: {}", hex::encode(input.as_bytes()));
    println!("Hash: {}", hex::encode(hash));

    let input2 = "Hello, world";
    let hash2 = stacksat_hash(input2.as_bytes());
    println!("Input 2: {}", input2);
    println!("Input 2 hex: {}", hex::encode(input2.as_bytes()));
    println!("Hash 2: {}", hex::encode(hash2));
}
