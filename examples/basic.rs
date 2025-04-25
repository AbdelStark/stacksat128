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

    let input3 = [0x00; 32].as_slice();
    let hash3 = stacksat_hash(input3);
    println!("Input 3: {}", hex::encode(input3));
    println!("Hash 3: {}", hex::encode(hash3));

    // 31 zero bytes and a one
    let mut input4 = [0x00; 32];
    input4[31] = 0x01;
    let hash4 = stacksat_hash(input4.as_slice());
    println!("Input 4: {}", hex::encode(input4));
    println!("Hash 4: {}", hex::encode(hash4));
}
