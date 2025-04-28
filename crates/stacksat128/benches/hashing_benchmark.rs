use criterion::{black_box, criterion_group, criterion_main, Criterion};
use sha2::{Digest, Sha256};
use stacksat128::stacksat_hash;

const KB: usize = 1024;

// Function to generate some test data
fn generate_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

fn hashing_benchmarks(c: &mut Criterion) {
    let data_1k = generate_data(KB);
    let data_64k = generate_data(64 * KB);

    let mut group = c.benchmark_group("Hashing Algorithms Comparison");

    // --- Benchmarks for 1KB Input ---
    group.bench_with_input("STACKSAT-128 (1KB)", &data_1k, |b, data| {
        b.iter(|| stacksat_hash(black_box(data)))
    });

    group.bench_with_input("SHA-256 (1KB)", &data_1k, |b, data| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(data));
            hasher.finalize()
        })
    });

    group.bench_with_input("BLAKE3 (1KB)", &data_1k, |b, data| {
        b.iter(|| blake3::hash(black_box(data)))
    });

    // --- Benchmarks for 64KB Input ---
    group.bench_with_input("STACKSAT-128 (64KB)", &data_64k, |b, data| {
        b.iter(|| stacksat_hash(black_box(data)))
    });

    group.bench_with_input("SHA-256 (64KB)", &data_64k, |b, data| {
        b.iter(|| {
            let mut hasher = Sha256::new();
            hasher.update(black_box(data));
            hasher.finalize()
        })
    });

    group.bench_with_input("BLAKE3 (64KB)", &data_64k, |b, data| {
        b.iter(|| blake3::hash(black_box(data)))
    });

    group.finish();
}

criterion_group!(benches, hashing_benchmarks);
criterion_main!(benches);
