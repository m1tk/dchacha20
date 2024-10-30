use chacha20::cipher::{KeyIvInit, StreamCipher};
use criterion::*;
use rand::RngCore;
use openssl::symm::{encrypt, Cipher, decrypt};

fn bench_decrypt(c: &mut Criterion, name: &str, size: usize) {
    let mut rand  = black_box(rand::rngs::OsRng {});
    let mut key   = [0u8; 32];
    rand.fill_bytes(&mut key);
    let mut nonce = [0u8; 12];
    rand.fill_bytes(&mut nonce);
    let mut iv    = [0u8; 16];
    rand.fill_bytes(&mut iv);

    let mut group = c.benchmark_group(name);
    let mut input = black_box(vec![0u8; size]);
    group.throughput(Throughput::Bytes(input.len() as u64));
    
    let chacha20      = Cipher::chacha20();
    let mut rchacha20 = chacha20::ChaCha20::new(&key.into(), &nonce.into());

    let r = encrypt(chacha20, &key, Some(&iv), &input).unwrap();
    group.bench_function("OpenSSL chacha20", |b| {
        b.iter(|| {
            let _r = decrypt(chacha20, &key, Some(&iv), &r).unwrap();
        })
    });

    group.bench_function("RustCrypto chacha20", |b| {
        b.iter(|| {
            rchacha20.apply_keystream(&mut input);
        })
    });

    group.finish();
}

fn bench_encrypt(c: &mut Criterion, name: &str, size: usize) {
    let mut rand  = black_box(rand::rngs::OsRng {});
    let mut key   = [0u8; 32];
    rand.fill_bytes(&mut key);
    let mut nonce = [0u8; 12];
    rand.fill_bytes(&mut nonce);
    let mut iv    = [0u8; 16];
    rand.fill_bytes(&mut iv);

    let mut group = c.benchmark_group(name);
    let mut input = black_box(vec![0u8; size]);
    group.throughput(Throughput::Bytes(input.len() as u64));
    
    let chacha20      = Cipher::chacha20();
    let mut rchacha20 = chacha20::ChaCha20::new(&key.into(), &nonce.into());

    group.bench_function("OpenSSL chacha20", |b| {
        b.iter(|| {
            let _r = encrypt(chacha20, &key, Some(&iv), &input).unwrap();
        })
    });

    group.bench_function("RustCrypto chacha20", |b| {
        b.iter(|| {
            rchacha20.apply_keystream(&mut input);
        })
    });

    group.finish();
}

fn bench(c: &mut Criterion) {
    bench_encrypt(c, "Encrypt 100B", 100);
    bench_encrypt(c, "Encrypt 10KB", 10_240);
    bench_encrypt(c, "Encrypt 1MB", 1_048_576);
    bench_encrypt(c, "Encrypt 100MB", 104_857_600);
    bench_encrypt(c, "Encrypt 1GB", 1_073_741_824);
    
    bench_decrypt(c, "Decrypt 100B", 100);
    bench_encrypt(c, "Encrypt 10KB", 10_240);
    bench_decrypt(c, "Decrypt 1MB", 1_048_576);
    bench_decrypt(c, "Decrypt 100MB", 104_857_600);
    bench_decrypt(c, "Decrypt 1GB", 1_073_741_824);
}

criterion_group!(benches, bench);
criterion_main!(benches);
