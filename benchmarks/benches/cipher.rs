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
    let mut tchacha20 = dchacha20::ChaCha20::new(&key, &nonce);
    let mut dchacha20 = dchacha20::DChaCha20::new(&key, &nonce);

    let r = encrypt(chacha20, &key, Some(&iv), &input).unwrap();
    group.bench_function("OpenSSL ChaCha20", |b| {
        b.iter(|| {
            let _r = decrypt(chacha20, &key, Some(&iv), &r).unwrap();
        })
    });

    group.bench_function("RustCrypto ChaCha20", |b| {
        b.iter(|| {
            rchacha20.apply_keystream(&mut input);
        })
    });

    group.bench_function("ChaCha20", |b| {
        b.iter(|| {
            tchacha20.decrypt(&mut input);
        })
    });

    group.bench_function("DChaCha20", |b| {
        b.iter(|| {
            dchacha20.decrypt(&mut input);
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
    let mut tchacha20 = dchacha20::ChaCha20::new(&key, &nonce);
    let mut dchacha20 = dchacha20::DChaCha20::new(&key, &nonce);

    group.bench_function("OpenSSL ChaCha20", |b| {
        b.iter(|| {
            let _r = encrypt(chacha20, &key, Some(&iv), &input).unwrap();
        })
    });

    group.bench_function("RustCrypto ChaCha20", |b| {
        b.iter(|| {
            rchacha20.apply_keystream(&mut input);
        })
    });

    group.bench_function("ChaCha20", |b| {
        b.iter(|| {
            tchacha20.encrypt(&mut input);
        })
    });

    group.bench_function("DChaCha20", |b| {
        b.iter(|| {
            dchacha20.encrypt(&mut input);
        })
    });

    group.finish();
}

fn bench(c: &mut Criterion) {
    bench_encrypt(c, "Encrypt 1B", 1);
    bench_encrypt(c, "Encrypt 16B", 16);
    bench_encrypt(c, "Encrypt 32B", 32);
    bench_encrypt(c, "Encrypt 64B", 64);
    bench_encrypt(c, "Encrypt 100B", 100);
    bench_encrypt(c, "Encrypt 300B", 300);
    bench_encrypt(c, "Encrypt 500B", 500);
    bench_encrypt(c, "Encrypt 700B", 700);
    bench_encrypt(c, "Encrypt 1KB", 1_024);
    bench_encrypt(c, "Encrypt 3KB", 3_072);
    bench_encrypt(c, "Encrypt 5KB", 5_120);
    bench_encrypt(c, "Encrypt 7KB", 7_168);
    bench_encrypt(c, "Encrypt 10KB", 10_240);
    bench_encrypt(c, "Encrypt 1MB", 1_048_576);
    bench_encrypt(c, "Encrypt 50MB", 52_428_800);
    bench_encrypt(c, "Encrypt 100MB", 104_857_600);
    bench_encrypt(c, "Encrypt 300MB", 314_572_800);
    bench_encrypt(c, "Encrypt 600MB", 629_145_600);
    bench_encrypt(c, "Encrypt 1GB", 1_073_741_824);
    bench_encrypt(c, "Encrypt 3GB", 3_221_225_472);
    bench_encrypt(c, "Encrypt 5GB", 5_368_709_120);
    
    bench_decrypt(c, "Decrypt 1B", 1);
    bench_decrypt(c, "Decrypt 16B", 16);
    bench_decrypt(c, "Decrypt 32B", 32);
    bench_decrypt(c, "Decrypt 64B", 64);
    bench_decrypt(c, "Decrypt 100B", 100);
    bench_decrypt(c, "Decrypt 300B", 300);
    bench_decrypt(c, "Decrypt 500B", 500);
    bench_decrypt(c, "Decrypt 700B", 700);
    bench_decrypt(c, "Decrypt 1KB", 1_024);
    bench_decrypt(c, "Decrypt 3KB", 3_072);
    bench_decrypt(c, "Decrypt 5KB", 5_120);
    bench_decrypt(c, "Decrypt 7KB", 7_168);
    bench_decrypt(c, "Decrypt 10KB", 10_240);
    bench_decrypt(c, "Decrypt 1MB", 1_048_576);
    bench_decrypt(c, "Decrypt 50MB", 52_428_800);
    bench_decrypt(c, "Decrypt 100MB", 104_857_600);
    bench_decrypt(c, "Decrypt 300MB", 314_572_800);
    bench_decrypt(c, "Decrypt 600MB", 629_145_600);
    bench_decrypt(c, "Decrypt 1GB", 1_073_741_824);
    bench_decrypt(c, "Decrypt 3GB", 3_221_225_472);
    bench_decrypt(c, "Decrypt 5GB", 5_368_709_120);
}

criterion_group!(benches, bench);
criterion_main!(benches);
