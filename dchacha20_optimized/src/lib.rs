#![feature(portable_simd)]
#![feature(slice_pattern)]
mod chacha20;
mod dchacha20;

pub use chacha20::ChaCha20;
pub use dchacha20::DChaCha20;
