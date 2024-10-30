use zeroize::Zeroizing;

pub struct DChaCha20 {
    /// This is where the initial state is stored
    state: Zeroizing<[u32; 16]>,
    /// Calculated keystream
    keystream: Zeroizing<[u32; 16]>,
    /// Keystream as u8 buffer
    keystream_buffer: Zeroizing<[u8; 64]>,
    /// Digest for XORing previous ciphertext generated random bytes
    prev_dig: Zeroizing<[u8; 64]>,
    xorshift: XorShift
}

impl DChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        Self {
            state: Zeroizing::new([
                /*
                cccccccc cccccccc cccccccc cccccccc
                kkkkkkkk kkkkkkkk kkkkkkkk kkkkkkkk
                kkkkkkkk kkkkkkkk kkkkkkkk kkkkkkkk
                bbbbbbbb nnnnnnnn nnnnnnnn nnnnnnnn
                c=constant k=key b=blockcount n=nonce
                */

                // The 4 u32 constants of chacha
                0x61707865, 0x3320646E, 0x79622D32, 0x6B206574,
                // Key
                u32_from_le_bytes(&key[0..4]), u32_from_le_bytes(&key[4..8]), u32_from_le_bytes(&key[8..12]), u32_from_le_bytes(&key[12..16]),
                u32_from_le_bytes(&key[16..20]), u32_from_le_bytes(&key[20..24]), u32_from_le_bytes(&key[24..28]), u32_from_le_bytes(&key[28..32]),
                // Bit counter + nonce
                0, u32_from_le_bytes(&nonce[..4]), u32_from_le_bytes(&nonce[4..8]), u32_from_le_bytes(&nonce[8..12]),
            ]),
            keystream: Zeroizing::new([0u32; 16]),
            keystream_buffer: Zeroizing::new([0u8; 64]),
            prev_dig: Zeroizing::new([0u8; 64]),
            xorshift: XorShift::new()
        }
    }

    fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        state[a]  = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d]  = state[d].rotate_left(16);
        state[c]  = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b]  = state[b].rotate_left(12);
        state[a]  = state[a].wrapping_add(state[b]);
        state[d] ^= state[a];
        state[d]  = state[d].rotate_left(8);
        state[c]  = state[c].wrapping_add(state[d]);
        state[b] ^= state[c];
        state[b]  = state[b].rotate_left(7);
    }

    fn rounds(state: &mut [u32; 16]) {
        for _ in 0..10 {
            // column round
            Self::quarter_round(state, 0, 4, 8, 12);
            Self::quarter_round(state, 1, 5, 9, 13);
            Self::quarter_round(state, 2, 6, 10, 14);
            Self::quarter_round(state, 3, 7, 11, 15);

            // diagonal round
            Self::quarter_round(state, 0, 5, 10, 15);
            Self::quarter_round(state, 1, 6, 11, 12);
            Self::quarter_round(state, 2, 7, 8, 13);
            Self::quarter_round(state, 3, 4, 9, 14);
        }
    }

    fn block_fn(&mut self) {
        self.keystream.copy_from_slice(self.state.as_ref());
        Self::rounds(&mut self.keystream);
        for (k, i) in self.keystream.iter_mut().zip(self.state.iter()) {
            *k = k.wrapping_add(*i);
        }
        self.state[12] = self.state[12].wrapping_add(1);
    }

    fn convert_keystream_to_u8_arr(&mut self) {
        for i in 0..16 {
            self.keystream_buffer[4*i..][..4].copy_from_slice(&self.keystream[i].to_le_bytes());
        }
    }

    fn apply_keystream(&mut self, buff: &mut [u8]) {
        self.block_fn();
        self.convert_keystream_to_u8_arr();

        for (i, byte) in buff.iter_mut().enumerate() {
            *byte = *byte ^ self.keystream_buffer[i] ^ self.prev_dig[i];
        }
    }

    pub fn encrypt(&mut self, plaintext: &mut [u8]) {
        for chunk in plaintext.chunks_mut(64) {
            self.apply_keystream(chunk);
            self.xorshift.set_seed(chunk.as_ref());
            for byte in self.prev_dig.iter_mut() {
                *byte ^= self.xorshift.next_random();
            }
        }
    }

    pub fn decrypt(&mut self, ciphertext: &mut [u8]) {
        for chunk in ciphertext.chunks_mut(64) {
            self.xorshift.set_seed(chunk.as_ref());
            self.apply_keystream(chunk);
            for byte in self.prev_dig.iter_mut() {
                *byte ^= self.xorshift.next_random();
            }
        }
    }
}


/// Method to convert to u32
/// This should never panic since we are sure of size we pass to method
fn u32_from_le_bytes(slice: &[u8]) -> u32 {
    u32::from_le_bytes(
        slice
            .try_into()
            .expect("u32_from_le_bytes given u8 slice with invalid size")
    )
}


struct XorShift {
    state: Zeroizing<u32>
}

impl XorShift {
    pub fn new() -> Self {
        Self {
            state: Zeroizing::new(0)
        }
    }

    pub fn set_seed(&mut self, seed: &[u8]) {
        *self.state = 0;
        for numb in seed.chunks(4) {
            for (pos, byte) in numb.iter().enumerate() {
                *self.state = self.state.wrapping_add(
                    (*byte as u32) <<  (pos * 8)
                );
            }
        }
    }

    fn next_random(&mut self) -> u8 {
        *self.state ^= *self.state << 13;
        *self.state ^= *self.state >> 17;
        *self.state ^= *self.state << 5;
        (*self.state & 255) as u8
    }
}

#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use rand::RngCore;

    use super::DChaCha20;

    #[test]
    fn validate() {
        let key = hex!("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f");
        let nonce = hex!("00 00 00 00 00 00 00 4a 00 00 00 00");

        let msg = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".as_bytes().to_vec();

        let mut cipher = DChaCha20::new(&key, &nonce);
        let mut cipher1 = DChaCha20::new(&key, &nonce);
        
        let mut buffer1 = msg.clone();
        let mut buffer2 = msg.clone();
        let mut buffer3 = msg.clone();

        cipher.encrypt(&mut buffer1);
        cipher.encrypt(&mut buffer2);
        cipher.encrypt(&mut buffer3);

        assert_eq!(buffer1, hex!("e3647a29ded31528ef56bac70f7a7ac3b735c7444da42d99823ef9938c8ebfdcf05bb71a822c62981aa1ea608f47933f2ed755b62d9312ae72037674f3e93e24c9ac47dced09b0d02a6f3fb2659a3f04bf9e4aa7bca2d5a0bc1038db191fb11cedbfa743f4b76bd60a07cd985aa4f6017439"));

        assert_eq!(buffer2, hex!("01cd51c0df81a6950ed03086fe09e8f64ca3230aa0e51a482edb8d3168f74deb8759df6a2b4822d9143663e2802a5ff296e8a29b3de51d7a2b908817131eafff3fcbd6de090ac37adafd49b58e92900815b8b062b8ff6ea6e55a3ac3115461a30ab730e341826732bb5b3ad427699f6c5fff"));

        assert_eq!(buffer3, hex!("ea28b7883476f68ed10cf399c6e139cffbbd2a6656a99e3e43480eb53b4f576df5eaecd876b6786b80c7c44dbc2f6553a4ad61b0a025b3e56f02cc63d118e955092dff82f5bc8ed9a305428be48b28692b0fdf523f26c96a9b50388dc1dee6ddc058680116bc2577b610f48882f4d2ef46a3"));

        cipher1.decrypt(&mut buffer1);
        cipher1.decrypt(&mut buffer2);
        cipher1.decrypt(&mut buffer3);

        assert_eq!(buffer1, msg);
        assert_eq!(buffer2, msg);
        assert_eq!(buffer3, msg);
    }

    #[test]
    fn encrypt_decrypt() {
        let mut rand  = rand::rngs::OsRng {};
        let mut key   = [0u8; 32];
        rand.fill_bytes(&mut key);
        let mut nonce = [0u8; 12];
        rand.fill_bytes(&mut nonce);

        let mut cipher = DChaCha20::new(&key, &nonce);
        let mut cipher1 = DChaCha20::new(&key, &nonce);

        for _ in 0..100 {
            let mut msg = b"hello".to_vec();
            cipher.encrypt(&mut msg);
            cipher1.decrypt(&mut msg);
            assert_eq!(msg, b"hello");
        }

        for _ in 0..100 {
            let mut msg = b"hello".repeat(300);
            cipher.encrypt(&mut msg);
            cipher1.decrypt(&mut msg);
            assert_eq!(msg, b"hello".repeat(300));
        }
    }
}
