use core::slice::SlicePattern;
use std::{ops::AddAssign, simd::{u32x16, u32x4, u32x8, u8x64}};

use zeroize::Zeroizing;

pub struct DChaCha20 {
    /// This is where the initial state is stored
    state: u32x16,
    /// Calculated keystream
    keystream: u32x16,
    /// Keystream as u8 buffer
    keystream_buffer: u8x64,
    /// Digest for XORing previous ciphertext generated random bytes
    prev_dig: u8x64,
    /// Temp storage for previous ciphertext
    prev_ciph: Zeroizing<[u8; 64]>,
    xorshift: XorShiftSIMD
}

impl DChaCha20 {
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        Self {
            state: u32x16::from_array([
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
            keystream: u32x16::from_array([0u32; 16]),
            keystream_buffer: u8x64::from_array([0u8; 64]),
            prev_dig: u8x64::from_array([0u8; 64]),
            prev_ciph: Zeroizing::new([0u8; 64]),
            xorshift: XorShiftSIMD::new()
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
        self.state.copy_to_slice(self.keystream.as_mut_array());
        Self::rounds(self.keystream.as_mut_array());
        self.keystream.add_assign(&self.state);
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
            if chunk.len() == 64 {
                self.prev_dig ^= u8x64::from_slice(chunk);
            } else {
                self.xorshift.set_seed(chunk.as_ref());
                self.xorshift.xor_with_slice(self.prev_dig.as_mut_array());
            }
        }
    }

    pub fn decrypt(&mut self, ciphertext: &mut [u8]) {
        for chunk in ciphertext.chunks_mut(64) {
            if chunk.len() != 64 {
                self.xorshift.set_seed(chunk.as_ref());
            } else {
                self.prev_ciph.copy_from_slice(chunk.as_slice());
            }
            self.apply_keystream(chunk);
            if chunk.len() == 64 {
                self.prev_dig ^= u8x64::from_slice(self.prev_ciph.as_slice());
            } else {
                self.xorshift.xor_with_slice(self.prev_dig.as_mut_array());
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


struct XorShiftSIMD {
    state: u32x8,
    len: usize
}

impl XorShiftSIMD {
    pub fn new() -> Self {
        Self {
            state: u32x8::from_array([0; 8]),
            len: 0
        }
    }

    pub fn set_seed(&mut self, seed: &[u8]) {
        let s    = self.state.as_mut_array();
        self.len = seed.len();
        for (i, numb) in seed.chunks(4).take(8).enumerate() {
            s[i] = 0;
            for (pos, byte) in numb.iter().enumerate() {
                s[i] = s[i].wrapping_add(
                    (*byte as u32) <<  (pos * 8)
                );
            }
        }
    }

    fn xor_with_slice(&mut self, slice: &mut [u8; 64]) {
        if self.len < 16 {
            let s = &mut self.state.as_mut_array()[0];
            for b in &mut *slice {
                *s ^= *s << 13;
                *s ^= *s >> 17;
                *s ^= *s << 5;
                *b ^= (*s & 255) as u8;
            }
        } else if self.len < 32 {
            let mut s = u32x4::from_slice(self.state.as_array()[0..4].as_slice());
            let mut p = 0;
            for _ in 0..16 {
                s ^= s << 13;
                s ^= s >> 17;
                s ^= s << 5;
                for b in 0..4 {
                    slice[p] ^= (s[b] & 255) as u8;
                    p += 1;
                }
            }
        } else {
            let mut s = u32x8::from_slice(self.state.as_array()[0..8].as_slice());
            let mut p = 0;
            for _ in 0..8 {
                s ^= s << 13;
                s ^= s >> 17;
                s ^= s << 5;
                for b in 0..8 {
                    slice[p] ^= (s[b] & 255) as u8;
                    p += 1;
                }
            }
        }
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

        let msg  = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".as_bytes().to_vec();
        let msg1 = "111111111".as_bytes().to_vec();
        let msg2 = "1111111112222222222222222222".as_bytes().to_vec();
        let msg3 = "1111111112222222222222222222333333".as_bytes().to_vec();

        let mut cipher = DChaCha20::new(&key, &nonce);
        let mut cipher1 = DChaCha20::new(&key, &nonce);
        
        let mut buffer1 = msg.clone();
        let mut buffer2 = msg.clone();
        let mut buffer3 = msg.clone();
        let mut buffer4 = msg1.clone();
        let mut buffer5 = msg2.clone();
        let mut buffer6 = msg3.clone();

        cipher.encrypt(&mut buffer1);
        cipher.encrypt(&mut buffer2);
        cipher.encrypt(&mut buffer3);
        cipher.encrypt(&mut buffer4);
        cipher.encrypt(&mut buffer5);
        cipher.encrypt(&mut buffer6);


        assert_eq!(buffer1, hex!("e3647a29ded31528ef56bac70f7a7ac3b735c7444da42d99823ef9938c8ebfdcf05bb71a822c62981aa1ea608f47933f2ed755b62d9312ae72037674f3e93e24af4752faf1a6a9e9b4e1ed88d176150e4f4ebde616fd5f0e8e141f5f61081ed71912d8dc9e6c1f65dab4fa8d0009206223b5"));

        assert_eq!(buffer2, hex!("baa993a9d12b536004c7c88e1495bad4ff4e76d0300a107631071ddc547353ad41ab964a399ad38e241539eadbc82348d7c5b2c90261ffd680f973c83b8ab31583466f9a5bedd74009b240aea81c31d79e7fbf65f7ee336c63cc4695d25f779523ab3774ac4bec6f1647f9e3a0f7a044a5b8"));

        assert_eq!(buffer3, hex!("9b30a8c27dcfc009452d9e9513ec4f6c2de03b67f6f93dc68f7bec8a46fb21394c5fc1380718ae60134b0010a18be6af46a7e1cf1b0d0cd3b5d4e8a617bddfbe478f5d0ced2d7415c61f46a4af5519872f3b19ccdced672e6b7e96ac272955ace8a0800f6d21b1f07e701cc9865614005584"));
        
        assert_eq!(buffer4, hex!("67d74ed67435de1e63"));
        assert_eq!(buffer5, hex!("022a199635c83fc3604f804bafdb3f121b888350693d0a0db31ac3e0"));
        assert_eq!(buffer6, hex!("ce34b79c788723be97da5c3f661420b64131ccbfcfd9e92eec9981a76ce5ddecc203"));

        cipher1.decrypt(&mut buffer1);
        cipher1.decrypt(&mut buffer2);
        cipher1.decrypt(&mut buffer3);
        cipher1.decrypt(&mut buffer4);
        cipher1.decrypt(&mut buffer5);
        cipher1.decrypt(&mut buffer6);

        assert_eq!(buffer1, msg);
        assert_eq!(buffer2, msg);
        assert_eq!(buffer3, msg);
        assert_eq!(buffer4, msg1);
        assert_eq!(buffer5, msg2);
        assert_eq!(buffer6, msg3);
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
