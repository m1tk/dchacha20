use zeroize::Zeroizing;

pub struct ChaCha20 {
    /// This is where the initial state is stored
    state: Zeroizing<[u32; 16]>,
    /// Calculated keystream
    keystream: Zeroizing<[u32; 16]>,
    /// Keystream as u8 buffer
    keystream_buffer: Zeroizing<[u8; 64]>
}

impl ChaCha20 {
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
            keystream_buffer: Zeroizing::new([0u8; 64])
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

        for (byte, k) in buff.iter_mut().zip(self.keystream_buffer.iter()) {
            *byte ^= *k;
        }
    }

    pub fn encrypt(&mut self, plaintext: &mut [u8]) {
        for chunk in plaintext.chunks_mut(64) {
            self.apply_keystream(chunk);
        }
    }

    pub fn decrypt(&mut self, ciphertext: &mut [u8]) {
        for chunk in ciphertext.chunks_mut(64) {
            self.apply_keystream(chunk);
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


#[cfg(test)]
mod tests {
    use hex_literal::hex;
    use rand::RngCore;

    use super::ChaCha20;

    #[test]
    fn validate() {
        let key = hex!("00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f 10 11 12 13 14 15 16 17 18 19 1a 1b 1c 1d 1e 1f");
        let nonce = hex!("00 00 00 00 00 00 00 4a 00 00 00 00");

        let msg = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".as_bytes().to_vec();

        let mut cipher = ChaCha20::new(&key, &nonce);
        let mut cipher1 = ChaCha20::new(&key, &nonce);
        
        let mut buffer1 = msg.clone();
        let mut buffer2 = msg.clone();
        let mut buffer3 = msg.clone();

        cipher.encrypt(&mut buffer1);
        cipher.encrypt(&mut buffer2);
        cipher.encrypt(&mut buffer3);

        assert_eq!(buffer1, hex!("e3647a29ded31528ef56bac70f7a7ac3b735c7444da42d99823ef9938c8ebfdcf05bb71a822c62981aa1ea608f47933f2ed755b62d9312ae72037674f3e93e244c2328d32f75bcc15bb7574fde0c6fcdf87b7aa25b5972970c2ae6cced86a10be9496fc61c407dfdc01510ed8f4eb35d0d62"));

        assert_eq!(buffer2, hex!("25c710f65a102f204caede6f8923b01243b9510350d6ea538781a01aa76038364aab01bc3aa415b0fb47a3abb0545e489c161867534f7cc7ed899c9156e4e482a6817f6c01fdf860451c9ec1213f81c5ddc6ee66a738d93fe44de68f753f4fa3690036c896eff9dfed005a4810a3fe0c39ae"));

        assert_eq!(buffer3, hex!("e2b2918e9ffe293d5e01676f500ab8ff0492462b0dd8a056111de080861d1a72baad5228a3e09fe296d56d86e4db61cce87e7f1735ca431f85a3650416d4ed49a53dcc8272d35d28981e21cbff5fa1782ba95fe7d135c7787a63762ca1344fde520dd227cec12e12e8a5714f628d75ccbdfa"));

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

        let mut cipher = ChaCha20::new(&key, &nonce);
        let mut cipher1 = ChaCha20::new(&key, &nonce);

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
