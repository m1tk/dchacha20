use std::{ops::AddAssign, simd::{u32x16, u32x4, u8x64, ToBytes}};

pub struct ChaCha20 {
    /// This is where the initial state is stored
    state: u32x16,
    /// Calculated keystream
    keystream: u32x16
}

impl ChaCha20 {
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
            keystream: u32x16::from_array([0u32; 16])
        }
    }

    #[inline(always)]
    fn quarter_round(a: &mut u32x4, b: &mut u32x4, c: &mut u32x4, d: &mut u32x4) {
        a.add_assign(*b);
        *d ^= *a;
        *d  = (*d << 16) | (*d >> 16);
        c.add_assign(*d);
        *b ^= *c;
        *b  = (*b << 12) | (*b >> 20);
        a.add_assign(*b);
        *d ^= *a;
        *d  = (*d << 8) | (*d >> 24);
        c.add_assign(*d);
        *b ^= *c;
        *b  = (*b << 7) | (*b >> 25);
    }

    #[inline(always)]
    fn rounds(state: &mut u32x16) {
        let mut a = u32x4::from_slice(&state[0..4]);
        let mut b = u32x4::from_slice(&state[4..8]);
        let mut c = u32x4::from_slice(&state[8..12]);
        let mut d = u32x4::from_slice(&state[12..16]);
        for _ in 0..10 {
            // column round
            Self::quarter_round(&mut a, &mut b, &mut c, &mut d);

            // diagonal round
            b = u32x4::from_array([b[1], b[2], b[3], b[0]]);
            c = u32x4::from_array([c[2], c[3], c[0], c[1]]);
            d = u32x4::from_array([d[3], d[0], d[1], d[2]]);

            Self::quarter_round(&mut a, &mut b, &mut c, &mut d);

            b = u32x4::from_array([b[3], b[0], b[1], b[2]]);
            c = u32x4::from_array([c[2], c[3], c[0], c[1]]);
            d = u32x4::from_array([d[1], d[2], d[3], d[0]]);
        }

        a.copy_to_slice(&mut state[0..4]);
        b.copy_to_slice(&mut state[4..8]);
        c.copy_to_slice(&mut state[8..12]);
        d.copy_to_slice(&mut state[12..16]);
    }

    #[inline(always)]
    fn block_fn(&mut self) {
        self.keystream = self.state;
        Self::rounds(&mut self.keystream);
        self.keystream.add_assign(&self.state);
        self.state[12] = self.state[12].wrapping_add(1);
    }

    #[inline(always)]
    fn apply_keystream(&mut self, buff: &mut [u8]) {
        self.block_fn();

        if buff.len() == 64 {
            let mut b = u8x64::from_slice(buff);
            b ^= self.keystream.to_le_bytes();
            b.copy_to_slice(buff);
        } else {
            let ks = self.keystream.to_le_bytes();
            for (i, byte) in buff.iter_mut().enumerate() {
                *byte ^= ks[i];
            }
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
