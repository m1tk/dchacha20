use zeroize::Zeroizing;



pub struct DChaCha20 {
    state: Zeroizing<[u32; 16]>
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
            ])
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
