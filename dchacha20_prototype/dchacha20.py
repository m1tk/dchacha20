import numpy as np
import struct

def chunked(size, source):
    for i in range(0, len(source), size):
        yield source[i:i+size]


# overflow is not a problem
np.seterr(over='ignore')

class DChaCha20():
    def __init__(self, key, nonce):
        self.block_counter = 0
        # Declaring state
        # Here we are using fixed size int to handle overflow edge cases
        state = np.empty(shape=16, dtype=np.uint32)
        state[:4] = np.array([0x61707865, 0x3320646E, 0x79622D32, 0x6B206574], dtype=np.uint32)
        # 4..11 from the key
        state[4:12] = struct.unpack("<8L", key)
        state[12]   = self.block_counter
        # nonce
        state[13:]  = struct.unpack("<3L", nonce)

        self.state = state

        self.prev_dig = [0] * 64

    def quarter_round(self, a, b, c, d):
        a = (a + b)
        d = (d ^ a)
        d = (d << 16 | d >> 16)
        c = (c + d)
        b = (b ^ c)
        b = (b << 12 | b >> 20)
        a = (a + b)
        d = (d ^ a)
        d = (d << 8 | d >> 24)
        c = (c + d)
        b = (b ^ c)
        b = (b << 7 | b >> 25)
        return a, b, c, d

    def rounds(self, state):
        steps = [
            [0, 4, 8, 12],
            [1, 5, 9, 13],
            [2, 6, 10, 14],
            [3, 7, 11, 15],
            [0, 5, 10, 15],
            [1, 6, 11, 12],
            [2, 7, 8, 13],
            [3, 4, 9, 14],
        ]
        for _ in range(10):
            for r in steps:
                state[r] = self.quarter_round(*(state[r]))
        return state

    def block_fn(self):
        self.state[12] = self.block_counter
        state     = self.rounds(self.state.copy())
        state     = state + self.state
        self.block_counter += 1
        return state
        
    def encrypt_inner(self, plaintext):
        # calling block function
        state      = self.block_fn()
        # serializing final state
        stream     = struct.pack("<16L", *state)
        # XOR
        ciphertext = bytes([a ^ b ^ c for a, b, c in zip(stream, plaintext, self.prev_dig)])
        
        return ciphertext
    
    def encrypt(self, plaintext):
        chunk = b''
        for i in chunked(64, plaintext):
            ciphertext = self.encrypt_inner(i)
            self.prev_dig = [a ^ b for a, b in zip(XorShiftSIMD(ciphertext).random_bytes(64) if len(ciphertext) < 64 else ciphertext, self.prev_dig)]
            chunk += ciphertext
        return chunk


    def decrypt(self, ciphertext):
        chunk = b''
        for i in chunked(64, ciphertext):
            plaintext = self.encrypt_inner(i)
            self.prev_dig = [a ^ b for a, b in zip(XorShiftSIMD(i).random_bytes(64) if len(i) < 64 else i, self.prev_dig)]
            chunk += plaintext
        return chunk

class XorShiftSIMD:
    def __init__(self, seed):
        if len(seed) % 4 != 0:
            seed = seed + bytearray(4 - (len(seed) % 4))

        self.state = np.frombuffer(seed, dtype="<u4").copy()

    def gen_rand(self, rand):
        if len(self.state) < 4:
            grp = 64
            byt = 1
        elif len(self.state) < 8:
            grp = 16
            byt = 4
        else:
            grp = 8
            byt = 8

        p = 0
        for i in range(0, grp):
            for j in range(0, byt):
                self.state[j] ^= self.state[j] << 13
                self.state[j] ^= self.state[j] >> 17
                self.state[j] ^= self.state[j] << 5
            for b in range(0, byt):
                rand[p] = self.state[b] % 256
                p += 1

    def random_bytes(self, n):
        rand = bytearray(n)
        self.gen_rand(rand)
        return bytes(rand)
