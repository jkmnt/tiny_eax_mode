import struct

MASK32 = (1 << 32) - 1

class XTEA:
    def __init__(self, key, rounds=32):
        self.keywords = struct.unpack('<IIII', key)
        schkey = []
        # schedule the key for 32 rounds to move it out of enc loop
        sum = 0
        delta = 0x9E3779B9
        for round in range(rounds):
            k0 = (sum + self.keywords[sum & 3]) & MASK32
            sum = (sum + delta) & MASK32
            k1 = (sum + self.keywords[(sum>>11) & 3]) & MASK32
            schkey.append((k0, k1))
        self.schkey = schkey

    def encrypt(self, pt):
        v0, v1 = struct.unpack('<II', pt)
        for schkey in self.schkey:
            v0 = (v0 + ((((v1<<4) ^ (v1>>5)) + v1) ^ schkey[0])) & MASK32
            v1 = (v1 + ((((v0<<4) ^ (v0>>5)) + v0) ^ schkey[1])) & MASK32
        return struct.pack('<II', v0, v1)
