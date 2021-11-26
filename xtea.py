MASK32 = (1 << 32) - 1

class XTEA:
    def __init__(self, key, rounds=32):
        if len(key) != 16:
            raise Exception('Expecting the 128 bit (16 bytes) key')

        key = int.from_bytes(key, 'little', signed=False)
        keywords = (key >> 0) & MASK32, (key >> 32) & MASK32, (key >> 64) & MASK32, (key >> 96) & MASK32,

        schkey = []
        # schedule the key for 32 rounds to move it out of enc loop
        sum = 0
        delta = 0x9E3779B9
        for round in range(rounds):
            k0 = (sum + keywords[sum & 3]) & MASK32
            sum = (sum + delta) & MASK32
            k1 = (sum + keywords[(sum>>11) & 3]) & MASK32
            schkey.append((k0, k1))
        self.schkey = schkey

    def encrypt(self, pt):
        pt = int.from_bytes(pt, 'little', signed=False)
        v0, v1 = (pt >> 0) & MASK32, (pt >> 32) & MASK32
        for schkey in self.schkey:
            v0 = (v0 + ((((v1<<4) ^ (v1>>5)) + v1) ^ schkey[0])) & MASK32
            v1 = (v1 + ((((v0<<4) ^ (v0>>5)) + v0) ^ schkey[1])) & MASK32
        ct = (v1 << 32) | v0
        return ct.to_bytes(8, 'little')
