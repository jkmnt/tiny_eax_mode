import struct
import xtea

try:
    from Crypto.Cipher import AES

    class AESCfg:
        BLOCKSIZE = 16
        BLOCKSIZE_MASK = (1 << 128) - 1
        ENDIAN = 'big'

        class ECB:
            def __init__(self, key):
                self.enc = AES.new(key, AES.MODE_ECB)
            def run(self, pt):
                return self.enc.encrypt(pt)
except:
    pass

class XTEACfg:

    BLOCKSIZE = 8
    BLOCKSIZE_MASK = (1 << 64) - 1
    ENDIAN = 'little'

    class ECB:
        def __init__(self, key):
            self.enc  = xtea.XTEA(key)
        def run(self, pt):
            return self.enc.encrypt(pt)
