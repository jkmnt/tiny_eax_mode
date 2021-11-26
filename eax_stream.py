from eax import gf_double, xorstrings

# these classes simulate the way it could be done in C in online mode, byte by byte
class OMAC_stream:
    def __init__(self, cfg, key, k):
        enc = cfg.ECB(key)
        L = enc.run(bytes([0] * cfg.BLOCKSIZE))
        L_int = int.from_bytes(L, cfg.ENDIAN, signed=False)

        L2_int = gf_double(L_int, cfg.BLOCKSIZE)
        L4_int = gf_double(L2_int, cfg.BLOCKSIZE)

        self.cfg = cfg
        self.L2 = L2_int.to_bytes(cfg.BLOCKSIZE, cfg.ENDIAN)
        self.L4 = L4_int.to_bytes(cfg.BLOCKSIZE, cfg.ENDIAN)

        self.enc = enc
        self.readyblock = bytes([0] * (cfg.BLOCKSIZE - 1) + [k])
        self.mac = bytes(cfg.BLOCKSIZE)
        self.buf = bytes([])

    def process_byte(self, byte):
        cfg = self.cfg
        self.buf += bytes([byte])
        if len(self.buf) == cfg.BLOCKSIZE:  # full buf collected, ok. process prev
            xorred = xorstrings(self.readyblock, self.mac)
            self.mac = self.enc.run(xorred)
            self.readyblock = self.buf
            self.buf = bytes([])

    def digest(self):
        readyblock = self.readyblock
        buf = self.buf
        mac = self.mac
        cfg = self.cfg

        if not buf: # readyblock is last
            readyblock = xorstrings(readyblock, self.L2)

        xorred = xorstrings(readyblock, mac)
        mac = self.enc.run(xorred)

        if buf:
            buf += bytes([0x80])
            buf = buf.ljust((len(buf) + cfg.BLOCKSIZE - 1) & -cfg.BLOCKSIZE, b'\0')
            xorred = xorstrings(xorstrings(buf, self.L4), mac)
            mac = self.enc.run(xorred)

        return mac


class CTR_stream:
    def __init__(self, cfg, key, nonce):
        enc = cfg.ECB(key)
        nonce_int = int.from_bytes(nonce, cfg.ENDIAN, signed=False)

        self.cfg = cfg
        self.enc = enc
        self.nonce = nonce_int
        self.pos = 0
        self.xorbuf = None

    def process_byte(self, byte):
        cfg = self.cfg
        if self.pos % cfg.BLOCKSIZE == 0:
            counter = (self.nonce + self.pos // cfg.BLOCKSIZE) & cfg.BLOCKSIZE_MASK
            counter = counter.to_bytes(cfg.BLOCKSIZE, cfg.ENDIAN)
            self.xorbuf = self.enc.run(counter)

        pt = self.xorbuf[self.pos % cfg.BLOCKSIZE] ^ byte
        self.pos += 1
        return bytes([pt])

# wrappers for the online stream api to test it
def omac_stream(cfg, key, data, k):
    s = OMAC_stream(cfg, key, k)
    for b in data:
        s.process_byte(b)
    return s.digest()

def ctr_stream(cfg, key, data, nonce):
    s = CTR_stream(cfg, key, nonce)
    out = b''
    for b in data:
        out += s.process_byte(b)
    return out


def eax_enc(cfg, key, nonce, header, pt):
    N = omac_stream(cfg, key, nonce, 0)
    H = omac_stream(cfg, key, header, 1)
    ct = ctr_stream(cfg, key, pt, N)
    C = omac_stream(cfg, key, ct, 2)
    tag = xorstrings(xorstrings(N, C), H)
    return (ct, tag)

def eax_dec(cfg, key, nonce, header, ct):
    N = omac_stream(cfg, key, nonce, 0)
    H = omac_stream(cfg, key, header, 1)
    C = omac_stream(cfg, key, ct, 2)
    tag_local = xorstrings(xorstrings(N, C), H)
    pt = ctr_stream(cfg, key, ct, N)
    return (pt, tag_local)
