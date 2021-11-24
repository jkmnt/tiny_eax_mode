# the implementation is coded to match test vectors for AES-EAX from libtomcrypt:
# https://github.com/libtom/libtomcrypt/blob/develop/src/encauth/eax/eax_test.c
#
# and then the blocksize is changed to 8 bytes and underlying cypher is swapped to xtea

def gf_double(a, blocksize):
    if blocksize == 16:
        if a >> 127:
            a = (a << 1) ^ 0x87 # 0x87 for the 128 bit
        else:
            a = a << 1
    else:
        if a >> 63:
            a = (a << 1) ^ 0x1B # 0x1B for 64 bit
        else:
            a = a << 1
    return a & ((1 << (blocksize * 8)) - 1)


def xorstrings(b0, b1):
    return bytes([a^b for a, b in zip(b0, b1)])

# simple pythonic implementations. the streamlike interface is in eax_stream
def ctr(cfg, key, data, nonce):
    enc = cfg.ECB(key)
    out = b''

    nonce_int = int.from_bytes(nonce, byteorder=cfg.ENDIAN, signed=False)

    cnt = 0
    for i in range(0, len(data), cfg.BLOCKSIZE):
        block = data[i:i+cfg.BLOCKSIZE]
        k = (nonce_int + cnt) & cfg.BLOCKSIZE_MASK
        k = k.to_bytes(cfg.BLOCKSIZE, byteorder=cfg.ENDIAN)
        xorbuf = enc.run(k)
        out += xorstrings(block, xorbuf)
        cnt += 1
    return out

def omac(cfg, key, data, k):
    enc = cfg.ECB(key)

    L = enc.run(bytes([0] * cfg.BLOCKSIZE))
    L_int = int.from_bytes(L, byteorder=cfg.ENDIAN, signed=False)

    L2_int = gf_double(L_int, cfg.BLOCKSIZE)
    L4_int = gf_double(L2_int, cfg.BLOCKSIZE)

    L2 = L2_int.to_bytes(cfg.BLOCKSIZE, byteorder=cfg.ENDIAN)
    L4 = L4_int.to_bytes(cfg.BLOCKSIZE, byteorder=cfg.ENDIAN)

    data = bytes([0] * (cfg.BLOCKSIZE - 1) + [k]) + data
    data = bytearray(data)

    if len(data) % cfg.BLOCKSIZE:
        data += bytes([0x80])
        data = data.ljust((len(data) + cfg.BLOCKSIZE - 1) & -cfg.BLOCKSIZE, b'\0')
        data[-cfg.BLOCKSIZE:] = xorstrings(data[-cfg.BLOCKSIZE:], L4)
    else:
        data[-cfg.BLOCKSIZE:] = xorstrings(data[-cfg.BLOCKSIZE:], L2)

    mac = bytes(cfg.BLOCKSIZE)

    for i in range(0, len(data), cfg.BLOCKSIZE):
        block = data[i:i+cfg.BLOCKSIZE]
        xorred = xorstrings(block, mac)
        mac = enc.run(xorred)

    return mac


def eax_enc(cfg, key, nonce, header, pt):
    N = omac(cfg, key, nonce, 0)
    H = omac(cfg, key, header, 1)
    ct = ctr(cfg, key, pt, N)
    C = omac(cfg, key, ct, 2)
    tag = xorstrings(xorstrings(N, C), H)
    return (ct, tag)


def eax_dec(cfg, key, nonce, header, ct):
    N = omac(cfg, key, nonce, 0)
    H = omac(cfg, key, header, 1)
    C = omac(cfg, key, ct, 2)
    tag_local = xorstrings(xorstrings(N, C), H)
    pt = ctr(cfg, key, ct, N)
    return (pt, tag_local)
