import json

from cfgs import XTEACfg
import eax as eax

# the vectors are self-generated and specific to implementation
with open('vectors_eax_xtea.json', 'r') as f:
    VECTORS = json.load(f)

    for vector in VECTORS:
        key, nonce, header, pt, ct, tag = vector
        key = bytes(key)
        nonce = bytes(nonce)
        pt = bytes(pt)
        header = bytes(header)
        ct = bytes(ct)
        tag = bytes(tag)
        enc = eax.eax_enc(XTEACfg, key, nonce, header, pt)
        if enc[0] != ct or enc[1] != tag:
            raise Exception('Encrypt failed', vector, enc)

        dec = eax.eax_dec(XTEACfg, key, nonce, header, ct)
        if dec[0] != pt or dec[1] != tag:
            raise Exception('Decrypt failed', vector, dec)
