import json

def hexy(s):
    return ', '.join(['0x%02x' % c for c in s])

def produce_py_vectors(vectors):
    txts = []
    for v in vectors:
        txt = '''
    [
        # key
        [%s],
        # nonce
        [%s],
        # header
        [%s],
        # plaintext
        [%s],
        # cyphertext
        [%s],
        # tag
        [%s],
    ]''' % tuple([hexy(h) for h in v])
        txts.append(txt)

    template = '''
VECTORS = [
%s
]''' % ',\n'.join(txts)

    return template

def produce_c_vectors(vectors):
    txts = []
    for v in vectors:
        txt = '''
    {
        %d, %d, %d, %d, %d, %d,
        // key
        {%s},
        // nonce
        {%s},
        // header
        {%s},
        // plaintext
        {%s},
        // cyphertext
        {%s},
        // tag
        {%s},
    }''' % tuple([len(h) for h in v] + [hexy(h) for h in v])
        txts.append(txt)

    template = '''
typedef struct
{
    int keylen;
    int noncelen;
    int headerlen;
    int ptlen;
    int ctlen;
    int taglen;
    uint8_t key[16];
    uint8_t nonce[256];
    uint8_t header[256];
    uint8_t pt[256];
    uint8_t ct[256];
    uint8_t tag[8];
} xtea_eax_testvector_t;

const xtea_eax_testvector_t xtea_eax_testvectors[] =
{
    %s
};
''' % ',\n'.join(txts)
    return template


with open('vectors.json', 'r') as f:
    vectors = json.load(f)

with open('vectors.py', 'w') as f:
     f.write(produce_py_vectors(vectors))

with open('vectors.h', 'w') as f:
     f.write(produce_c_vectors(vectors))
