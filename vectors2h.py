import json

def hexy(s):
    return ', '.join(['0x%02x' % c for c in s])

def produce_c_vectors(vectors):
    entries = []

    for v in vectors:
        entry = '''
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
        entries.append(entry)

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
    uint8_t tag[16];
} testvector_t;

const testvector_t testvectors[] =
{
    %s
};

''' % (',\n'.join(entries))
    return template


with open('vectors_eax_xtea.json', 'r') as f:
    vectors = json.load(f)

with open('vectors_eax_xtea.h', 'w') as f:
     f.write(produce_c_vectors(vectors))


with open('vectors_eax_aes.json', 'r') as f:
    vectors = json.load(f)

with open('vectors_eax_aes.h', 'w') as f:
     f.write(produce_c_vectors(vectors))
