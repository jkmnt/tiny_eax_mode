#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>

#include "eax128.h"
#include "aes128.h"

#include "vectors_eax_aes.h"

typedef struct
{
    uint32_t words[AES128_KMSTORE_NWORDS];
} aes_kmstore_t;

static aes_kmstore_t aes_kmstore;

void aes128_save_km(void *ctx, int i, uint32_t w)
{
    aes_kmstore_t *store = ctx;
    store->words[i] = w;
}

uint32_t aes128_load_km(void *ctx, int i)
{
    const aes_kmstore_t *store = ctx;
    return store->words[i];
}

void aes_install_key(const uint8_t *key)
{
    aes128_set_key(&aes_kmstore, key);
}


void print64(uint64_t q)
{
    printf("%08x%08x", (uint32_t)(q >> 32), (uint32_t)q);
}

void print_dump(const void *data, int len)
{
    const uint8_t *p = data;
    int col = 0;
    const int max_cols = 8;

    while (col < len)
    {
        if (!(col % max_cols))
            printf("\n%08x:", col);
        printf(" %02x", *p);
        p++;
        col++;
    }
    printf("\n");
}

extern void eax128_cipher(void *ctx, uint8_t block[16])
{
    aes128_encrypt_ecb(&aes_kmstore, block);
}

static void test_vector(const testvector_t *v)
{
    eax128_t ctx;

    aes_install_key(v->key);

    eax128_init(&ctx, NULL, v->nonce, v->noncelen);

    uint8_t pt[256];

    for (int i = 0; i < v->headerlen; i++)
        eax128_auth_header(&ctx, v->header[i]);

    for (int i = 0; i < v->ctlen; i++)
        eax128_auth_ct(&ctx, v->ct[i]);

    for (int i = 0; i < v->ctlen; i++)
    {
        pt[i] = eax128_decrypt_ct(&ctx, i, v->ct[i]);
    }

    uint8_t local_tag[16];
    eax128_digest(&ctx, local_tag);

    if (memcmp(pt, v->pt, v->ptlen) != 0)
    {
        print_dump(pt, v->ptlen);
        print_dump(v->pt, v->ptlen);
        printf("decrypt fail\n");
        exit(-1);
    }

    if (memcmp(local_tag, v->tag, v->taglen) != 0)
    {
        print_dump(v->tag, v->taglen);
        print_dump(local_tag, v->taglen);
        printf("auth fail\n");
        exit(-1);
    }
}

// special test to be sure the 64 bit nonce addition is running fine
static void test_ctr_ovf(void)
{
    uint8_t key[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};
    uint8_t nonce[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfd};
    uint8_t pt[] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
                    0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24,
                    0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f};
    uint8_t ct[] = {0xfc, 0x55, 0xa7, 0x76, 0xe8, 0xfa, 0x9f, 0x5e, 0x7b, 0x6f, 0xf2, 0xdc, 0xeb, 0x4b, 0xf7, 0xb5, 0x26, 0xda,
                    0xfa, 0xb4, 0x0d, 0xda, 0xde, 0x1b, 0x69, 0xab, 0x95, 0x8c, 0xbb, 0xa0, 0xa3, 0x1a, 0x19, 0x86, 0xcd, 0x29, 0x2e, 0x7d,
                    0x74, 0x8f, 0x97, 0xfb, 0x29, 0x08, 0x68, 0x92, 0xba, 0x3d, 0x23, 0x29, 0xa8, 0x59, 0xd0, 0x9e, 0x31, 0x99, 0x48, 0x9a, 0x90, 0x86, 0x0c, 0x83, 0xa7, 0xe1};

    eax128_ctr_t ctr;

    aes_install_key(key);
    eax128_ctr_init(&ctr, &aes_kmstore, nonce);

    for (int i = 0; i < sizeof(pt); i++)
    {
        int ptb = eax128_ctr_process(&ctr, i, pt[i]);
        if (ptb != ct[i])
        {
            printf("ctr failed\n");
            exit(-1);
        }
    }
}

int main(void)
{
    test_ctr_ovf();

    for (int i = 0; i < sizeof(testvectors) / sizeof(testvectors[0]); i++)
        test_vector(&testvectors[i]);

    printf("Ok");
    return 0;
}
