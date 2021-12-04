#include <stdint.h>
#include <string.h>
#include "eax128.h"

#define BIG_CTR     1
#define BIG_TAIL    1

#define USE_CUSTOM_MATH128 0    // use user-coded 128bit math (assembly or something)

extern void _add128be_32le(uint32_t dst[4], const uint32_t a[4], uint32_t inc);
extern void _add128le_32le(uint32_t dst[4], const uint32_t a[4], uint32_t inc);
extern void _gf_double_128be(uint32_t dst[4], const uint32_t src[4], int n);
extern void _gf_double_128le(uint32_t dst[4], const uint32_t src[4], int n);
extern void _xor128(uint32_t dst[4], const uint32_t a[4], const uint32_t b[4]);

static uint64_t byterev64(uint64_t a)
{
    return    (((a >>  0) & 0xff) << 56)
            | (((a >>  8) & 0xff) << 48)
            | (((a >> 16) & 0xff) << 40)
            | (((a >> 24) & 0xff) << 32)
            | (((a >> 32) & 0xff) << 24)
            | (((a >> 40) & 0xff) << 16)
            | (((a >> 48) & 0xff) <<  8)
            | (((a >> 56) & 0xff) <<  0);
}


static void gf_double(eax128_block_t *dst, eax128_block_t *src, int n)
{
    if (USE_CUSTOM_MATH128)
    {
        BIG_TAIL ? _gf_double_128be(dst->w, src->w, n) : _gf_double_128le(dst->w, src->w, n);
        return;
    }

    uint64_t q0 = BIG_TAIL ? byterev64(src->q[1]) : src->q[0];
    uint64_t q1 = BIG_TAIL ? byterev64(src->q[0]) : src->q[1];

    do
    {
        uint32_t m = (((int32_t)(q1 >> 32)) >> 31) & 0x87;
        q1 = (q1 << 1) | (q0 >> 63);
        q0 = (q0 << 1) ^ m;
    } while(--n);

    dst->q[0] = BIG_TAIL ? byterev64(q1) : q0;
    dst->q[1] = BIG_TAIL ? byterev64(q0) : q1;
}


static void add_ctr(eax128_block_t *dst, const eax128_block_t *a, uint32_t inc)
{
    if (USE_CUSTOM_MATH128)
    {
        BIG_CTR ? _add128be_32le(dst->w, a->w, inc) : _add128le_32le(dst->w, a->w, inc);
        return;
    }

    uint64_t q0 = BIG_CTR ? byterev64(a->q[1]) : a->q[0];
    uint64_t q1 = BIG_CTR ? byterev64(a->q[0]) : a->q[1];

    q0 += inc;

    if (q0 < (uint64_t)inc)
        q1 += 1;

    dst->q[0] = BIG_CTR ? byterev64(q1) : q0;
    dst->q[1] = BIG_CTR ? byterev64(q0) : q1;
}


static void xor128(eax128_block_t *dst, const eax128_block_t *a, const eax128_block_t *b)
{
    if (USE_CUSTOM_MATH128)
    {
        _xor128(dst->w, a->w, b->w);
        return;
    }

    dst->q[0] = a->q[0] ^ b->q[0];
    dst->q[1] = a->q[1] ^ b->q[1];
}


void eax128_omac_init(eax128_omac_t *ctx, void *cipher_ctx, int k)
{
    memset(ctx, 0, sizeof(eax128_omac_t));
    ctx->block.b[15] = k;
    ctx->cipher_ctx = cipher_ctx;
}

void eax128_omac_process(eax128_omac_t *ctx, int byte)
{
    // got full block here, convert it
    if (ctx->bytepos == 0)
    {
        xor128(&ctx->mac, &ctx->mac, &ctx->block);
        eax128_cipher(ctx->cipher_ctx, ctx->mac.b);
        ctx->block.q[0] = 0;
        ctx->block.q[1] = 0;
    }

    ctx->block.b[ctx->bytepos] = byte;
    ctx->bytepos = (ctx->bytepos + 1) & 15;
}

eax128_block_t *eax128_omac_digest(eax128_omac_t *ctx)
{
    if (ctx->bytepos != 0)
        ctx->block.b[ctx->bytepos] = 0x80;

    xor128(&ctx->mac, &ctx->mac, &ctx->block);

    // now block is no longer needed, reuse it as tail
    eax128_block_t *tail = &ctx->block;
    tail->q[0] = 0;
    tail->q[1] = 0;
    eax128_cipher(ctx->cipher_ctx, tail->b);
    gf_double(tail, tail, ctx->bytepos == 0 ? 1 : 2);

    xor128(&ctx->mac, &ctx->mac, tail);
    eax128_cipher(ctx->cipher_ctx, ctx->mac.b);

    return &ctx->mac;
}

void eax128_omac_clear(eax128_omac_t *ctx)
{
    memset(ctx, 0, sizeof(eax128_omac_t));
}


void eax128_ctr_init(eax128_ctr_t *ctx, void *cipher_ctx, const uint8_t nonce[16])
{
    memset(ctx, 0, sizeof(eax128_ctr_t));
    memcpy(ctx->nonce.b, nonce, 16);
    ctx->blocknum = -1;    // something nonzero
    ctx->cipher_ctx = cipher_ctx;
}

int eax128_ctr_process(eax128_ctr_t *ctx, unsigned int pos, int byte)
{
    unsigned int blocknum = pos / 16;
    if (blocknum != ctx->blocknum)    // change of block
    {
        ctx->blocknum = blocknum;
        add_ctr(&ctx->xorbuf, &ctx->nonce, blocknum);
        eax128_cipher(ctx->cipher_ctx, ctx->xorbuf.b);
    }

    return ctx->xorbuf.b[pos % 16] ^ byte;

}

void eax128_ctr_clear(eax128_ctr_t *ctx)
{
    memset(ctx, 0, sizeof(eax128_ctr_t));
}


void eax128_init(eax128_t *ctx, void *cipher_ctx, const uint8_t *nonce, unsigned int nonce_len)
{
    // the parts of ctx are cleared by called functions

    // reuse header omac to avoid stack
    eax128_omac_t *nomac = &ctx->homac;

    eax128_omac_init(nomac, cipher_ctx, 0);
    for (unsigned int i = 0; i < nonce_len; i++)
        eax128_omac_process(nomac, nonce[i]);
    eax128_omac_digest(nomac);
    eax128_ctr_init(&ctx->ctr, cipher_ctx, nomac->mac.b);

    // this init will clear nonceomac too
    eax128_omac_init(&ctx->homac, cipher_ctx, 1);
    eax128_omac_init(&ctx->domac, cipher_ctx, 2);
}


void eax128_auth_data(eax128_t *ctx, int byte)
{
    eax128_omac_process(&ctx->domac, byte);
}

void eax128_auth_header(eax128_t *ctx, int byte)
{
    eax128_omac_process(&ctx->homac, byte);
}

int eax128_crypt_data(eax128_t *ctx, unsigned int pos, int byte)
{
    return eax128_ctr_process(&ctx->ctr, pos, byte);
}

void eax128_digest(eax128_t *ctx, uint8_t tag[16])
{
    eax128_block_t *t = (eax128_block_t *)(void *)tag;

    eax128_omac_digest(&ctx->domac);
    eax128_omac_digest(&ctx->homac);

    xor128(t, &ctx->domac.mac, &ctx->homac.mac);
    xor128(t, t, &ctx->ctr.nonce);

    eax128_omac_clear(&ctx->domac);
    eax128_omac_clear(&ctx->homac);
}

void eax128_clear(eax128_t *ctx)
{
    memset(ctx, 0, sizeof(eax128_t));
}
