#include <stdint.h>
#include <string.h>
#include "eax128.h"

#define BIG_CTR     1
#define BIG_TAIL    1

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

static void gf_double(eax128_block_t *block)
{
    uint64_t q1;
    uint64_t q0;

    if (BIG_TAIL)
    {
        q0 = byterev64(block->q[1]);
        q1 = byterev64(block->q[0]);
    }
    else
    {
        q1 = block->q[1];
        q0 = block->q[0];
    }

    uint32_t m = (q1 >> 63) * 0x87;
    q1 = (q1 << 1) ^ (q0 >> 63);
    q0 = (q0 << 1) ^ m;

    if (BIG_TAIL)
    {
        block->q[0] = byterev64(q1);
        block->q[1] = byterev64(q0);
    }
    else
    {
        block->q[0] = q0;
        block->q[1] = q1;
    }
}

static void add_ctr(eax128_block_t *out, const eax128_block_t *a, int inc)
{
    uint64_t q1;
    uint64_t q0;

    if (BIG_CTR)
    {
        q0 = byterev64(a->q[1]);
        q1 = byterev64(a->q[0]);
    }
    else
    {
        q1 = a->q[1];
        q0 = a->q[0];
    }

    q0 += inc;

    if (q0 < (uint64_t)inc)
        q1 += 1;

    if (BIG_CTR)
    {
        out->q[0] = byterev64(q1);
        out->q[1] = byterev64(q0);
    }
    else
    {
        out->q[0] = q0;
        out->q[1] = q1;
    }
}


static void xor128(eax128_block_t *block, const eax128_block_t *a)
{
    block->q[0] ^= a->q[0];
    block->q[1] ^= a->q[1];
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
        xor128(&ctx->mac, &ctx->block);
        eax128_cipher(ctx->mac.b, ctx->cipher_ctx);
        ctx->block.q[0] = 0;
        ctx->block.q[1] = 0;
    }

    ctx->block.b[ctx->bytepos] = byte;
    ctx->bytepos = (ctx->bytepos + 1) & 15;
}

eax128_block_t *eax128_omac_digest(eax128_omac_t *ctx)
{
    eax128_block_t tail = {0};
    eax128_cipher(tail.b, ctx->cipher_ctx);
    gf_double(&tail);

    if (ctx->bytepos != 0)
    {
        ctx->block.b[ctx->bytepos] = 0x80;
        gf_double(&tail);
    }

    xor128(&ctx->block, &tail);
    memset(&tail, 0, sizeof(tail));
    xor128(&ctx->mac, &ctx->block);
    eax128_cipher(ctx->mac.b, ctx->cipher_ctx);

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

int eax128_ctr_process(eax128_ctr_t *ctx, int pos, int byte)
{
    int blocknum = pos / 16;
    if (blocknum != ctx->blocknum)    // change of block
    {
        ctx->blocknum = blocknum;
        add_ctr(&ctx->xorbuf, &ctx->nonce, blocknum);
        eax128_cipher(ctx->xorbuf.b, ctx->cipher_ctx);
    }

    return ctx->xorbuf.b[pos % 16] ^ byte;

}

void eax128_ctr_clear(eax128_ctr_t *ctx)
{
    memset(ctx, 0, sizeof(eax128_ctr_t));
}


void eax128_init(eax128_t *ctx, void *cipher_ctx, const uint8_t *nonce, int nonce_len)
{
    // the parts of ctx are cleared by called functions

    // reuse header omac to avoid stack
    eax128_omac_t *nonceomac = &ctx->headermac;

    eax128_omac_init(nonceomac, cipher_ctx, 0);
    for (int i = 0; i < nonce_len; i++)
        eax128_omac_process(nonceomac, nonce[i]);
    eax128_omac_digest(nonceomac);
    eax128_ctr_init(&ctx->ctr, cipher_ctx, nonceomac->mac.b);

    // this init will clear noncemac too
    eax128_omac_init(&ctx->headermac, cipher_ctx, 1);
    eax128_omac_init(&ctx->ctomac, cipher_ctx, 2);
}


void eax128_auth_ct(eax128_t *ctx, int byte)
{
    eax128_omac_process(&ctx->ctomac, byte);
}

void eax128_auth_header(eax128_t *ctx, int byte)
{
    eax128_omac_process(&ctx->headermac, byte);
}

int eax128_decrypt_ct(eax128_t *ctx, int pos, int byte)
{
    return eax128_ctr_process(&ctx->ctr, pos, byte);
}

void eax128_digest(eax128_t *ctx, uint8_t digest[16])
{
    eax128_block_t *tag = (eax128_block_t *)(void *)digest;
    memset(tag, 0, 16);
    eax128_omac_digest(&ctx->ctomac);
    xor128(tag, &ctx->ctomac.mac);
    eax128_omac_digest(&ctx->headermac);
    xor128(tag, &ctx->headermac.mac);
    xor128(tag, &ctx->ctr.nonce);

    eax128_omac_clear(&ctx->ctomac);
    eax128_omac_clear(&ctx->headermac);
}

void eax128_clear(eax128_t *ctx)
{
    memset(ctx, 0, sizeof(eax128_t));
}
