#include <stdint.h>
#include <string.h>
#include "eax64.h"

static uint64_t gf_double(uint64_t a)
{
    return (a << 1) ^ ((a >> 63) * 0x1B);
}

void eax64_omac_init(eax64_omac_t *ctx, void *cipher_ctx, int k)
{
    memset(ctx, 0, sizeof(eax64_omac_t));
    ctx->block.b[7] = k;
    ctx->cipher_ctx = cipher_ctx;
}

void eax64_omac_process(eax64_omac_t *ctx, int byte)
{
    if (ctx->bytepos == 0)
    {
        ctx->mac = eax64_cipher(ctx->block.q ^ ctx->mac, ctx->cipher_ctx);
        ctx->block.q = 0;

    }

    ctx->block.b[ctx->bytepos] = byte;
    ctx->bytepos = (ctx->bytepos + 1) & 7;
}

uint64_t eax64_omac_digest(eax64_omac_t *ctx)
{
    uint64_t tail = eax64_cipher(0, ctx->cipher_ctx);
    tail = gf_double(tail);

    if (ctx->bytepos != 0)
    {
        tail = gf_double(tail);
        ctx->block.b[ctx->bytepos] = 0x80;
    }

    ctx->mac = eax64_cipher(ctx->block.q ^ tail ^ ctx->mac, ctx->cipher_ctx);

    return ctx->mac;
}

void eax64_omac_clear(eax64_omac_t *ctx)
{
    memset(ctx, 0, sizeof(eax64_omac_t));
}


void eax64_ctr_init(eax64_ctr_t *ctx, void *cipher_ctx, uint64_t nonce)
{
    memset(ctx, 0, sizeof(eax64_ctr_t));
    ctx->nonce = nonce;
    ctx->blocknum = -1;    // something nonzero
    ctx->cipher_ctx = cipher_ctx;
}

int eax64_ctr_process(eax64_ctr_t *ctx, int pos, int byte)
{
    int blocknum = pos / 8;
    if (blocknum != ctx->blocknum)    // change of block
    {
        ctx->blocknum = blocknum;
        ctx->xorbuf.q = eax64_cipher(ctx->nonce + blocknum, ctx->cipher_ctx);
    }

    return ctx->xorbuf.b[pos % 8] ^ byte;

}

void eax64_ctr_clear(eax64_ctr_t *ctx)
{
    memset(ctx, 0, sizeof(eax64_ctr_t));
}

void eax64_init(eax64_t *ctx, void *cipher_ctx, const uint8_t *nonce, int nonce_len)
{
    // reuse header omac to avoid stack
    eax64_omac_t *nonceomac = &ctx->headermac;
    eax64_omac_init(nonceomac, cipher_ctx, 0);
    for (int i = 0; i < nonce_len; i++)
        eax64_omac_process(nonceomac, nonce[i]);
    uint64_t n = eax64_omac_digest(nonceomac);
    eax64_ctr_init(&ctx->ctr, cipher_ctx, n);

    // this init will clear noncemac too
    eax64_omac_init(&ctx->headermac, cipher_ctx, 1);
    eax64_omac_init(&ctx->ctomac, cipher_ctx, 2);
}


void eax64_auth_ct(eax64_t *ctx, int byte)
{
    eax64_omac_process(&ctx->ctomac, byte);
}

void eax64_auth_header(eax64_t *ctx, int byte)
{
    eax64_omac_process(&ctx->headermac, byte);
}

int eax64_decrypt_ct(eax64_t *ctx, int pos, int byte)
{
    return eax64_ctr_process(&ctx->ctr, pos, byte);
}

uint64_t eax64_digest(eax64_t *ctx)
{
    uint64_t c = eax64_omac_digest(&ctx->ctomac);
    eax64_omac_clear(&ctx->ctomac);
    uint64_t h = eax64_omac_digest(&ctx->headermac);
    eax64_omac_clear(&ctx->headermac);

    uint64_t local_tag = c ^ h ^ ctx->ctr.nonce;

    return local_tag;
}

void eax64_clear(eax64_t *ctx)
{
    memset(ctx, 0, sizeof(eax64_t));
}