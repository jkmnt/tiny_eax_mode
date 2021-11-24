#include <stdint.h>
#include <string.h>
#include "crypt64.h"

static uint64_t gf_double(uint64_t a)
{
    return (a << 1) ^ ((a >> 63) ? 0x1B : 0);
}

void crypt64_omac_init(crypt64_omac_t *ctx, crypt64_cipher_t *cypher, int k, uint64_t tail0)
{
    memset(ctx, 0, sizeof(crypt64_omac_t));
    ctx->fullblock.b[7] = k;
    ctx->tail2 = gf_double(tail0);
    ctx->cypher = cypher;
}

void crypt64_omac_process(crypt64_omac_t *ctx, int byte)
{
    ctx->buf.b[ctx->bytepos] = byte;
    ctx->bytepos += 1;
    if (ctx->bytepos == 8)
    {
        ctx->mac = ctx->cypher->ecb(ctx->cypher, ctx->fullblock.q ^ ctx->mac);
        ctx->fullblock = ctx->buf;
        ctx->buf.q = 0;
        ctx->bytepos = 0;
    }
}

uint64_t crypt64_omac_digest(crypt64_omac_t *ctx)
{
    if (ctx->bytepos == 0)  // readyblock is last
        ctx->fullblock.q ^= ctx->tail2;

    ctx->mac = ctx->cypher->ecb(ctx->cypher, ctx->fullblock.q ^ ctx->mac);

    if (ctx->bytepos)  // something still in buffer
    {
        ctx->buf.b[ctx->bytepos] = 0x80;
        uint64_t tail4 = gf_double(ctx->tail2);
        ctx->mac = ctx->cypher->ecb(ctx->cypher, ctx->buf.q ^ ctx->mac ^ tail4);
    }

    return ctx->mac;
}

void crypt64_omac_clear(crypt64_omac_t *ctx)
{
    memset(ctx, 0, sizeof(crypt64_omac_t));
}


void crypt64_ctr_init(crypt64_ctr_t *ctx, crypt64_cipher_t *cypher, uint64_t nonce)
{
    memset(ctx, 0, sizeof(crypt64_ctr_t));
    ctx->nonce = nonce;
    ctx->blocknum = -1;    // something nonzero
    ctx->cypher = cypher;
}

int crypt64_ctr_process(crypt64_ctr_t *ctx, int pos, int byte)
{
    int blocknum = pos / 8;
    if (blocknum != ctx->blocknum)    // change of block
    {
        ctx->blocknum = blocknum;
        ctx->xorbuf.q = ctx->cypher->ecb(ctx->cypher, ctx->nonce + blocknum);
    }

    return ctx->xorbuf.b[pos % 8] ^ byte;

}

void crypt64_ctr_clear(crypt64_ctr_t *ctx)
{
    memset(ctx, 0, sizeof(crypt64_ctr_t));
}


void crypt64_eax_init(crypt64_eax_t *ctx, crypt64_cipher_t *cypher, const uint8_t *nonce, int nonce_len)
{
    memset(ctx, 0, sizeof(crypt64_eax_t));

    uint64_t tail0 = cypher->ecb(cypher, 0);

    crypt64_omac_t nonceomac;
    crypt64_omac_init(&nonceomac, cypher, 0, tail0);
    crypt64_omac_init(&ctx->headermac, cypher, 1, tail0);
    crypt64_omac_init(&ctx->ctomac, cypher, 2, tail0);

    for (int i = 0; i < nonce_len; i++)
        crypt64_omac_process(&nonceomac, nonce[i]);

    uint64_t n = crypt64_omac_digest(&nonceomac);
    crypt64_omac_clear(&nonceomac);

    crypt64_ctr_init(&ctx->ctr, cypher, n);
}


void crypt64_eax_auth_ct(crypt64_eax_t *ctx, int byte)
{
    crypt64_omac_process(&ctx->ctomac, byte);
}

void crypt64_eax_auth_header(crypt64_eax_t *ctx, int byte)
{
    crypt64_omac_process(&ctx->headermac, byte);
}

int crypt64_eax_decrypt_ct(crypt64_eax_t *ctx, int pos, int byte)
{
    return crypt64_ctr_process(&ctx->ctr, pos, byte);
}

uint64_t crypt64_eax_digest(crypt64_eax_t *ctx)
{
    uint64_t c = crypt64_omac_digest(&ctx->ctomac);
    crypt64_omac_clear(&ctx->ctomac);
    uint64_t h = crypt64_omac_digest(&ctx->headermac);
    crypt64_omac_clear(&ctx->headermac);

    uint64_t local_tag = c ^ h ^ ctx->ctr.nonce;

    return local_tag;
}

void crypt64_eax_clear(crypt64_eax_t *ctx)
{
    memset(ctx, 0, sizeof(crypt64_eax_t));
}
