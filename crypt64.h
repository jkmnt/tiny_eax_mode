#ifndef _CRYPT64_H_
#define _CRYPT64_H_

typedef struct crypt64_cipher_t crypt64_cipher_t;

struct crypt64_cipher_t
{
    uint64_t (*ecb)(crypt64_cipher_t *me, uint64_t block);
    // base structure. cypher may extend it
};

typedef union
{
    uint64_t q;
    uint8_t b[8];
} crypt64_block_t;

typedef struct
{
    crypt64_cipher_t *cypher;
    uint64_t mac;
    uint64_t tail2;
    crypt64_block_t fullblock;
    crypt64_block_t buf;
    int bytepos;
} crypt64_omac_t;

typedef struct
{
    crypt64_cipher_t *cypher;
    uint64_t nonce;
    crypt64_block_t xorbuf;
    int blocknum;
} crypt64_ctr_t;

typedef struct
{
    crypt64_omac_t ctomac;
    crypt64_omac_t headermac;
    crypt64_ctr_t ctr;
} crypt64_eax_t;

void crypt64_omac_init(crypt64_omac_t *ctx, crypt64_cipher_t *cypher, int k, uint64_t tail0);
void crypt64_omac_process(crypt64_omac_t *ctx, int byte);
uint64_t crypt64_omac_digest(crypt64_omac_t *ctx);
void crypt64_omac_clear(crypt64_omac_t *ctx);

void crypt64_ctr_init(crypt64_ctr_t *ctx, crypt64_cipher_t *cypher, uint64_t nonce);
int crypt64_ctr_process(crypt64_ctr_t *ctx, int pos, int byte);
void crypt64_ctr_clear(crypt64_ctr_t *ctx);

void crypt64_eax_init(crypt64_eax_t *ctx, crypt64_cipher_t *cypher, const uint8_t *nonce, int nonce_len);
void crypt64_eax_auth_ct(crypt64_eax_t *ctx, int byte);
void crypt64_eax_auth_header(crypt64_eax_t *ctx, int byte);
int crypt64_eax_decrypt_ct(crypt64_eax_t *ctx, int pos, int byte);
uint64_t crypt64_eax_digest(crypt64_eax_t *ctx);
void crypt64_eax_clear(crypt64_eax_t *ctx);

#endif
