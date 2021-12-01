#ifndef _EAX64_H_
#define _EAX64_H_

/*
    See eax128.h for generic comments on usage.
    The 64-bit version is almost the same
*/

typedef union
{
    uint64_t q;     // Little-endian only, yap.
    uint8_t b[8];
} eax64_block_t;

typedef struct
{
    void *cipher_ctx;
    uint64_t mac;
    eax64_block_t block;
    int bytepos;
} eax64_omac_t;

typedef struct
{
    void *cipher_ctx;
    uint64_t nonce;
    eax64_block_t xorbuf;
    int blocknum;
} eax64_ctr_t;

typedef struct
{
    eax64_omac_t ctomac;
    eax64_omac_t headermac;
    eax64_ctr_t ctr;
} eax64_t;

// The external cipher function to be linked.
// ctx is the argument passed to cipher. i.e. it may be used to distinguish cipher instances
extern uint64_t eax64_cipher(void *ctx, uint64_t pt);

void eax64_init(eax64_t *ctx, void *cipher_ctx, const uint8_t *nonce, int nonce_len);
void eax64_auth_ct(eax64_t *ctx, int byte);
void eax64_auth_header(eax64_t *ctx, int byte);
int eax64_decrypt_ct(eax64_t *ctx, int pos, int byte);
uint64_t eax64_digest(eax64_t *ctx);
void eax64_clear(eax64_t *ctx);


void eax64_omac_init(eax64_omac_t *ctx, void *cipher_ctx, int k);
void eax64_omac_process(eax64_omac_t *ctx, int byte);
uint64_t eax64_omac_digest(eax64_omac_t *ctx);
void eax64_omac_clear(eax64_omac_t *ctx);
void eax64_ctr_init(eax64_ctr_t *ctx, void *cipher_ctx, uint64_t nonce);
int eax64_ctr_process(eax64_ctr_t *ctx, int pos, int byte);
void eax64_ctr_clear(eax64_ctr_t *ctx);

#endif
