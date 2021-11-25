#ifndef _CRYPT64_H_
#define _CRYPT64_H_

typedef union
{
    uint64_t q;     // Little-endian only, yap.
    uint8_t b[8];
} crypt64_block_t;

typedef struct
{
    void *cipher_ctx;
    uint64_t mac;
    uint64_t tail2;
    crypt64_block_t fullblock;
    crypt64_block_t buf;
    int bytepos;
} crypt64_omac_t;

typedef struct
{
    void *cipher_ctx;
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

// The external cipher function to be linked.
// ctx is the argument passed to cipher. i.e. it may be used to distinguish cipher instances
extern uint64_t crypt64_cipher(uint64_t pt, void *ctx);

// The intended way of using crypt64 is via crypt64_eax API:
// But OMAC and CTR functions are made public since they could be useful on their own.
void crypt64_omac_init(crypt64_omac_t *ctx, void *cipher_ctx, int k, uint64_t tail0);
void crypt64_omac_process(crypt64_omac_t *ctx, int byte);
uint64_t crypt64_omac_digest(crypt64_omac_t *ctx);
void crypt64_omac_clear(crypt64_omac_t *ctx);
void crypt64_ctr_init(crypt64_ctr_t *ctx, void *cipher_ctx, uint64_t nonce);
int crypt64_ctr_process(crypt64_ctr_t *ctx, int pos, int byte);
void crypt64_ctr_clear(crypt64_ctr_t *ctx);

// The EAX flow:
//
// 1) Collect the nonce of the message, init
//      crypt64_eax_init(nonce)
//
// 2) Auth the header and data byte-by-byte in any order:
//      for each header_byte:
//          crypt64_eax_auth_header(header_byte)
//      for each ciphertext_byte:
//          crypt64_eax_auth_ct(ciphertext_byte)
//
// 3) Compute digest and compare it to the message tag:
//      digest = crypt64_eax_digest
//
// 5) Decrypt payload if tags match:
//      for each ciphertext_byte:
//          plaintext_byte = crypt64_eax_decrypt_ct(ciphertext_byte)
//
// 6) Clear EAX:
//       crypt64_eax_clear
//

// Notes:
//
// cipher_ctx argument is passed to the each crypt64_cipher call
//
// crypt64_eax_decrypt_ct may be called while auth in progress.
// Pos is the ciphertext byte position and random access is fine.
//
// crypt64_eax_digest finalizes the auths, i.e. the crypt64_eax_auth_* shouldn't be called after that.

void crypt64_eax_init(crypt64_eax_t *ctx, void *cipher_ctx, const uint8_t *nonce, int nonce_len);

void crypt64_eax_auth_ct(crypt64_eax_t *ctx, int byte);
void crypt64_eax_auth_header(crypt64_eax_t *ctx, int byte);
int crypt64_eax_decrypt_ct(crypt64_eax_t *ctx, int pos, int byte);
uint64_t crypt64_eax_digest(crypt64_eax_t *ctx);
void crypt64_eax_clear(crypt64_eax_t *ctx);

#endif
