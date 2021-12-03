#ifndef _EAX128_H_
#define _EAX128_H_

/*
    The EAX flow:

 1) Collect the nonce of the message, init
      eax_init(nonce)

 2) Auth the header and data byte-by-byte in any order:
      for each header_byte:
          eax_auth_header(header_byte)
      for each ciphertext_byte:
          eax_auth_ct(ciphertext_byte)

 3) Compute digest and compare it to the message tag:
      digest = eax_digest

 5) Decrypt payload if tags match:
      for each ciphertext_byte:
          plaintext_byte = eax_decrypt_ct(ciphertext_byte)

 6) Clear EAX:
       eax_clear


 Notes:

 cipher_ctx argument is passed to the each eax_cipher call

 eax_decrypt_ct may be called while auth in progress.
 Pos is the ciphertext byte position and random access is fine.

 eax_digest finalizes the auths, i.e. the eax_auth_* shouldn't be called after that.


 OMAC and CTR internal functions are made public since they could be useful on their own.
 The OMAC functions are not generic but with a tweak: a single block with last byte == k is 'prepended' before the data


 See crypt64.c/h for 64-bit ciphers eax

*/


typedef union
{
    uint64_t q[2];
    uint32_t w[4];
    uint8_t b[16];
} eax128_block_t;


typedef struct
{
    void *cipher_ctx;
    eax128_block_t mac;
    eax128_block_t block;
    unsigned int bytepos;
} eax128_omac_t;

typedef struct
{
    void *cipher_ctx;
    eax128_block_t nonce;
    eax128_block_t xorbuf;
    unsigned int blocknum;
} eax128_ctr_t;

typedef struct
{
    eax128_omac_t domac;
    eax128_omac_t homac;
    eax128_ctr_t ctr;
} eax128_t;


// The external cipher function to be linked.
// ctx is the argument passed to cipher. i.e. it may be used to distinguish cipher instances.
// The cipher must process the data in place
extern void eax128_cipher(void *ctx, uint8_t pt[16]);


void eax128_init(eax128_t *ctx, void *cipher_ctx, const uint8_t *nonce, unsigned int nonce_len);
void eax128_auth_data(eax128_t *ctx, int byte);
void eax128_auth_header(eax128_t *ctx, int byte);
int eax128_crypt_data(eax128_t *ctx, unsigned int pos, int byte);
void eax128_digest(eax128_t *ctx, uint8_t tag[8]);
void eax128_clear(eax128_t *ctx);



void eax128_omac_init(eax128_omac_t *ctx, void *cipher_ctx, int k);
void eax128_omac_process(eax128_omac_t *ctx, int byte);
eax128_block_t *eax128_omac_digest(eax128_omac_t *ctx);
void eax128_omac_clear(eax128_omac_t *ctx);

void eax128_ctr_init(eax128_ctr_t *ctx, void *cipher_ctx, const uint8_t nonce[16]);
int eax128_ctr_process(eax128_ctr_t *ctx, unsigned int pos, int byte);
void eax128_ctr_clear(eax128_ctr_t *ctx);


#endif
