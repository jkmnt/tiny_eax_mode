#ifndef _AES_H_
#define _AES_H_

#define AES128_KMCTX_NWORDS 8

extern void aes128_save_km(void *kmctx, int i, uint32_t w);
extern uint32_t aes128_load_km(void *kmctx, int i);

void aes128_set_key(void *kmctx, const uint8_t key[16]);
void aes128_encrypt_ecb(void *kmctx, uint8_t buf[16]);

#endif