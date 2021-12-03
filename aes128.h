#ifndef _AES128_H_
#define _AES128_H_

enum aes128_regs_e
{
    // key
    AES128_K0,
    AES128_K1,
    AES128_K2,
    AES128_K3,

    // round key
    AES128_RK0,
    AES128_RK1,
    AES128_RK2,
    AES128_RK3,
};

#define AES128_KMSTORE_NWORDS 8

extern void aes128_save_km(void *kmstore, int i, uint32_t w);
extern uint32_t aes128_load_km(void *kmstore, int i);

void aes128_set_key(void *kmctx, const uint8_t key[16]);
void aes128_encrypt_ecb(void *kmctx, uint8_t buf[16]);

#endif