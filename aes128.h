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

    // state aka data
    AES128_S0,
    AES128_S1,
    AES128_S2,
    AES128_S3,
};

#define AES128_NREGS 12

extern void aes128_streg(int i, uint32_t w);
extern uint32_t aes128_ldreg(int i);

void aes128_set_key(const uint8_t key[16]);
void aes128_set_data(const uint8_t src[16]);
void aes128_get_data(uint8_t dst[16]);

void aes128_encrypt(void);

#endif