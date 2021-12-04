/*

   Derived from https://github.com/kokke/tiny-AES-c and other public domain sources.

   This implementation is quite special.

   It tries hard to do all the processing on processor registers and avoid using RAM at all, even stack.

   The key material and state are in some store.
   Store is word-accessed via aes128_streg/aes128_ldreg user-defined functions.
   It's expected the store would be implemented in some hardware registers (think TRESOR of linux-x86).

   The flow is:
    1) aes128_set_key(key)
    2) aes128_set_data(plaintext)
    3) aes128_encrypt()
    4) ciphertext = aes128_get_data(plaintext)
    5) optionally clear store

   NOTES:
    Since the store is singleton, only one AES instance may be running at time.
    No thread-safety, of course.
    Only little-endian mode is supported.
    It's advised to inspect the resulting assembly to make sure no stack is actually used.


   Yes, this AES is quite slow :-)

*/

#include <stdint.h>
#include "aes128.h"

static const uint8_t sbox[256] =
{
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
};

static inline uint32_t rotr32(uint32_t x, int r)
{
    return(x >> r) | (x << (32 - r));
}

static inline uint32_t u8to32le(const uint8_t *b)
{
    return (b[0] << 0) | (b[1] << 8) | (b[2] << 16) | (b[3] << 24);
}

static inline void u32to8le(uint8_t *b, uint32_t w)
{
    b[0] = w;
    b[1] = w >> 8;
    b[2] = w >> 16;
    b[3] = w >> 24;
}

// xb stands for 'extract byte'
static inline uint32_t xb(uint32_t w, uint32_t s, int b)
{
    return (w >> (s * 8) & 0xFF) << (b * 8);
}

// xbsb stands for 'extract byte, process via sbox'
static inline uint32_t xbsb(uint32_t w, uint32_t s, int d)
{
    return sbox[(w >> (s * 8)) & 0xFF] << (d * 8);
}

static inline uint32_t xtime32(uint32_t x)
{
    // constant-time to prevent the timing attacks
    return ((x << 1) & 0xFEFEFEFEU) ^ (((x >> 7) & 0x01010101U) * 0x1BU);
}

static inline uint32_t mix_column(uint32_t col)
{
    return xtime32(col ^ rotr32(col, 8)) ^ rotr32(col, 8) ^ rotr32(col, 16) ^ rotr32(col, 24);
}

static void do_round(int rcon)
{
    uint32_t rk3 = aes128_ldreg(AES128_RK3);
    uint32_t tmp = rk3;

    tmp =  (xbsb(tmp, 1, 0) ^ rcon) | xbsb(tmp, 2, 1) | xbsb(tmp, 3, 2) | xbsb(tmp, 0, 3);

    uint32_t c0 = aes128_ldreg(AES128_S0);
    uint32_t c1 = aes128_ldreg(AES128_S1);
    uint32_t c2 = aes128_ldreg(AES128_S2);
    uint32_t c3 = aes128_ldreg(AES128_S3);

    uint32_t r0 = xbsb(c0, 0, 0) | xbsb(c1, 0, 1) | xbsb(c2, 0, 2) | xbsb(c3, 0, 3);
    uint32_t r1 = xbsb(c1, 1, 0) | xbsb(c2, 1, 1) | xbsb(c3, 1, 2) | xbsb(c0, 1, 3);
    uint32_t r2 = xbsb(c2, 2, 0) | xbsb(c3, 2, 1) | xbsb(c0, 2, 2) | xbsb(c1, 2, 3);
    uint32_t r3 = xbsb(c3, 3, 0) | xbsb(c0, 3, 1) | xbsb(c1, 3, 2) | xbsb(c2, 3, 3);

    c0 = xb(r0, 0,  0) | xb(r1, 0, 1) | xb(r2, 0, 2) | xb(r3, 0, 3);
    c1 = xb(r0, 1,  0) | xb(r1, 1, 1) | xb(r2, 1, 2) | xb(r3, 1, 3);
    c2 = xb(r0, 2,  0) | xb(r1, 2, 1) | xb(r2, 2, 2) | xb(r3, 2, 3);
    c3 = xb(r0, 3,  0) | xb(r1, 3, 1) | xb(r2, 3, 2) | xb(r3, 3, 3);

    if (rcon != 0x36)
    {
        c0 = mix_column(c0);
        c1 = mix_column(c1);
        c2 = mix_column(c2);
        c3 = mix_column(c3);
    }

    tmp ^= aes128_ldreg(AES128_RK0);
    aes128_streg(AES128_RK0, tmp);
    aes128_streg(AES128_S0, c0 ^ tmp);

    tmp ^= aes128_ldreg(AES128_RK1);
    aes128_streg(AES128_RK1, tmp);
    aes128_streg(AES128_S1, c1 ^ tmp);

    tmp ^= aes128_ldreg(AES128_RK2);
    aes128_streg(AES128_RK2, tmp);
    aes128_streg(AES128_S2, c2 ^ tmp);

    tmp ^= rk3;
    aes128_streg(AES128_RK3, tmp);
    aes128_streg(AES128_S3, c3 ^ tmp);
}


void aes128_set_key(const uint8_t key[16])
{
    aes128_streg(AES128_K0, u8to32le(&key[0]));
    aes128_streg(AES128_K1, u8to32le(&key[4]));
    aes128_streg(AES128_K2, u8to32le(&key[8]));
    aes128_streg(AES128_K3, u8to32le(&key[12]));
}

void aes128_set_data(const uint8_t src[16])
{
    aes128_streg(AES128_S0, u8to32le(&src[0]));
    aes128_streg(AES128_S1, u8to32le(&src[4]));
    aes128_streg(AES128_S2, u8to32le(&src[8]));
    aes128_streg(AES128_S3, u8to32le(&src[12]));
}

void aes128_get_data(uint8_t dst[16])
{
    u32to8le(&dst[0], aes128_ldreg(AES128_S0));
    u32to8le(&dst[4], aes128_ldreg(AES128_S1));
    u32to8le(&dst[8], aes128_ldreg(AES128_S2));
    u32to8le(&dst[12], aes128_ldreg(AES128_S3));
}

void aes128_encrypt(void)
{
    uint32_t tmp;
    tmp = aes128_ldreg(AES128_K0);
    aes128_streg(AES128_RK0, tmp);
    aes128_streg(AES128_S0, aes128_ldreg(AES128_S0) ^ tmp);

    tmp = aes128_ldreg(AES128_K1);
    aes128_streg(AES128_RK1, tmp);
    aes128_streg(AES128_S1, aes128_ldreg(AES128_S1) ^ tmp);

    tmp = aes128_ldreg(AES128_K2);
    aes128_streg(AES128_RK2, tmp);
    aes128_streg(AES128_S2, aes128_ldreg(AES128_S2) ^ tmp);

    tmp = aes128_ldreg(AES128_K3);
    aes128_streg(AES128_RK3, tmp);
    aes128_streg(AES128_S3, aes128_ldreg(AES128_S3) ^ tmp);

    int rcon = 0x01;

    while (1)
    {
        do_round(rcon);

        if (rcon == 0x36)
            break;

        if (rcon == 0x80)
            rcon = 0x1B;
        else
            rcon <<= 1;
    }
}
