# Tiny EAX mode

This is the C-implementation of the EAX encryption and authentication mode.

Sometimes the standart way of AES + SHA1 HMAC is overkill and EAX mode may be a better option.
It uses the single encryption primitive and single key for both the privacy and authentication.
It's online, the message may be processed without knowing the lengh beforehand. 
Additional aux data (message header) may be authenticated too.
(https://en.wikipedia.org/wiki/EAX_mode)


This implementation is small, simple and targets 32-bit platforms.

The basic code is for the 128-bit block cipher, but the 64-bit variant is included too for the
specific cases there the simple oldschool 64-bit Feistel cipher would be good enough.


Python encoder/decoder, C-decoder and test vectors inside.

The 128-bit demo (eax_aes_test.c) uses the AES-128.
The 64-bit demo (eax_xtea_test.c) uses the XTEA.
