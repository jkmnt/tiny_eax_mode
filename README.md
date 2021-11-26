# eax64
EAX auth encryption mode for 64-bit cipher

Sometimes you need no real hardcore security, but having some privacy + auth simultaneously is nice.
Small code size and simplicity is important. Sometimes even AES-128 + SHA-1 are overkill for tiny microcontrollers yet simple oldschool 64-bit Feistel cipher would be good enough.

Here is a demo of such cipher in EAX mode. The single decryption primitive
provides both the encryption and auth. The cipher used for demoing is XTEA, probably the simplest one could find.

Python encoder/decoder, C-decoder and test vectors inside.
