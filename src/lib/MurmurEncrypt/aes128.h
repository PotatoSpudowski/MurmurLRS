/*
 * aes128.h — Minimal AES-128 ECB encrypt
 *
 * Single-block encrypt only. CTR mode and CMAC are built on top
 * in aegis.c. No heap allocation, no dependencies beyond <stdint.h>.
 */
#ifndef AES128_H
#define AES128_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* Encrypt a single 16-byte block with AES-128.
 * key:  16-byte encryption key
 * in:   16-byte plaintext
 * out:  16-byte ciphertext (may alias in)
 */
void aes128_encrypt(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]);

#ifdef __cplusplus
}
#endif

#endif /* AES128_H */
