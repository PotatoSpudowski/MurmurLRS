#ifndef ASCON_H
#define ASCON_H

#include <stdint.h>

#define ASCON_128_KEY_SIZE 16
#define ASCON_128_NONCE_SIZE 16
#define ASCON_128_TAG_SIZE 16

/* ASCON-128 AEAD encryption
 * key: 16 bytes
 * nonce: 16 bytes
 * ad: associated data
 * ad_len: length of associated data
 * m: message (plaintext)
 * m_len: length of message
 * c: ciphertext (must be m_len + 16 bytes to hold the tag)
 */
void ascon128_encrypt(const uint8_t key[16], const uint8_t nonce[16],
                      const uint8_t *ad, uint64_t ad_len,
                      const uint8_t *m, uint64_t m_len,
                      uint8_t *c);

/* ASCON-128 AEAD decryption
 * key: 16 bytes
 * nonce: 16 bytes
 * ad: associated data
 * ad_len: length of associated data
 * c: ciphertext (including 16-byte tag)
 * c_len: length of ciphertext (including tag)
 * m: message (plaintext)
 * returns 0 on success, -1 on authentication failure
 */
int ascon128_decrypt(const uint8_t key[16], const uint8_t nonce[16],
                     const uint8_t *ad, uint64_t ad_len,
                     const uint8_t *c, uint64_t c_len,
                     uint8_t *m);

/* ASCON-XOF (eXtendable-Output Function)
 * in: input data
 * in_len: length of input data
 * out: output buffer
 * out_len: desired length of output
 */
void ascon_xof(const uint8_t *in, uint64_t in_len, uint8_t *out, uint64_t out_len);

#endif /* ASCON_H */
