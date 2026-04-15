#ifndef ASCON_H
#define ASCON_H

#include <stdint.h>

#define ASCON_128_KEY_SIZE 16
#define ASCON_128_NONCE_SIZE 16
#define ASCON_128_TAG_SIZE 16

/* ASCON-128 AEAD in-place encryption
 * key: 16 bytes
 * nonce: 16 bytes
 * ad: associated data
 * ad_len: length of associated data
 * m: message (in) / ciphertext (out)
 * m_len: length of message
 * tag: computed tag
 */
void ascon128_encrypt(const uint8_t key[16], const uint8_t nonce[16],
                      const uint8_t *ad, uint32_t ad_len,
                      uint8_t *m, uint32_t m_len,
                      uint8_t tag[16]);

/* ASCON-128 AEAD in-place decryption
 * key: 16 bytes
 * nonce: 16 bytes
 * ad: associated data
 * ad_len: length of associated data
 * c: ciphertext (in) / plaintext (out)
 * c_len: length of ciphertext
 * tag: 16 bytes
 * returns 0 on success, -1 on authentication failure
 */
int ascon128_decrypt(const uint8_t key[16], const uint8_t nonce[16],
                     const uint8_t *ad, uint32_t ad_len,
                     uint8_t *c, uint32_t c_len, const uint8_t tag[16]);

/* ASCON-XOF (eXtendable-Output Function)
 * in: input data
 * in_len: length of input data
 * out: output buffer
 * out_len: desired length of output
 */
void ascon_xof(const uint8_t *in, uint32_t in_len, uint8_t *out, uint32_t out_len);

#endif /* ASCON_H */
