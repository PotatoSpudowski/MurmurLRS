/*
 * murmur.h — MurmurLRS encryption module
 *
 * Authenticated encryption for ExpressLRS OTA packets.
 * Encrypt-then-MAC with zero packet overhead:
 *   - AES-128-CTR encrypts the payload
 *   - AES-128-CMAC replaces the CRC field (keyed authentication)
 *   - 32-bit counter reconstructed from 8-bit OtaNonce
 *   - 64-packet sliding window for replay protection
 *
 * Designed for ELRS Packet4 (6-byte payload, 14-bit MAC) and
 * Packet8 (10-byte payload, 16-bit MAC).
 */
#ifndef MURMUR_H
#define MURMUR_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdbool.h>

/* ------------------------------------------------------------------ */
/*  Key derivation                                                     */
/* ------------------------------------------------------------------ */

void murmur_derive_keys(const char *binding_phrase,
                        uint8_t enc_key[16],
                        uint8_t uid[6]);

/* ------------------------------------------------------------------ */
/*  Packet encryption (encrypt-then-MAC)                               */
/* ------------------------------------------------------------------ */

uint16_t murmur_encrypt_packet(const uint8_t enc_key[16],
                               uint32_t counter,
                               uint8_t packet_type,
                               uint8_t *payload, uint8_t payload_len,
                               uint8_t mac_bits);

bool murmur_decrypt_packet(const uint8_t enc_key[16],
                           uint32_t counter,
                           uint8_t packet_type,
                           uint8_t *payload, uint8_t payload_len,
                           uint16_t received_mac, uint8_t mac_bits);

/* ------------------------------------------------------------------ */
/*  Counter reconstruction                                             */
/* ------------------------------------------------------------------ */

uint32_t murmur_reconstruct_counter(uint32_t expected, uint8_t nonce);

/* ------------------------------------------------------------------ */
/*  Replay protection                                                  */
/* ------------------------------------------------------------------ */

typedef struct {
    uint32_t highest;
    uint64_t window;
    bool     initialized;
} murmur_replay_t;

void murmur_replay_init(murmur_replay_t *r);
bool murmur_replay_check(murmur_replay_t *r, uint32_t counter);

/* ------------------------------------------------------------------ */
/*  AES-CMAC (used internally, exposed for testing)                    */
/* ------------------------------------------------------------------ */

void murmur_cmac(const uint8_t key[16],
                 const uint8_t *msg, uint32_t msg_len,
                 uint8_t mac[16]);

#ifdef __cplusplus
}
#endif

#endif /* MURMUR_H */
