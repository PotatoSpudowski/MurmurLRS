/*
 * murmur.c — MurmurLRS encryption module implementation
 *
 * ASCON-128 AEAD for ELRS OTA packets:
 *   1. ASCON-128 AEAD encrypts payload and provides authentication
 *   2. 32-bit counter from 8-bit nonce (replay protection)
 *
 * Total cost per packet: 1 ASCON-128 operation.
 */
#include "murmur.h"
#include "ascon.h"
#include <string.h>

/* Internal ASCON function -- not part of the public API */
void ascon128_decrypt_no_verify(const uint8_t key[16], const uint8_t nonce[16],
                                const uint8_t *ad, uint64_t ad_len,
                                uint8_t *c, uint64_t c_len, uint8_t expected_tag[16]);

/* ------------------------------------------------------------------ */
/*  Key derivation                                                     */
/* ------------------------------------------------------------------ */

void murmur_derive_keys(const char *binding_phrase,
                        uint8_t enc_key[16],
                        uint8_t uid[6])
{
    uint8_t master[32];
    uint8_t derived[22];
    uint32_t phrase_len = (uint32_t)strlen(binding_phrase);

    /* master = Ascon-XOF(binding_phrase, 32) */
    ascon_xof((const uint8_t *)binding_phrase, phrase_len, master, 32);

    /* enc_key || uid = Ascon-XOF(master, 22) */
    ascon_xof(master, 32, derived, 22);

    memcpy(enc_key, derived, 16);
    memcpy(uid, derived + 16, 6);
}

/* ------------------------------------------------------------------ */
/*  Packet encryption / decryption                                     */
/* ------------------------------------------------------------------ */

static void prepare_nonce(uint32_t counter, uint8_t header,
                          uint8_t direction, uint8_t nonce[16])
{
    memset(nonce, 0, 16);
    nonce[0] = (uint8_t)(counter >> 24);
    nonce[1] = (uint8_t)(counter >> 16);
    nonce[2] = (uint8_t)(counter >> 8);
    nonce[3] = (uint8_t)(counter);
    nonce[4] = header;
    nonce[5] = direction;
}

uint16_t murmur_encrypt_packet(const uint8_t enc_key[16],
                               uint32_t counter,
                               uint8_t header,
                               uint8_t direction,
                               uint8_t *payload, uint8_t payload_len,
                               uint8_t mac_bits)
{
    uint8_t nonce[16];
    uint8_t tag[16]; // payload + tag

    prepare_nonce(counter, header, direction, nonce);

    ascon128_encrypt(enc_key, nonce, &header, 1, payload, payload_len, tag);

    uint16_t truncated = ((uint16_t)tag[0] << 8) | tag[1];
    if (mac_bits < 16)
        truncated >>= (16 - mac_bits);

    return truncated;
}

bool murmur_decrypt_packet(const uint8_t enc_key[16],
                           uint32_t counter,
                           uint8_t header,
                           uint8_t direction,
                           uint8_t *payload, uint8_t payload_len,
                           uint16_t received_mac, uint8_t mac_bits)
{
    uint8_t nonce[16];
    uint8_t expected_tag[16];

    prepare_nonce(counter, header, direction, nonce);

    /* Decrypt the ciphertext (which is in payload) and get the expected tag */
    ascon128_decrypt_no_verify(enc_key, nonce, &header, 1, payload, payload_len,
                               expected_tag);

    uint16_t expected = ((uint16_t)expected_tag[0] << 8) | expected_tag[1];
    if (mac_bits < 16)
        expected >>= (16 - mac_bits);

    if (expected != received_mac)
        return false;

    return true;
}

/* ------------------------------------------------------------------ */
/*  Counter reconstruction                                             */
/* ------------------------------------------------------------------ */

uint32_t murmur_reconstruct_counter(uint32_t expected, uint8_t nonce)
{
    uint32_t base = expected & 0xFFFFFF00u;
    uint32_t candidate = base | nonce;

    if (candidate > expected + 128)
        candidate -= 256;
    else if (candidate + 128 < expected)
        candidate += 256;

    return candidate;
}

/* ------------------------------------------------------------------ */
/*  Replay protection                                                  */
/* ------------------------------------------------------------------ */

void murmur_replay_init(murmur_replay_t *r)
{
    r->highest = 0;
    r->window = 0;
    r->initialized = false;
}

bool murmur_replay_check(murmur_replay_t *r, uint32_t counter)
{
    if (!r->initialized) {
        r->highest = counter;
        r->window = 1;
        r->initialized = true;
        return true;
    }

    if (counter > r->highest) {
        uint32_t shift = counter - r->highest;
        if (shift >= 64)
            r->window = 0;
        else
            r->window <<= shift;
        r->window |= 1;
        r->highest = counter;
        return true;
    }

    uint32_t age = r->highest - counter;

    if (age >= 64)
        return false;

    uint64_t bit = (uint64_t)1 << age;
    if (r->window & bit)
        return false;

    r->window |= bit;
    return true;
}
