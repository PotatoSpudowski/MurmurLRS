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
                                const uint8_t *ad, uint32_t ad_len,
                                uint8_t *c, uint32_t c_len, uint8_t expected_tag[16]);

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
    uint8_t saved[16];

    /* Save ciphertext so in-place decrypt doesn't destroy it on MAC mismatch */
    memcpy(saved, payload, payload_len);

    prepare_nonce(counter, header, direction, nonce);

    ascon128_decrypt_no_verify(enc_key, nonce, &header, 1, payload, payload_len,
                               expected_tag);

    uint16_t expected = ((uint16_t)expected_tag[0] << 8) | expected_tag[1];
    if (mac_bits < 16)
        expected >>= (16 - mac_bits);

    if (expected != received_mac) {
        memcpy(payload, saved, payload_len);
        return false;
    }

    return true;
}

/* ------------------------------------------------------------------ */
/*  FHSS sequence generation (ASCON-XOF keyed CSPRNG)                  */
/* ------------------------------------------------------------------ */

void murmur_derive_fhss_key(const uint8_t uid[6], uint8_t fhss_key[16])
{
    /* Domain-separated: "MurmurFHSS" || uid → ASCON-XOF → 16-byte key */
    uint8_t input[10 + 6];
    memcpy(input, "MurmurFHSS", 10);
    memcpy(input + 10, uid, 6);
    ascon_xof(input, 16, fhss_key, 16);
}

void murmur_fhss_fill_sequence(const uint8_t fhss_key[16],
                               uint8_t domain_id,
                               uint8_t *sequence, uint16_t seq_len,
                               uint8_t num_channels, uint8_t sync_channel)
{
    /* Generate XOF stream: "FHSSv1" || fhss_key || domain_id */
    uint8_t xof_input[6 + 16 + 1];
    memcpy(xof_input, "FHSSv1", 6);
    memcpy(xof_input + 6, fhss_key, 16);
    xof_input[22] = domain_id;

    /* Pre-generate enough random bytes for rejection sampling.
     * Each slot needs ~1 byte, but rejection sampling may discard some.
     * 3x buffer provides headroom. */
    uint16_t buf_len = (uint16_t)(seq_len * 3);
    uint8_t buf[256 * 3];
    if (buf_len > sizeof(buf))
        buf_len = sizeof(buf);
    ascon_xof(xof_input, 23, buf, buf_len);

    /* Initialize: sync channel at position 0 of every block */
    for (uint16_t i = 0; i < seq_len; i++) {
        if (i % num_channels == 0)
            sequence[i] = sync_channel;
        else if (i % num_channels == sync_channel)
            sequence[i] = 0;
        else
            sequence[i] = i % num_channels;
    }

    /* Fisher-Yates shuffle each block using rejection-sampled random indices.
     * Rejection sampling eliminates modulo bias: we discard values >= threshold
     * where threshold is the largest multiple of (num_channels-1) that fits in 256. */
    uint8_t range = num_channels - 1;
    /* Use uint16_t: when range divides 256, 256 % range == 0 and threshold == 256,
     * which overflows uint8_t to 0 (every sample would be rejected). */
    uint16_t threshold = 256 - (256 % range);
    uint16_t buf_idx = 0;

    for (uint16_t i = 0; i < seq_len; i++) {
        if (i % num_channels == 0)
            continue;

        /* Get an unbiased random value in [0, range) via rejection sampling */
        uint8_t rand_val;
        uint8_t retries = 0;
        do {
            if (buf_idx >= buf_len) {
                /* Exhausted buffer — regenerate with incremented domain */
                xof_input[22]++;
                ascon_xof(xof_input, 23, buf, buf_len);
                buf_idx = 0;
            }
            rand_val = buf[buf_idx++];
            retries++;
        } while (rand_val >= threshold && retries < 16);
        uint8_t r = (rand_val % range) + 1;

        uint16_t offset = (i / num_channels) * num_channels;
        uint8_t temp = sequence[i];
        sequence[i] = sequence[offset + r];
        sequence[offset + r] = temp;
    }
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
