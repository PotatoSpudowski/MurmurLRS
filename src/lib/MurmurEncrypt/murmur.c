/*
 * murmur.c — MurmurLRS encryption module implementation
 *
 * Encrypt-then-MAC for ELRS OTA packets:
 *   1. AES-128-CTR encrypts payload (confidentiality)
 *   2. AES-128-CMAC over (counter || type || ciphertext) replaces CRC
 *      (authentication)
 *   3. 32-bit counter from 8-bit nonce (replay protection)
 *
 * Total cost per packet: 3 AES blocks (~9 us on ESP32 at 240 MHz).
 */
#include "murmur.h"
#include "aes128.h"
#include <string.h>

/* ------------------------------------------------------------------ */
/*  AES-CMAC (RFC 4493)                                                */
/* ------------------------------------------------------------------ */

static void block_leftshift(const uint8_t in[16], uint8_t out[16])
{
    uint8_t carry = 0;
    for (int i = 15; i >= 0; i--) {
        uint8_t next_carry = (in[i] >> 7) & 1;
        out[i] = (uint8_t)((in[i] << 1) | carry);
        carry = next_carry;
    }
}

static void block_xor(uint8_t out[16], const uint8_t a[16], const uint8_t b[16])
{
    for (int i = 0; i < 16; i++)
        out[i] = a[i] ^ b[i];
}

static void cmac_generate_subkeys(const uint8_t key[16],
                                  uint8_t k1[16], uint8_t k2[16])
{
    uint8_t L[16];
    uint8_t zeros[16];
    memset(zeros, 0, 16);

    aes128_encrypt(key, zeros, L);

    block_leftshift(L, k1);
    if (L[0] & 0x80)
        k1[15] ^= 0x87;

    block_leftshift(k1, k2);
    if (k1[0] & 0x80)
        k2[15] ^= 0x87;
}

void murmur_cmac(const uint8_t key[16],
                 const uint8_t *msg, uint32_t msg_len,
                 uint8_t mac[16])
{
    uint8_t k1[16], k2[16];
    uint8_t X[16], Y[16], M_last[16];
    uint32_t n, i;
    bool complete;

    cmac_generate_subkeys(key, k1, k2);

    n = (msg_len + 15) / 16;
    if (n == 0) {
        n = 1;
        complete = false;
    } else {
        complete = (msg_len % 16 == 0);
    }

    if (complete) {
        block_xor(M_last, msg + (n - 1) * 16, k1);
    } else {
        uint32_t remaining = msg_len % 16;
        if (msg_len == 0) remaining = 0;
        memset(M_last, 0, 16);
        if (remaining > 0)
            memcpy(M_last, msg + (n - 1) * 16, remaining);
        M_last[remaining] = 0x80;
        block_xor(M_last, M_last, k2);
    }

    memset(X, 0, 16);
    for (i = 0; i < n - 1; i++) {
        block_xor(Y, X, msg + i * 16);
        aes128_encrypt(key, Y, X);
    }

    block_xor(Y, X, M_last);
    aes128_encrypt(key, Y, mac);
}

/* ------------------------------------------------------------------ */
/*  AES-128-CTR encryption                                             */
/* ------------------------------------------------------------------ */

static void ctr_encrypt(const uint8_t key[16], uint32_t counter,
                        uint8_t packet_type,
                        uint8_t *data, uint8_t data_len)
{
    uint8_t nonce[16];
    uint8_t keystream[16];

    memset(nonce, 0, 16);
    nonce[0] = (uint8_t)(counter >> 24);
    nonce[1] = (uint8_t)(counter >> 16);
    nonce[2] = (uint8_t)(counter >> 8);
    nonce[3] = (uint8_t)(counter);
    nonce[4] = packet_type;

    aes128_encrypt(key, nonce, keystream);

    for (uint8_t i = 0; i < data_len && i < 16; i++)
        data[i] ^= keystream[i];
}

/* ------------------------------------------------------------------ */
/*  Key derivation                                                     */
/* ------------------------------------------------------------------ */

void murmur_derive_keys(const char *binding_phrase,
                        uint8_t enc_key[16],
                        uint8_t uid[6])
{
    uint8_t zeros[16];
    uint8_t master[16];
    uint8_t derived[16];

    memset(zeros, 0, 16);

    murmur_cmac(zeros, (const uint8_t *)binding_phrase,
                (uint32_t)strlen(binding_phrase), master);

    murmur_cmac(master, (const uint8_t *)"murmur-enc", 10, enc_key);

    murmur_cmac(master, (const uint8_t *)"murmur-uid", 10, derived);
    memcpy(uid, derived, 6);
}

/* ------------------------------------------------------------------ */
/*  Packet encryption / decryption                                     */
/* ------------------------------------------------------------------ */

static uint16_t compute_mac(const uint8_t key[16], uint32_t counter,
                            uint8_t packet_type,
                            const uint8_t *data, uint8_t data_len,
                            uint8_t mac_bits)
{
    uint8_t buf[5 + 16];
    uint8_t mac[16];
    uint32_t buf_len = 5 + data_len;

    buf[0] = (uint8_t)(counter >> 24);
    buf[1] = (uint8_t)(counter >> 16);
    buf[2] = (uint8_t)(counter >> 8);
    buf[3] = (uint8_t)(counter);
    buf[4] = packet_type;
    memcpy(buf + 5, data, data_len);

    murmur_cmac(key, buf, buf_len, mac);

    uint16_t truncated = ((uint16_t)mac[0] << 8) | mac[1];
    if (mac_bits < 16)
        truncated >>= (16 - mac_bits);

    return truncated;
}

uint16_t murmur_encrypt_packet(const uint8_t enc_key[16],
                               uint32_t counter,
                               uint8_t packet_type,
                               uint8_t *payload, uint8_t payload_len,
                               uint8_t mac_bits)
{
    ctr_encrypt(enc_key, counter, packet_type, payload, payload_len);

    return compute_mac(enc_key, counter, packet_type,
                       payload, payload_len, mac_bits);
}

bool murmur_decrypt_packet(const uint8_t enc_key[16],
                           uint32_t counter,
                           uint8_t packet_type,
                           uint8_t *payload, uint8_t payload_len,
                           uint16_t received_mac, uint8_t mac_bits)
{
    uint16_t expected = compute_mac(enc_key, counter, packet_type,
                                    payload, payload_len, mac_bits);

    uint16_t diff = expected ^ received_mac;
    if (diff != 0)
        return false;

    ctr_encrypt(enc_key, counter, packet_type, payload, payload_len);

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
