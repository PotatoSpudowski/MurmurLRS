/*
 * test_murmur.c — Test suite for MurmurLRS encryption module
 *
 * Tests against ASCON-128 AEAD and ASCON-XOF,
 * plus encrypt/decrypt roundtrips, counter reconstruction,
 * replay protection, and key derivation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "ascon.h"
#include "murmur.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  %-55s ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); } while(0)
#define ASSERT_EQ(a, b, msg) do { if ((a) != (b)) { FAIL(msg); return; } } while(0)
#define ASSERT_MEM_EQ(a, b, len, msg) do { if (memcmp(a, b, len) != 0) { FAIL(msg); return; } } while(0)

static void hex_to_bytes(const char *hex, uint8_t *out, int len)
{
    for (int i = 0; i < len; i++) {
        unsigned int val;
        sscanf(hex + i * 2, "%02x", &val);
        out[i] = (uint8_t)val;
    }
}

/* ================================================================== */
/*  ASCON-128 AEAD                                                     */
/* ================================================================== */

static void test_ascon128_basic(void)
{
    TEST("ASCON-128 AEAD: official test vector (empty AD/P)");
    uint8_t key[16], nonce[16], tag[16];
    uint8_t expected_tag[16];
    hex_to_bytes("000102030405060708090a0b0c0d0e0f", key, 16);
    hex_to_bytes("000102030405060708090a0b0c0d0e0f", nonce, 16);
    hex_to_bytes("e355159f292911f794cb1432a0103a8a", expected_tag, 16);

    ascon128_encrypt(key, nonce, NULL, 0, NULL, 0, tag);
    ASSERT_MEM_EQ(tag, expected_tag, 16, "tag mismatch");
    PASS();
}

static void test_ascon128_roundtrip(void)
{
    TEST("ASCON-128 AEAD: encryption/decryption roundtrip");
    uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t nonce[16] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,42};
    uint8_t ad[] = "associated data";
    uint8_t m[] = "this is a message";
    const uint8_t original_m[] = "this is a message";
    uint8_t tag[16];

    ascon128_encrypt(key, nonce, ad, strlen((char*)ad), m, strlen((char*)m), tag);
    int res = ascon128_decrypt(key, nonce, ad, strlen((char*)ad), m, strlen((char*)m), tag);

    ASSERT_EQ(res, 0, "decryption failed");
    ASSERT_MEM_EQ(original_m, m, strlen((char*)m), "plaintext mismatch");
    PASS();
}

/* ================================================================== */
/*  ASCON-XOF                                                          */
/* ================================================================== */

static void test_ascon_xof_kat(void)
{
    TEST("ASCON-XOF: official test vectors");
    uint8_t hash[32];
    uint8_t expected_empty[32];
    /* ASCON-XOF empty message KAT */
    hex_to_bytes("5d4cbde6350ea4c174bd65b5b332f8408f99740b81aa02735eaefbcf0ba0339e", expected_empty, 32);
    ascon_xof(NULL, 0, hash, 32);
    ASSERT_MEM_EQ(hash, expected_empty, 32, "empty message KAT mismatch");

    /* ASCON-XOF 0x00 message KAT */
    uint8_t msg_00 = 0x00;
    uint8_t expected_00[32];
    hex_to_bytes("b2edbb27ac8397a55bc83d137c151de9ede048338fe907f0d3629e717846fedc", expected_00, 32);
    ascon_xof(&msg_00, 1, hash, 32);
    ASSERT_MEM_EQ(hash, expected_00, 32, "message 0x00 KAT mismatch");
    PASS();
}

static void test_ascon_xof_logic(void)
{
    TEST("ASCON-XOF: deterministic and variable length");
    uint8_t h1[32], h2[32], h3[64];
    ascon_xof((uint8_t*)"test", 4, h1, 32);
    ascon_xof((uint8_t*)"test", 4, h2, 32);
    ascon_xof((uint8_t*)"test", 4, h3, 64);

    ASSERT_MEM_EQ(h1, h2, 32, "should be deterministic");
    ASSERT_MEM_EQ(h3, h1, 32, "first 32 bytes of 64-byte output should match 32-byte output");
    PASS();
}

/* ================================================================== */
/*  Packet encrypt / decrypt                                                  */
/* ================================================================== */

static void test_roundtrip_pkt4(void)
{
    TEST("Encrypt/decrypt roundtrip: Packet4 (6B, 14-bit MAC)");
    uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t orig[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint8_t payload[6];
    memcpy(payload, orig, 6);
    uint16_t mac = murmur_encrypt_packet(key, 42, 1, 0, payload, 6, 14);
    ASSERT_EQ(memcmp(payload, orig, 6) != 0, 1, "not encrypted");
    bool ok = murmur_decrypt_packet(key, 42, 1, 0, payload, 6, mac, 14);
    ASSERT_EQ(ok, true, "decrypt failed");
    ASSERT_MEM_EQ(payload, orig, 6, "plaintext mismatch");
    PASS();
}

static void test_roundtrip_pkt8(void)
{
    TEST("Encrypt/decrypt roundtrip: Packet8 (10B, 16-bit MAC)");
    uint8_t key[16] = {16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1};
    uint8_t orig[10] = {0x01,0x23,0x45,0x67,0x89,0xAB,0xCD,0xEF,0xFE,0xDC};
    uint8_t payload[10];
    memcpy(payload, orig, 10);
    uint16_t mac = murmur_encrypt_packet(key, 1000, 0, 0, payload, 10, 16);
    bool ok = murmur_decrypt_packet(key, 1000, 0, 0, payload, 10, mac, 16);
    ASSERT_EQ(ok, true, "decrypt failed");
    ASSERT_MEM_EQ(payload, orig, 10, "plaintext mismatch");
    PASS();
}

static void test_wrong_key(void)
{
    TEST("Wrong key: rejected");
    uint8_t k1[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t k2[16] = {16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1};
    uint8_t p[6] = {0x11,0x22,0x33,0x44,0x55,0x66};
    uint16_t mac = murmur_encrypt_packet(k1, 0, 1, 0, p, 6, 14);
    ASSERT_EQ(murmur_decrypt_packet(k2, 0, 1, 0, p, 6, mac, 14), false, "should reject");
    PASS();
}

static void test_wrong_counter(void)
{
    TEST("Wrong counter: rejected");
    uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t p[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint16_t mac = murmur_encrypt_packet(key, 100, 1, 0, p, 6, 14);
    ASSERT_EQ(murmur_decrypt_packet(key, 101, 1, 0, p, 6, mac, 14), false, "should reject");
    PASS();
}

static void test_tampered(void)
{
    TEST("Tampered ciphertext: rejected");
    uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t p[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint16_t mac = murmur_encrypt_packet(key, 50, 1, 0, p, 6, 14);
    p[3] ^= 0x01;
    ASSERT_EQ(murmur_decrypt_packet(key, 50, 1, 0, p, 6, mac, 14), false, "should reject");
    PASS();
}

static void test_different_counters(void)
{
    TEST("Different counters: different ciphertext");
    uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t p1[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint8_t p2[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    murmur_encrypt_packet(key, 0, 1, 0, p1, 6, 14);
    murmur_encrypt_packet(key, 1, 1, 0, p2, 6, 14);
    ASSERT_EQ(memcmp(p1, p2, 6) != 0, 1, "should differ");
    PASS();
}

static void test_wrong_direction(void)
{
    TEST("Wrong direction: rejected");
    uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t p[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint16_t mac = murmur_encrypt_packet(key, 42, 1, 0, p, 6, 14);
    ASSERT_EQ(murmur_decrypt_packet(key, 42, 1, 1, p, 6, mac, 14), false, "should reject");
    PASS();
}

static void test_direction_different_ciphertext(void)
{
    TEST("Different directions: different ciphertext");
    uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t p1[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint8_t p2[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    murmur_encrypt_packet(key, 0, 1, 0, p1, 6, 14);
    murmur_encrypt_packet(key, 0, 1, 1, p2, 6, 14);
    ASSERT_EQ(memcmp(p1, p2, 6) != 0, 1, "should differ");
    PASS();
}

/* ================================================================== */
/*  Counter reconstruction                                             */
/* ================================================================== */

static void test_ctr_exact(void)
{
    TEST("Counter reconstruct: exact match");
    ASSERT_EQ(murmur_reconstruct_counter(42, 42 & 0xFF), 42u, "mismatch");
    PASS();
}

static void test_ctr_ahead(void)
{
    TEST("Counter reconstruct: nonce slightly ahead");
    ASSERT_EQ(murmur_reconstruct_counter(300, 49), 305u, "mismatch");
    PASS();
}

static void test_ctr_wrap(void)
{
    TEST("Counter reconstruct: wrap around 256");
    ASSERT_EQ(murmur_reconstruct_counter(254, 2), 258u, "mismatch");
    PASS();
}

static void test_ctr_behind(void)
{
    TEST("Counter reconstruct: slightly behind");
    ASSERT_EQ(murmur_reconstruct_counter(260, 255), 255u, "mismatch");
    PASS();
}

static void test_ctr_large(void)
{
    TEST("Counter reconstruct: large values");
    ASSERT_EQ(murmur_reconstruct_counter(100000, 165), 100005u, "mismatch");
    PASS();
}

/* ================================================================== */
/*  Replay protection                                                  */
/* ================================================================== */

static void test_replay_first(void)
{
    TEST("Replay: first packet accepted");
    murmur_replay_t r; murmur_replay_init(&r);
    ASSERT_EQ(murmur_replay_check(&r, 100), true, "should pass");
    PASS();
}

static void test_replay_seq(void)
{
    TEST("Replay: sequential counters accepted");
    murmur_replay_t r; murmur_replay_init(&r);
    for (uint32_t i = 0; i < 100; i++)
        ASSERT_EQ(murmur_replay_check(&r, i), true, "should pass");
    PASS();
}

static void test_replay_dup(void)
{
    TEST("Replay: duplicate rejected");
    murmur_replay_t r; murmur_replay_init(&r);
    murmur_replay_check(&r, 50);
    ASSERT_EQ(murmur_replay_check(&r, 50), false, "should reject");
    PASS();
}

static void test_replay_ooo(void)
{
    TEST("Replay: out-of-order within window accepted");
    murmur_replay_t r; murmur_replay_init(&r);
    murmur_replay_check(&r, 100);
    murmur_replay_check(&r, 102);
    ASSERT_EQ(murmur_replay_check(&r, 101), true, "late packet in window");
    PASS();
}

static void test_replay_old(void)
{
    TEST("Replay: too old rejected");
    murmur_replay_t r; murmur_replay_init(&r);
    murmur_replay_check(&r, 0);
    murmur_replay_check(&r, 100);
    ASSERT_EQ(murmur_replay_check(&r, 0), false, "should reject");
    PASS();
}

static void test_replay_boundary(void)
{
    TEST("Replay: window boundary behavior");
    murmur_replay_t r; murmur_replay_init(&r);
    murmur_replay_check(&r, 0);
    murmur_replay_check(&r, 63);
    ASSERT_EQ(murmur_replay_check(&r, 0), false, "already seen");
    ASSERT_EQ(murmur_replay_check(&r, 1), true, "unseen in window");
    PASS();
}

static void test_replay_jump(void)
{
    TEST("Replay: large jump clears window");
    murmur_replay_t r; murmur_replay_init(&r);
    for (uint32_t i = 0; i < 10; i++) murmur_replay_check(&r, i);
    ASSERT_EQ(murmur_replay_check(&r, 1000), true, "jump accepted");
    ASSERT_EQ(murmur_replay_check(&r, 5), false, "old rejected");
    PASS();
}

/* ================================================================== */
/*  Key derivation                                                     */
/* ================================================================== */

static void test_key_deterministic(void)
{
    TEST("Key derivation: deterministic");
    uint8_t k1[16], u1[6], k2[16], u2[6];
    murmur_derive_keys("my secret phrase", k1, u1);
    murmur_derive_keys("my secret phrase", k2, u2);
    ASSERT_MEM_EQ(k1, k2, 16, "keys differ");
    ASSERT_MEM_EQ(u1, u2, 6, "UIDs differ");
    PASS();
}

static void test_key_different(void)
{
    TEST("Key derivation: different phrases differ");
    uint8_t k1[16], u1[6], k2[16], u2[6];
    murmur_derive_keys("phrase one", k1, u1);
    murmur_derive_keys("phrase two", k2, u2);
    ASSERT_EQ(memcmp(k1, k2, 16) != 0, 1, "keys should differ");
    PASS();
}

static void test_key_independent(void)
{
    TEST("Key derivation: key and UID independent");
    uint8_t key[16], uid[6];
    murmur_derive_keys("test phrase", key, uid);
    ASSERT_EQ(memcmp(key, uid, 6) != 0, 1, "should be independent");
    PASS();
}

/* ================================================================== */
/*  FHSSv2 sequence generation                                         */
/* ================================================================== */

static void test_fhss_key_deterministic(void)
{
    TEST("FHSS key: deterministic from same UID");
    uint8_t uid[6] = {0x01,0x02,0x03,0x04,0x05,0x06};
    uint8_t k1[16], k2[16];
    murmur_derive_fhss_key(uid, k1);
    murmur_derive_fhss_key(uid, k2);
    ASSERT_MEM_EQ(k1, k2, 16, "keys should match");
    PASS();
}

static void test_fhss_key_different_uid(void)
{
    TEST("FHSS key: different UIDs produce different keys");
    uint8_t uid1[6] = {0x01,0x02,0x03,0x04,0x05,0x06};
    uint8_t uid2[6] = {0x06,0x05,0x04,0x03,0x02,0x01};
    uint8_t k1[16], k2[16];
    murmur_derive_fhss_key(uid1, k1);
    murmur_derive_fhss_key(uid2, k2);
    ASSERT_EQ(memcmp(k1, k2, 16) != 0, 1, "keys should differ");
    PASS();
}

static void test_fhss_key_domain_separation(void)
{
    TEST("FHSS key: differs from encryption key");
    uint8_t enc_key[16], uid[6], fhss_key[16];
    murmur_derive_keys("test-phrase", enc_key, uid);
    murmur_derive_fhss_key(uid, fhss_key);
    ASSERT_EQ(memcmp(enc_key, fhss_key, 16) != 0, 1, "should differ");
    PASS();
}

static void test_fhss_seq_deterministic(void)
{
    TEST("FHSS seq: deterministic for same key+domain");
    uint8_t fhss_key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t seq1[256], seq2[256];
    murmur_fhss_fill_sequence(fhss_key, 0, seq1, 240, 80, 40);
    murmur_fhss_fill_sequence(fhss_key, 0, seq2, 240, 80, 40);
    ASSERT_MEM_EQ(seq1, seq2, 240, "sequences should match");
    PASS();
}

static void test_fhss_seq_sync_channel(void)
{
    TEST("FHSS seq: sync channel at start of every block");
    uint8_t fhss_key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t seq[256];
    uint8_t num_ch = 20;
    uint8_t sync_ch = 10;
    uint16_t seq_len = 240;
    murmur_fhss_fill_sequence(fhss_key, 0, seq, seq_len, num_ch, sync_ch);
    for (uint16_t i = 0; i < seq_len; i += num_ch) {
        ASSERT_EQ(seq[i], sync_ch, "sync channel at block start");
    }
    PASS();
}

static void test_fhss_seq_no_repeats_in_block(void)
{
    TEST("FHSS seq: no repeated channels within a block");
    uint8_t fhss_key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t seq[256];
    uint8_t num_ch = 20;
    uint16_t seq_len = 240;
    murmur_fhss_fill_sequence(fhss_key, 0, seq, seq_len, num_ch, 10);
    for (uint16_t block = 0; block < seq_len / num_ch; block++) {
        uint8_t seen[256] = {0};
        for (uint8_t j = 0; j < num_ch; j++) {
            uint8_t ch = seq[block * num_ch + j];
            ASSERT_EQ(seen[ch], 0, "channel repeated in block");
            seen[ch] = 1;
        }
    }
    PASS();
}

static void test_fhss_seq_all_channels_used(void)
{
    TEST("FHSS seq: all channels appear in each block");
    uint8_t fhss_key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t seq[256];
    uint8_t num_ch = 20;
    uint16_t seq_len = 240;
    murmur_fhss_fill_sequence(fhss_key, 0, seq, seq_len, num_ch, 10);
    for (uint16_t block = 0; block < seq_len / num_ch; block++) {
        uint8_t count[256] = {0};
        for (uint8_t j = 0; j < num_ch; j++)
            count[seq[block * num_ch + j]]++;
        for (uint8_t ch = 0; ch < num_ch; ch++)
            ASSERT_EQ(count[ch], 1, "channel missing from block");
    }
    PASS();
}

static void test_fhss_seq_different_domains(void)
{
    TEST("FHSS seq: different domain_id produces different sequence");
    uint8_t fhss_key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t seq1[256], seq2[256];
    murmur_fhss_fill_sequence(fhss_key, 0x00, seq1, 240, 80, 40);
    murmur_fhss_fill_sequence(fhss_key, 0x01, seq2, 240, 80, 40);
    ASSERT_EQ(memcmp(seq1, seq2, 240) != 0, 1, "should differ");
    PASS();
}

static void test_fhss_seq_different_keys(void)
{
    TEST("FHSS seq: different keys produce different sequence");
    uint8_t k1[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t k2[16] = {16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1};
    uint8_t seq1[256], seq2[256];
    murmur_fhss_fill_sequence(k1, 0, seq1, 240, 80, 40);
    murmur_fhss_fill_sequence(k2, 0, seq2, 240, 80, 40);
    ASSERT_EQ(memcmp(seq1, seq2, 240) != 0, 1, "should differ");
    PASS();
}

static void test_fhss_seq_small_domain(void)
{
    TEST("FHSS seq: works with small channel count (4 channels)");
    uint8_t fhss_key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t seq[256];
    uint8_t num_ch = 4;
    uint8_t sync_ch = 2;
    uint16_t seq_len = 252;
    murmur_fhss_fill_sequence(fhss_key, 0, seq, seq_len, num_ch, sync_ch);
    for (uint16_t i = 0; i < seq_len; i += num_ch)
        ASSERT_EQ(seq[i], sync_ch, "sync at block start");
    for (uint16_t block = 0; block < seq_len / num_ch; block++) {
        uint8_t seen[4] = {0};
        for (uint8_t j = 0; j < num_ch; j++) {
            uint8_t ch = seq[block * num_ch + j];
            ASSERT_EQ(ch < num_ch, 1, "channel out of range");
            ASSERT_EQ(seen[ch], 0, "channel repeated");
            seen[ch] = 1;
        }
    }
    PASS();
}

static void test_fhss_seq_80ch(void)
{
    TEST("FHSS seq: 80-channel 2.4GHz domain");
    uint8_t fhss_key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t seq[256];
    uint8_t num_ch = 80;
    uint8_t sync_ch = 40;
    uint16_t seq_len = 240;
    murmur_fhss_fill_sequence(fhss_key, 0, seq, seq_len, num_ch, sync_ch);
    ASSERT_EQ(seq[0], sync_ch, "sync at pos 0");
    ASSERT_EQ(seq[80], sync_ch, "sync at pos 80");
    ASSERT_EQ(seq[160], sync_ch, "sync at pos 160");
    for (uint16_t block = 0; block < 3; block++) {
        uint8_t count[80] = {0};
        for (uint8_t j = 0; j < 80; j++)
            count[seq[block * 80 + j]]++;
        for (uint8_t ch = 0; ch < 80; ch++)
            ASSERT_EQ(count[ch], 1, "missing or duplicated channel");
    }
    PASS();
}

/* ================================================================== */
/*  Integration                                                        */
/* ================================================================== */

static void test_full_flow(void)
{
    TEST("Full flow: derive -> encrypt -> reconstruct -> replay -> decrypt");
    uint8_t enc_key[16], uid[6];
    murmur_derive_keys("bench-test-2024", enc_key, uid);
    murmur_replay_t replay;
    murmur_replay_init(&replay);
    uint8_t rc_data[6] = {0x01, 0x80, 0x40, 0x20, 0x10, 0x08};
    for (uint32_t tx_ctr = 0; tx_ctr < 10; tx_ctr++) {
        uint8_t payload[6];
        memcpy(payload, rc_data, 6);
        uint16_t mac = murmur_encrypt_packet(enc_key, tx_ctr, 1, 0, payload, 6, 14);
        uint8_t nonce = (uint8_t)(tx_ctr & 0xFF);
        uint32_t rx_ctr = murmur_reconstruct_counter(tx_ctr, nonce);
        ASSERT_EQ(murmur_replay_check(&replay, rx_ctr), true, "fresh");
        bool ok = murmur_decrypt_packet(enc_key, rx_ctr, 1, 0, payload, 6, mac, 14);
        ASSERT_EQ(ok, true, "decrypt");
        ASSERT_MEM_EQ(payload, rc_data, 6, "data");
    }
    PASS();
}

static void test_forgery_rejected(void)
{
    TEST("Forgery: random payload + MAC rejected");
    uint8_t key[16], uid[6];
    murmur_derive_keys("legit-phrase", key, uid);
    uint8_t fake[6] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};
    ASSERT_EQ(murmur_decrypt_packet(key, 42, 1, 0, fake, 6, 0x1234, 14), false, "should reject");
    PASS();
}

/* ================================================================== */
/*  OTA4/OTA8 header-as-AD correctness                                 */
/* ================================================================== */

static void test_ota4_header_mismatch(void)
{
    TEST("OTA4 header: crcHigh contamination causes MAC failure");
    uint8_t key[16], uid[6];
    murmur_derive_keys("test-phrase", key, uid);
    uint8_t payload[6] = {0x11,0x22,0x33,0x44,0x55,0x66};

    /* TX encrypts with header = type bits only (0x01) */
    uint8_t tx_payload[6];
    memcpy(tx_payload, payload, 6);
    uint16_t mac = murmur_encrypt_packet(key, 100, 0x01, 0, tx_payload, 6, 14);

    /* RX tries to decrypt with contaminated header (crcHigh=0x3F in upper 6 bits) */
    uint8_t rx_payload[6];
    memcpy(rx_payload, tx_payload, 6);
    uint8_t contaminated_header = 0x01 | (0x3F << 2);
    bool ok = murmur_decrypt_packet(key, 100, contaminated_header, 0,
                                    rx_payload, 6, mac, 14);
    ASSERT_EQ(ok, false, "contaminated header should fail");
    PASS();
}

static void test_ota4_header_masked_succeeds(void)
{
    TEST("OTA4 header: masked type-only AD succeeds on both sides");
    uint8_t key[16], uid[6];
    murmur_derive_keys("test-phrase", key, uid);
    uint8_t payload[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};

    /* TX: header = ptype = byte0 & 0x03 = 0x02 */
    uint8_t tx_payload[6];
    memcpy(tx_payload, payload, 6);
    uint16_t mac = murmur_encrypt_packet(key, 200, 0x02, 0, tx_payload, 6, 14);

    /* RX: same masked header (0x02), regardless of what crcHigh was on wire */
    uint8_t rx_payload[6];
    memcpy(rx_payload, tx_payload, 6);
    bool ok = murmur_decrypt_packet(key, 200, 0x02, 0, rx_payload, 6, mac, 14);
    ASSERT_EQ(ok, true, "same masked header should succeed");
    ASSERT_MEM_EQ(rx_payload, payload, 6, "decrypted data should match original");
    PASS();
}

static void test_ota8_full_header_authenticated(void)
{
    TEST("OTA8 header: full byte authenticated, bit flip rejected");
    uint8_t key[16], uid[6];
    murmur_derive_keys("test-phrase", key, uid);
    uint8_t payload[10] = {1,2,3,4,5,6,7,8,9,10};

    /* TX encrypts with full OTA8 header byte (e.g., 0xA1 = type 0x01 + flags) */
    uint8_t tx_payload[10];
    memcpy(tx_payload, payload, 10);
    uint16_t mac = murmur_encrypt_packet(key, 300, 0xA1, 0, tx_payload, 10, 16);

    /* RX with correct full header succeeds */
    uint8_t rx_payload[10];
    memcpy(rx_payload, tx_payload, 10);
    bool ok = murmur_decrypt_packet(key, 300, 0xA1, 0, rx_payload, 10, mac, 16);
    ASSERT_EQ(ok, true, "correct full header should succeed");

    /* RX with flipped upper bit fails */
    memcpy(rx_payload, tx_payload, 10);
    ok = murmur_decrypt_packet(key, 300, 0x21, 0, rx_payload, 10, mac, 16);
    ASSERT_EQ(ok, false, "flipped header bit should fail");
    PASS();
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(void)
{
    printf("\n=== MurmurLRS Crypto Test Suite (ASCON) ===\n\n");

    printf("[ASCON-128 AEAD]\n");
    test_ascon128_basic(); test_ascon128_roundtrip();

    printf("\n[ASCON-XOF]\n");
    test_ascon_xof_kat();
    test_ascon_xof_logic();

    printf("\n[Packet encrypt/decrypt]\n");
    test_roundtrip_pkt4(); test_roundtrip_pkt8();
    test_wrong_key(); test_wrong_counter(); test_tampered(); test_different_counters();
    test_wrong_direction(); test_direction_different_ciphertext();

    printf("\n[Counter reconstruction]\n");
    test_ctr_exact(); test_ctr_ahead(); test_ctr_wrap(); test_ctr_behind(); test_ctr_large();

    printf("\n[Replay protection]\n");
    test_replay_first(); test_replay_seq(); test_replay_dup();
    test_replay_ooo(); test_replay_old(); test_replay_boundary(); test_replay_jump();

    printf("\n[Key derivation]\n");
    test_key_deterministic(); test_key_different(); test_key_independent();

    printf("\n[OTA header-as-AD]\n");
    test_ota4_header_mismatch();
    test_ota4_header_masked_succeeds();
    test_ota8_full_header_authenticated();

    printf("\n[FHSSv2 sequence generation]\n");
    test_fhss_key_deterministic(); test_fhss_key_different_uid();
    test_fhss_key_domain_separation();
    test_fhss_seq_deterministic(); test_fhss_seq_sync_channel();
    test_fhss_seq_no_repeats_in_block(); test_fhss_seq_all_channels_used();
    test_fhss_seq_different_domains(); test_fhss_seq_different_keys();
    test_fhss_seq_small_domain(); test_fhss_seq_80ch();

    printf("\n[Integration]\n");
    test_full_flow(); test_forgery_rejected();

    printf("\n=== Results: %d/%d passed ===\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
