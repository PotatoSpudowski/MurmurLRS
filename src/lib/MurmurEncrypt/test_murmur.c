/*
 * test_murmur.c — Test suite for MurmurLRS encryption module
 *
 * Tests against NIST FIPS 197 AES-128, RFC 4493 AES-CMAC,
 * plus encrypt/decrypt roundtrips, counter reconstruction,
 * replay protection, and key derivation.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aes128.h"
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
/*  AES-128 ECB (FIPS 197)                                             */
/* ================================================================== */

static void test_aes128_fips197(void)
{
    TEST("AES-128 ECB: FIPS 197 test vector");
    uint8_t key[16], plain[16], cipher[16], result[16];
    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
    hex_to_bytes("6bc1bee22e409f96e93d7e117393172a", plain, 16);
    hex_to_bytes("3ad77bb40d7a3660a89ecaf32466ef97", cipher, 16);
    aes128_encrypt(key, plain, result);
    ASSERT_MEM_EQ(result, cipher, 16, "ciphertext mismatch");
    PASS();
}

static void test_aes128_fips197_v2(void)
{
    TEST("AES-128 ECB: FIPS 197 test vector 2");
    uint8_t key[16], plain[16], cipher[16], result[16];
    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
    hex_to_bytes("ae2d8a571e03ac9c9eb76fac45af8e51", plain, 16);
    hex_to_bytes("f5d3d58503b9699de785895a96fdbaaf", cipher, 16);
    aes128_encrypt(key, plain, result);
    ASSERT_MEM_EQ(result, cipher, 16, "ciphertext mismatch");
    PASS();
}

static void test_aes128_zero(void)
{
    TEST("AES-128 ECB: all-zero key and plaintext");
    uint8_t key[16], plain[16], result[16], expected[16];
    memset(key, 0, 16);
    memset(plain, 0, 16);
    hex_to_bytes("66e94bd4ef8a2c3b884cfa59ca342b2e", expected, 16);
    aes128_encrypt(key, plain, result);
    ASSERT_MEM_EQ(result, expected, 16, "ciphertext mismatch");
    PASS();
}

/* ================================================================== */
/*  AES-CMAC (RFC 4493)                                                */
/* ================================================================== */

static void test_cmac_empty(void)
{
    TEST("AES-CMAC: RFC 4493 example 1 (empty message)");
    uint8_t key[16], mac[16], expected[16];
    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
    hex_to_bytes("bb1d6929e95937287fa37d129b756746", expected, 16);
    murmur_cmac(key, NULL, 0, mac);
    ASSERT_MEM_EQ(mac, expected, 16, "MAC mismatch");
    PASS();
}

static void test_cmac_16(void)
{
    TEST("AES-CMAC: RFC 4493 example 2 (16 bytes)");
    uint8_t key[16], msg[16], mac[16], expected[16];
    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
    hex_to_bytes("6bc1bee22e409f96e93d7e117393172a", msg, 16);
    hex_to_bytes("070a16b46b4d4144f79bdd9dd04a287c", expected, 16);
    murmur_cmac(key, msg, 16, mac);
    ASSERT_MEM_EQ(mac, expected, 16, "MAC mismatch");
    PASS();
}

static void test_cmac_40(void)
{
    TEST("AES-CMAC: RFC 4493 example 3 (40 bytes)");
    uint8_t key[16], mac[16], expected[16], msg[40];
    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
    hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411", msg, 40);
    hex_to_bytes("dfa66747de9ae63030ca32611497c827", expected, 16);
    murmur_cmac(key, msg, 40, mac);
    ASSERT_MEM_EQ(mac, expected, 16, "MAC mismatch");
    PASS();
}

static void test_cmac_64(void)
{
    TEST("AES-CMAC: RFC 4493 example 4 (64 bytes)");
    uint8_t key[16], mac[16], expected[16], msg[64];
    hex_to_bytes("2b7e151628aed2a6abf7158809cf4f3c", key, 16);
    hex_to_bytes("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710", msg, 64);
    hex_to_bytes("51f0bebf7e3b9d92fc49741779363cfe", expected, 16);
    murmur_cmac(key, msg, 64, mac);
    ASSERT_MEM_EQ(mac, expected, 16, "MAC mismatch");
    PASS();
}

/* ================================================================== */
/*  Encrypt / decrypt                                                  */
/* ================================================================== */

static void test_roundtrip_pkt4(void)
{
    TEST("Encrypt/decrypt roundtrip: Packet4 (6B, 14-bit MAC)");
    uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t orig[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint8_t payload[6];
    memcpy(payload, orig, 6);
    uint16_t mac = murmur_encrypt_packet(key, 42, 1, payload, 6, 14);
    ASSERT_EQ(memcmp(payload, orig, 6) != 0, 1, "not encrypted");
    bool ok = murmur_decrypt_packet(key, 42, 1, payload, 6, mac, 14);
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
    uint16_t mac = murmur_encrypt_packet(key, 1000, 0, payload, 10, 16);
    bool ok = murmur_decrypt_packet(key, 1000, 0, payload, 10, mac, 16);
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
    uint16_t mac = murmur_encrypt_packet(k1, 0, 1, p, 6, 14);
    ASSERT_EQ(murmur_decrypt_packet(k2, 0, 1, p, 6, mac, 14), false, "should reject");
    PASS();
}

static void test_wrong_counter(void)
{
    TEST("Wrong counter: rejected");
    uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t p[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint16_t mac = murmur_encrypt_packet(key, 100, 1, p, 6, 14);
    ASSERT_EQ(murmur_decrypt_packet(key, 101, 1, p, 6, mac, 14), false, "should reject");
    PASS();
}

static void test_tampered(void)
{
    TEST("Tampered ciphertext: rejected");
    uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t p[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint16_t mac = murmur_encrypt_packet(key, 50, 1, p, 6, 14);
    p[3] ^= 0x01;
    ASSERT_EQ(murmur_decrypt_packet(key, 50, 1, p, 6, mac, 14), false, "should reject");
    PASS();
}

static void test_different_counters(void)
{
    TEST("Different counters: different ciphertext");
    uint8_t key[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    uint8_t p1[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    uint8_t p2[6] = {0xAA,0xBB,0xCC,0xDD,0xEE,0xFF};
    murmur_encrypt_packet(key, 0, 1, p1, 6, 14);
    murmur_encrypt_packet(key, 1, 1, p2, 6, 14);
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
        uint16_t mac = murmur_encrypt_packet(enc_key, tx_ctr, 1, payload, 6, 14);
        uint8_t nonce = (uint8_t)(tx_ctr & 0xFF);
        uint32_t rx_ctr = murmur_reconstruct_counter(tx_ctr, nonce);
        ASSERT_EQ(murmur_replay_check(&replay, rx_ctr), true, "fresh");
        bool ok = murmur_decrypt_packet(enc_key, rx_ctr, 1, payload, 6, mac, 14);
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
    ASSERT_EQ(murmur_decrypt_packet(key, 42, 1, fake, 6, 0x1234, 14), false, "should reject");
    PASS();
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(void)
{
    printf("\n=== MurmurLRS Crypto Test Suite ===\n\n");

    printf("[AES-128 ECB]\n");
    test_aes128_fips197(); test_aes128_fips197_v2(); test_aes128_zero();

    printf("\n[AES-CMAC (RFC 4493)]\n");
    test_cmac_empty(); test_cmac_16(); test_cmac_40(); test_cmac_64();

    printf("\n[Packet encrypt/decrypt]\n");
    test_roundtrip_pkt4(); test_roundtrip_pkt8();
    test_wrong_key(); test_wrong_counter(); test_tampered(); test_different_counters();

    printf("\n[Counter reconstruction]\n");
    test_ctr_exact(); test_ctr_ahead(); test_ctr_wrap(); test_ctr_behind(); test_ctr_large();

    printf("\n[Replay protection]\n");
    test_replay_first(); test_replay_seq(); test_replay_dup();
    test_replay_ooo(); test_replay_old(); test_replay_boundary(); test_replay_jump();

    printf("\n[Key derivation]\n");
    test_key_deterministic(); test_key_different(); test_key_independent();

    printf("\n[Integration]\n");
    test_full_flow(); test_forgery_rejected();

    printf("\n=== Results: %d/%d passed ===\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
