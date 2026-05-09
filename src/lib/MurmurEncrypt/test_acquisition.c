/*
 * test_acquisition.c — Tests for MurmurLRS epoch acquisition state machine
 *
 * Simulates the acquisition/lock logic from OTA.cpp using the same
 * crypto primitives, without firmware dependencies.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "murmur.h"

static int tests_run = 0;
static int tests_passed = 0;

#define TEST(name) do { tests_run++; printf("  %-55s ", name); } while(0)
#define PASS() do { tests_passed++; printf("PASS\n"); } while(0)
#define FAIL(msg) do { printf("FAIL: %s\n", msg); return; } while(0)
#define ASSERT_EQ(a, b, msg) do { if ((a) != (b)) { FAIL(msg); } } while(0)
#define ASSERT_TRUE(a, msg) do { if (!(a)) { FAIL(msg); } } while(0)

/* Mirror the acquisition state machine from OTA.cpp */
#define ACQUIRE_THRESHOLD 3
#define ACQUIRE_EPOCHS_PER_PACKET 16
#define LOCK_FAIL_MAX 16

typedef struct {
    uint8_t key[16];
    uint32_t nonce_epoch;
    uint8_t prev_nonce;
    bool epoch_locked;
    uint8_t acquire_count;
    uint8_t acquire_epoch;
    uint8_t acquire_scan_pos;
    uint8_t lock_fail_count;
    murmur_replay_t replay;
} acquire_state_t;

static void state_init(acquire_state_t *s, const char *phrase)
{
    uint8_t uid[6];
    murmur_derive_keys(phrase, s->key, uid);
    s->nonce_epoch = 0;
    s->prev_nonce = 0;
    s->epoch_locked = false;
    s->acquire_count = 0;
    s->acquire_epoch = 0;
    s->acquire_scan_pos = 0;
    s->lock_fail_count = 0;
    murmur_replay_init(&s->replay);
}

static void state_reset(acquire_state_t *s, uint8_t nonce)
{
    s->prev_nonce = nonce;
    s->epoch_locked = false;
    s->acquire_count = 0;
    s->acquire_scan_pos = 0;
    s->lock_fail_count = 0;
    murmur_replay_init(&s->replay);
}

static void state_sync_nonce(acquire_state_t *s, uint8_t nonce)
{
    s->prev_nonce = nonce;
}

static uint32_t state_get_counter(acquire_state_t *s, uint8_t nonce)
{
    if (nonce < s->prev_nonce && (s->prev_nonce - nonce) > 128) {
        s->nonce_epoch++;
    }
    s->prev_nonce = nonce;
    return (s->nonce_epoch << 8) | (uint32_t)nonce;
}

/* Simulate TX encrypting a packet */
static uint16_t tx_encrypt(const uint8_t key[16], uint32_t counter,
                           uint8_t *payload, uint8_t payload_len)
{
    return murmur_encrypt_packet(key, counter, 0x01, 0, payload, payload_len, 14);
}

/* Simulate RX validation (mirrors MurmurValidatePacketCrc acquisition logic) */
static bool rx_validate(acquire_state_t *s, uint8_t rx_nonce,
                        uint8_t *payload, uint8_t payload_len,
                        uint16_t received_mac)
{
    if (s->epoch_locked) {
        uint32_t counter = state_get_counter(s, rx_nonce);
        uint32_t candidates[3] = { counter, counter + 256,
                                   (counter >= 256) ? counter - 256 : 0xFFFFFFFF };
        for (int i = 0; i < 3; i++) {
            if (candidates[i] == 0xFFFFFFFF) continue;
            if (murmur_decrypt_packet(s->key, candidates[i], 0x01, 0,
                                      payload, payload_len, received_mac, 14)) {
                if (!murmur_replay_check(&s->replay, candidates[i]))
                    return false;
                if (i == 1) s->nonce_epoch++;
                else if (i == 2) s->nonce_epoch--;
                s->lock_fail_count = 0;
                return true;
            }
        }
        if (++s->lock_fail_count >= LOCK_FAIL_MAX) {
            s->epoch_locked = false;
            s->acquire_count = 0;
            s->acquire_scan_pos = 0;
            s->lock_fail_count = 0;
        }
        return false;
    }

    /* Acquisition mode */
    uint8_t nonces[2] = { rx_nonce, (uint8_t)(rx_nonce - 1) };
    uint8_t scan_start = s->acquire_scan_pos;

    for (uint8_t i = 0; i < ACQUIRE_EPOCHS_PER_PACKET; i++) {
        uint32_t epoch = (scan_start + i) & 0xFF;
        for (uint8_t n = 0; n < 2; n++) {
            uint32_t candidate = (epoch << 8) | (uint32_t)nonces[n];
            if (murmur_decrypt_packet(s->key, candidate, 0x01, 0,
                                      payload, payload_len, received_mac, 14)) {
                if (epoch == s->acquire_epoch) {
                    s->acquire_count++;
                } else {
                    s->acquire_epoch = epoch;
                    s->acquire_count = 1;
                }
                if (s->acquire_count >= ACQUIRE_THRESHOLD) {
                    s->nonce_epoch = epoch;
                    s->prev_nonce = nonces[n];
                    s->epoch_locked = true;
                    murmur_replay_init(&s->replay);
                    murmur_replay_check(&s->replay, candidate);
                }
                s->acquire_scan_pos = epoch;
                return true;
            }
        }
    }

    s->acquire_count = 0;
    s->acquire_scan_pos = (scan_start + ACQUIRE_EPOCHS_PER_PACKET) & 0xFF;
    return false;
}

/* ================================================================== */
/*  Acquisition tests                                                  */
/* ================================================================== */

static void test_acquire_simultaneous_boot(void)
{
    TEST("Acquire: simultaneous boot (epoch=0) locks in 3 packets");
    acquire_state_t rx;
    state_init(&rx, "test-phrase");
    state_reset(&rx, 0);

    uint8_t payload[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t tx_payload[6];

    for (uint8_t i = 0; i < 3; i++) {
        memcpy(tx_payload, payload, 6);
        uint32_t tx_counter = (0 << 8) | (uint32_t)i;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        ASSERT_TRUE(rx_validate(&rx, i, tx_payload, 6, mac), "packet should pass");
    }
    ASSERT_TRUE(rx.epoch_locked, "should be locked after 3 packets");
    ASSERT_EQ(rx.nonce_epoch, (uint32_t)0, "locked epoch should be 0");
    PASS();
}

static void test_acquire_late_boot(void)
{
    TEST("Acquire: late boot (TX epoch=5) locks correctly");
    acquire_state_t rx;
    state_init(&rx, "test-phrase");
    state_reset(&rx, 100);

    uint8_t payload[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t tx_payload[6];
    uint32_t tx_epoch = 5;

    for (uint8_t i = 0; i < 3; i++) {
        memcpy(tx_payload, payload, 6);
        uint8_t nonce = 100 + i;
        uint32_t tx_counter = (tx_epoch << 8) | (uint32_t)nonce;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        ASSERT_TRUE(rx_validate(&rx, nonce, tx_payload, 6, mac), "packet should pass");
    }
    ASSERT_TRUE(rx.epoch_locked, "should be locked");
    ASSERT_EQ(rx.nonce_epoch, tx_epoch, "locked epoch should be 5");
    PASS();
}

static void test_acquire_nonce_minus_one(void)
{
    TEST("Acquire: RX nonce ahead by 1 still locks (nonce-1 fallback)");
    acquire_state_t rx;
    state_init(&rx, "test-phrase");
    state_reset(&rx, 50);

    uint8_t payload[6] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    uint8_t tx_payload[6];
    uint32_t tx_epoch = 3;

    for (uint8_t i = 0; i < 3; i++) {
        memcpy(tx_payload, payload, 6);
        uint8_t tx_nonce = 50 + i;
        uint8_t rx_nonce = tx_nonce + 1; /* RX is 1 ahead due to timer drift */
        uint32_t tx_counter = (tx_epoch << 8) | (uint32_t)tx_nonce;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        ASSERT_TRUE(rx_validate(&rx, rx_nonce, tx_payload, 6, mac), "nonce-1 should match");
    }
    ASSERT_TRUE(rx.epoch_locked, "should lock via nonce-1 path");
    ASSERT_EQ(rx.nonce_epoch, tx_epoch, "epoch should be 3");
    PASS();
}

static void test_acquire_miss_resets_count(void)
{
    TEST("Acquire: miss resets consecutive count (fix #2)");
    acquire_state_t rx;
    state_init(&rx, "test-phrase");
    state_reset(&rx, 0);

    uint8_t payload[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t tx_payload[6];

    /* Two valid packets at epoch=0 */
    for (uint8_t i = 0; i < 2; i++) {
        memcpy(tx_payload, payload, 6);
        uint32_t tx_counter = (0 << 8) | (uint32_t)i;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        ASSERT_TRUE(rx_validate(&rx, i, tx_payload, 6, mac), "valid packet");
    }
    ASSERT_EQ(rx.acquire_count, (uint8_t)2, "count should be 2");

    /* One garbage packet (wrong MAC) — should NOT match any epoch in scan window */
    memcpy(tx_payload, payload, 6);
    bool result = rx_validate(&rx, 2, tx_payload, 6, 0xDEAD);
    ASSERT_EQ(result, false, "garbage should fail");
    ASSERT_EQ(rx.acquire_count, (uint8_t)0, "count should reset on miss");

    /* After miss, scan_pos advanced to 16. Use epoch=20 which is in [16..31] */
    uint32_t recovery_epoch = 20;
    for (uint8_t i = 3; i < 6; i++) {
        memcpy(tx_payload, payload, 6);
        uint32_t tx_counter = (recovery_epoch << 8) | (uint32_t)i;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        ASSERT_TRUE(rx_validate(&rx, i, tx_payload, 6, mac), "valid after reset");
    }
    ASSERT_TRUE(rx.epoch_locked, "should lock after 3 fresh consecutive");
    ASSERT_EQ(rx.nonce_epoch, recovery_epoch, "locked at recovery epoch");
    PASS();
}

static void test_lock_fallback_on_failure(void)
{
    TEST("Lock: falls back to acquisition after 16 failures (fix #3)");
    acquire_state_t rx;
    state_init(&rx, "test-phrase");
    state_reset(&rx, 0);

    uint8_t payload[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t tx_payload[6];

    /* Lock at epoch=0 */
    for (uint8_t i = 0; i < 3; i++) {
        memcpy(tx_payload, payload, 6);
        uint32_t tx_counter = (0 << 8) | (uint32_t)i;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate(&rx, i, tx_payload, 6, mac);
    }
    ASSERT_TRUE(rx.epoch_locked, "should be locked");

    /* Send 16 garbage packets to trigger fallback */
    for (uint8_t i = 0; i < LOCK_FAIL_MAX; i++) {
        memcpy(tx_payload, payload, 6);
        rx_validate(&rx, 3 + i, tx_payload, 6, 0xBEEF);
    }
    ASSERT_EQ(rx.epoch_locked, false, "should fall back to acquisition");
    ASSERT_EQ(rx.acquire_count, (uint8_t)0, "acquire count reset");

    /* Now can re-acquire at a different epoch */
    uint32_t new_epoch = 10;
    for (uint8_t i = 0; i < 3; i++) {
        memcpy(tx_payload, payload, 6);
        uint8_t nonce = 20 + i;
        uint32_t tx_counter = (new_epoch << 8) | (uint32_t)nonce;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate(&rx, nonce, tx_payload, 6, mac);
    }
    ASSERT_TRUE(rx.epoch_locked, "should re-lock at new epoch");
    ASSERT_EQ(rx.nonce_epoch, new_epoch, "epoch should be 10");
    PASS();
}

static void test_acquire_sliding_window(void)
{
    TEST("Acquire: epoch outside first 16 found via sliding window");
    acquire_state_t rx;
    state_init(&rx, "test-phrase");
    state_reset(&rx, 0);

    uint8_t payload[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t tx_payload[6];
    uint32_t tx_epoch = 200; /* Outside first 16-epoch scan window */

    /* First packet will miss (scan 0-15), second misses (scan 16-31), etc. */
    int packets_until_found = 0;
    for (uint8_t i = 0; i < 255; i++) {
        memcpy(tx_payload, payload, 6);
        uint8_t nonce = i;
        uint32_t tx_counter = (tx_epoch << 8) | (uint32_t)nonce;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        if (rx_validate(&rx, nonce, tx_payload, 6, mac)) {
            packets_until_found = i + 1;
            break;
        }
    }
    ASSERT_TRUE(packets_until_found > 0, "should eventually find epoch");
    ASSERT_TRUE(packets_until_found <= 16, "should find within 16 packets");

    /* Continue to lock */
    for (uint8_t i = packets_until_found; i < packets_until_found + 2; i++) {
        memcpy(tx_payload, payload, 6);
        uint8_t nonce = i;
        uint32_t tx_counter = (tx_epoch << 8) | (uint32_t)nonce;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate(&rx, nonce, tx_payload, 6, mac);
    }
    ASSERT_TRUE(rx.epoch_locked, "should lock after sliding window finds epoch");
    ASSERT_EQ(rx.nonce_epoch, tx_epoch, "epoch should be 200");
    PASS();
}

static void test_acquire_sync_preserves_progress(void)
{
    TEST("Acquire: MurmurSyncNonce preserves acquisition progress");
    acquire_state_t rx;
    state_init(&rx, "test-phrase");
    state_reset(&rx, 10);

    uint8_t payload[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t tx_payload[6];
    uint32_t tx_epoch = 2;

    /* Two valid hits */
    for (uint8_t i = 0; i < 2; i++) {
        memcpy(tx_payload, payload, 6);
        uint8_t nonce = 10 + i;
        uint32_t tx_counter = (tx_epoch << 8) | (uint32_t)nonce;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate(&rx, nonce, tx_payload, 6, mac);
    }
    ASSERT_EQ(rx.acquire_count, (uint8_t)2, "count should be 2");

    /* SYNC re-syncs nonce (non-disconnect path) */
    state_sync_nonce(&rx, 12);
    ASSERT_EQ(rx.acquire_count, (uint8_t)2, "count preserved after sync_nonce");
    ASSERT_EQ(rx.epoch_locked, false, "still in acquisition");

    /* Third hit locks in */
    memcpy(tx_payload, payload, 6);
    uint32_t tx_counter = (tx_epoch << 8) | 12u;
    uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
    rx_validate(&rx, 12, tx_payload, 6, mac);
    ASSERT_TRUE(rx.epoch_locked, "should lock on third consecutive");
    PASS();
}

static void test_lock_survives_valid_packets(void)
{
    TEST("Lock: counter tracks correctly across many packets");
    acquire_state_t rx;
    state_init(&rx, "test-phrase");
    state_reset(&rx, 0);

    uint8_t payload[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t tx_payload[6];

    /* Lock at epoch=0 */
    for (uint8_t i = 0; i < 3; i++) {
        memcpy(tx_payload, payload, 6);
        uint32_t tx_counter = (0 << 8) | (uint32_t)i;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate(&rx, i, tx_payload, 6, mac);
    }
    ASSERT_TRUE(rx.epoch_locked, "locked");

    /* Send 500 more packets including an epoch wrap */
    int valid_count = 0;
    for (uint32_t i = 3; i < 503; i++) {
        memcpy(tx_payload, payload, 6);
        uint8_t nonce = (uint8_t)(i & 0xFF);
        uint32_t tx_epoch = i >> 8;
        uint32_t tx_counter = (tx_epoch << 8) | (uint32_t)nonce;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        if (rx_validate(&rx, nonce, tx_payload, 6, mac))
            valid_count++;
    }
    ASSERT_EQ(valid_count, 500, "all 500 packets should validate");
    ASSERT_TRUE(rx.epoch_locked, "still locked");
    PASS();
}

static void test_acquire_wrong_key_never_locks(void)
{
    TEST("Acquire: wrong key never locks (adversarial)");
    acquire_state_t rx;
    state_init(&rx, "correct-phrase");
    state_reset(&rx, 0);

    /* Attacker uses different key */
    uint8_t attacker_key[16];
    uint8_t uid[6];
    murmur_derive_keys("wrong-phrase", attacker_key, uid);

    uint8_t payload[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t tx_payload[6];

    int accepted = 0;
    for (uint8_t i = 0; i < 100; i++) {
        memcpy(tx_payload, payload, 6);
        uint32_t tx_counter = (0 << 8) | (uint32_t)i;
        uint16_t mac = murmur_encrypt_packet(attacker_key, tx_counter, 0x01, 0, tx_payload, 6, 14);
        if (rx_validate(&rx, i, tx_payload, 6, mac))
            accepted++;
    }
    ASSERT_EQ(rx.epoch_locked, false, "should never lock with wrong key");
    /* With 14-bit MAC and 32 trials/packet, expect ~0.2% false accept rate */
    ASSERT_TRUE(accepted < 5, "very few false accepts expected");
    PASS();
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(void)
{
    printf("\n=== MurmurLRS Acquisition Mode Test Suite ===\n\n");

    printf("[Acquisition]\n");
    test_acquire_simultaneous_boot();
    test_acquire_late_boot();
    test_acquire_nonce_minus_one();
    test_acquire_miss_resets_count();
    test_acquire_sliding_window();
    test_acquire_sync_preserves_progress();
    test_acquire_wrong_key_never_locks();

    printf("\n[Lock fallback]\n");
    test_lock_fallback_on_failure();
    test_lock_survives_valid_packets();

    printf("\n=== Results: %d/%d passed ===\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
