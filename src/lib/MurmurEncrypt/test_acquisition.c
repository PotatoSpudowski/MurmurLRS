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
    uint32_t acquire_epoch;
    uint32_t acquire_scan_pos;
    uint32_t acquire_scan_origin;
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
    s->acquire_scan_origin = 0;
    s->lock_fail_count = 0;
    murmur_replay_init(&s->replay);
}

static void state_reset(acquire_state_t *s, uint8_t nonce)
{
    s->prev_nonce = nonce;
    s->epoch_locked = false;
    s->acquire_count = 0;
    s->acquire_scan_pos = 0;
    s->acquire_scan_origin = 0;
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

/* Simulate RX validation (mirrors MurmurValidatePacketCrc logic) */
static bool rx_validate(acquire_state_t *s, uint8_t rx_nonce,
                        uint8_t *payload, uint8_t payload_len,
                        uint16_t received_mac)
{
    if (s->epoch_locked) {
        uint32_t counter = state_get_counter(s, rx_nonce);
        uint32_t expected_epoch = counter >> 8;

        /* Fast path: expected epoch with primary nonce */
        uint32_t candidate = (expected_epoch << 8) | (uint32_t)rx_nonce;
        if (murmur_decrypt_packet(s->key, candidate, 0x01, 0,
                                  payload, payload_len, received_mac, 14)) {
            if (!murmur_replay_check(&s->replay, candidate))
                return false;
            s->lock_fail_count = 0;
            return true;
        }

        /* Outward spiral: ±1..±4 epochs with primary nonce */
        for (uint32_t d = 1; d <= 4; d++) {
            uint32_t epochs[2] = { expected_epoch + d,
                                   (expected_epoch >= d) ? expected_epoch - d : 0xFFFFFFFF };
            for (int e = 0; e < 2; e++) {
                if (epochs[e] == 0xFFFFFFFF) continue;
                candidate = (epochs[e] << 8) | (uint32_t)rx_nonce;
                if (murmur_decrypt_packet(s->key, candidate, 0x01, 0,
                                          payload, payload_len, received_mac, 14)) {
                    if (!murmur_replay_check(&s->replay, candidate))
                        return false;
                    s->nonce_epoch = epochs[e];
                    s->prev_nonce = rx_nonce;
                    s->lock_fail_count = 0;
                    return true;
                }
            }
        }

        /* Last resort: nonce-1 (if nonce=0, belongs to previous epoch) */
        uint8_t nonce_m1 = (uint8_t)(rx_nonce - 1);
        uint32_t nonce_m1_epoch = (rx_nonce == 0 && expected_epoch > 0)
                                  ? expected_epoch - 1 : expected_epoch;
        candidate = (nonce_m1_epoch << 8) | (uint32_t)nonce_m1;
        if (murmur_decrypt_packet(s->key, candidate, 0x01, 0,
                                  payload, payload_len, received_mac, 14)) {
            if (!murmur_replay_check(&s->replay, candidate))
                return false;
            s->nonce_epoch = nonce_m1_epoch;
            s->prev_nonce = nonce_m1;
            s->lock_fail_count = 0;
            return true;
        }

        if (++s->lock_fail_count >= LOCK_FAIL_MAX) {
            s->epoch_locked = false;
            s->acquire_count = 0;
            s->acquire_scan_pos = (s->nonce_epoch > 4) ? s->nonce_epoch - 4 : 0;
            s->acquire_scan_origin = s->acquire_scan_pos;
            s->lock_fail_count = 0;
        }
        return false;
    }

    /* Acquisition mode — 32-bit epoch, no & 0xFF mask */
    uint8_t nonces[2] = { rx_nonce, (uint8_t)(rx_nonce - 1) };
    uint32_t scan_start = s->acquire_scan_pos;

    for (uint8_t i = 0; i < ACQUIRE_EPOCHS_PER_PACKET; i++) {
        uint32_t epoch = scan_start + i;
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
                    return true;
                }
                s->acquire_scan_pos = epoch;
                return false;
            }
        }
    }

    s->acquire_count = 0;
    s->acquire_scan_pos = scan_start + ACQUIRE_EPOCHS_PER_PACKET;
    if (s->acquire_scan_pos - s->acquire_scan_origin >= 256) {
        s->acquire_scan_pos = 0;
        s->acquire_scan_origin = 0;
    }
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

    /* First two packets find epoch but don't pass threshold */
    for (uint8_t i = 0; i < 2; i++) {
        memcpy(tx_payload, payload, 6);
        uint32_t tx_counter = (0 << 8) | (uint32_t)i;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        ASSERT_EQ(rx_validate(&rx, i, tx_payload, 6, mac), false, "pre-threshold returns false");
    }
    ASSERT_EQ(rx.epoch_locked, false, "not locked until threshold");

    /* Third packet meets threshold — returns true and locks */
    memcpy(tx_payload, payload, 6);
    uint32_t tx_counter = (0 << 8) | 2u;
    uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
    ASSERT_TRUE(rx_validate(&rx, 2, tx_payload, 6, mac), "third packet locks");
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

    /* Acquisition scans forward from 0. Epoch 5 is within first scan window. */
    int locked_at = -1;
    for (uint8_t i = 0; i < 10; i++) {
        memcpy(tx_payload, payload, 6);
        uint8_t nonce = 100 + i;
        uint32_t tx_counter = (tx_epoch << 8) | (uint32_t)nonce;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate(&rx, nonce, tx_payload, 6, mac);
        if (rx.epoch_locked) { locked_at = i; break; }
    }
    ASSERT_TRUE(rx.epoch_locked, "should be locked");
    ASSERT_EQ(rx.nonce_epoch, tx_epoch, "locked epoch should be 5");
    ASSERT_TRUE(locked_at <= 5, "should lock within 5 packets");
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

    int locked_at = -1;
    for (uint8_t i = 0; i < 10; i++) {
        memcpy(tx_payload, payload, 6);
        uint8_t tx_nonce = 50 + i;
        uint8_t rx_nonce = tx_nonce + 1; /* RX is 1 ahead due to timer drift */
        uint32_t tx_counter = (tx_epoch << 8) | (uint32_t)tx_nonce;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate(&rx, rx_nonce, tx_payload, 6, mac);
        if (rx.epoch_locked) { locked_at = i; break; }
    }
    ASSERT_TRUE(rx.epoch_locked, "should lock via nonce-1 path");
    ASSERT_EQ(rx.nonce_epoch, tx_epoch, "epoch should be 3");
    ASSERT_TRUE(locked_at <= 5, "should lock within 5 packets");
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

    /* Two valid packets at epoch=0 — returns false (below threshold) */
    for (uint8_t i = 0; i < 2; i++) {
        memcpy(tx_payload, payload, 6);
        uint32_t tx_counter = (0 << 8) | (uint32_t)i;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate(&rx, i, tx_payload, 6, mac);
    }
    ASSERT_EQ(rx.acquire_count, (uint8_t)2, "count should be 2");

    /* One garbage packet (wrong MAC) — should NOT match any epoch in scan window */
    memcpy(tx_payload, payload, 6);
    bool result = rx_validate(&rx, 2, tx_payload, 6, 0xDEAD);
    ASSERT_EQ(result, false, "garbage should fail");
    ASSERT_EQ(rx.acquire_count, (uint8_t)0, "count should reset on miss");

    /* After miss, scan_pos advanced. Use epoch=20 which is in next scan window */
    uint32_t recovery_epoch = 20;
    int locked_at = -1;
    for (uint8_t i = 3; i < 20; i++) {
        memcpy(tx_payload, payload, 6);
        uint32_t tx_counter = (recovery_epoch << 8) | (uint32_t)i;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate(&rx, i, tx_payload, 6, mac);
        if (rx.epoch_locked) { locked_at = i; break; }
    }
    ASSERT_TRUE(rx.epoch_locked, "should lock after 3 fresh consecutive");
    ASSERT_EQ(rx.nonce_epoch, recovery_epoch, "locked at recovery epoch");
    ASSERT_TRUE(locked_at > 0, "should have locked");
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
    for (uint8_t i = 0; i < 5; i++) {
        memcpy(tx_payload, payload, 6);
        uint32_t tx_counter = (0 << 8) | (uint32_t)i;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate(&rx, i, tx_payload, 6, mac);
    }
    ASSERT_TRUE(rx.epoch_locked, "should be locked");

    /* Send 16 garbage packets to trigger fallback */
    for (uint8_t i = 0; i < LOCK_FAIL_MAX; i++) {
        memcpy(tx_payload, payload, 6);
        rx_validate(&rx, (uint8_t)(5 + i), tx_payload, 6, 0xBEEF);
    }
    ASSERT_EQ(rx.epoch_locked, false, "should fall back to acquisition");
    ASSERT_EQ(rx.acquire_count, (uint8_t)0, "acquire count reset");

    /* Now can re-acquire at a different epoch (scan_pos starts near 0) */
    uint32_t new_epoch = 10;
    int locked_at = -1;
    for (uint8_t i = 0; i < 20; i++) {
        memcpy(tx_payload, payload, 6);
        uint8_t nonce = 20 + i;
        uint32_t tx_counter = (new_epoch << 8) | (uint32_t)nonce;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate(&rx, nonce, tx_payload, 6, mac);
        if (rx.epoch_locked) { locked_at = i; break; }
    }
    ASSERT_TRUE(rx.epoch_locked, "should re-lock at new epoch");
    ASSERT_EQ(rx.nonce_epoch, new_epoch, "epoch should be 10");
    ASSERT_TRUE(locked_at > 0, "should have locked");
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

    /* Scan advances 16 epochs per miss. Need ceil(200/16) = 13 misses to reach
     * epoch 200's window, then 3 more for threshold = ~16 packets total */
    int locked_at = -1;
    for (uint8_t i = 0; i < 100; i++) {
        memcpy(tx_payload, payload, 6);
        uint8_t nonce = i;
        uint32_t tx_counter = (tx_epoch << 8) | (uint32_t)nonce;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate(&rx, nonce, tx_payload, 6, mac);
        if (rx.epoch_locked) { locked_at = i; break; }
    }
    ASSERT_TRUE(locked_at > 0, "should eventually find and lock");
    ASSERT_TRUE(rx.epoch_locked, "should lock after sliding window finds epoch");
    ASSERT_EQ(rx.nonce_epoch, tx_epoch, "epoch should be 200");
    /* ceil(200/16) misses + 3 threshold packets ~= 16 packets */
    ASSERT_TRUE(locked_at <= 20, "should lock within 20 packets");
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

    /* Two valid hits (returns false, but increments count) */
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

    /* Third hit locks in — returns true */
    memcpy(tx_payload, payload, 6);
    uint32_t tx_counter = (tx_epoch << 8) | 12u;
    uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
    bool result = rx_validate(&rx, 12, tx_payload, 6, mac);
    ASSERT_TRUE(result, "third hit should return true");
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

    /* Lock at epoch=0 (3 packets for acquisition threshold) */
    for (uint8_t i = 0; i < 5; i++) {
        memcpy(tx_payload, payload, 6);
        uint32_t tx_counter = (0 << 8) | (uint32_t)i;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate(&rx, i, tx_payload, 6, mac);
    }
    ASSERT_TRUE(rx.epoch_locked, "locked");

    /* Send 500 more packets including epoch wraps */
    int valid_count = 0;
    for (uint32_t i = 5; i < 505; i++) {
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

static void test_acquire_tx_reboot_wrap(void)
{
    TEST("Acquire: TX reboot (epoch 0) found after RX was at epoch 500");
    acquire_state_t rx;
    state_init(&rx, "test-phrase");

    uint8_t payload[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t tx_payload[6];

    /* Simulate RX was locked at epoch 500, then lost link */
    rx.nonce_epoch = 500;
    rx.prev_nonce = 100;
    rx.epoch_locked = true;
    murmur_replay_init(&rx.replay);

    /* Send garbage to trigger lock failure → acquisition mode */
    for (int i = 0; i < LOCK_FAIL_MAX + 1; i++) {
        memcpy(tx_payload, payload, 6);
        rx_validate(&rx, (uint8_t)(101 + i), tx_payload, 6, 0xBEEF);
    }
    ASSERT_EQ(rx.epoch_locked, false, "should drop to acquisition");
    ASSERT_TRUE(rx.acquire_scan_pos >= 496, "scan starts near old epoch");

    /* TX rebooted — now at epoch 0. RX scans forward from ~496.
     * After 256 epochs of scanning without a hit, scan wraps to 0.
     * Then it should find epoch 0 within a few more packets. */
    int locked_at = -1;
    for (int i = 0; i < 80; i++) {
        memcpy(tx_payload, payload, 6);
        uint8_t nonce = (uint8_t)(50 + i);
        uint32_t tx_counter = (0 << 8) | (uint32_t)nonce;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate(&rx, nonce, tx_payload, 6, mac);
        if (rx.epoch_locked) { locked_at = i; break; }
    }
    ASSERT_TRUE(rx.epoch_locked, "should lock at epoch 0 after wrap");
    ASSERT_EQ(rx.nonce_epoch, (uint32_t)0, "locked epoch should be 0");
    ASSERT_TRUE(locked_at > 0, "should have locked");
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
    test_acquire_tx_reboot_wrap();

    printf("\n=== Results: %d/%d passed ===\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
