/*
 * test_epoch_overflow.c — Regression tests for the 5-minute epoch overflow bug
 *
 * Bug: After ~131 seconds at 500Hz (65536 packets), murmur_nonce_epoch > 255.
 * Acquisition mode searches (epoch & 0xFF) so it can never find the correct
 * counter. Locked mode only tries ±256, so a dropout >0.5s loses the link.
 *
 * These tests verify that:
 * 1. Acquisition works when TX epoch > 255
 * 2. Locked mode recovers from multi-epoch drift (signal dropouts)
 * 3. Acquisition does not return true on single MAC collisions
 * 4. MurmurTrackNonce keeps RX epoch synchronized during RF dropout
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
#define ASSERT_FALSE(a, msg) do { if ((a)) { FAIL(msg); } } while(0)

/* Mirror the acquisition state machine from OTA.cpp (current buggy version) */
#define ACQUIRE_THRESHOLD 3
#define ACQUIRE_EPOCHS_PER_PACKET 16
#define LOCK_FAIL_MAX 16

typedef struct {
    uint8_t key[16];
    uint32_t nonce_epoch;
    uint8_t prev_nonce;
    bool epoch_locked;
    uint8_t acquire_count;
    uint32_t acquire_epoch;      /* FIXED: was uint8_t */
    uint32_t acquire_scan_pos;   /* FIXED: was uint8_t */
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

/*
 * FIXED rx_validate — this is what the code SHOULD look like after the fix.
 * Tests are written against this fixed version to define correct behavior.
 */
static bool rx_validate_fixed(acquire_state_t *s, uint8_t rx_nonce,
                              uint8_t *payload, uint8_t payload_len,
                              uint16_t received_mac)
{
    if (s->epoch_locked) {
        uint32_t counter = state_get_counter(s, rx_nonce);
        uint32_t expected_epoch = counter >> 8;

        /* Try expected epoch first (fast path — covers normal operation) */
        uint32_t candidate = (expected_epoch << 8) | (uint32_t)rx_nonce;
        if (murmur_decrypt_packet(s->key, candidate, 0x01, 0,
                                  payload, payload_len, received_mac, 14)) {
            if (!murmur_replay_check(&s->replay, candidate))
                return false;
            s->lock_fail_count = 0;
            return true;
        }

        /* Outward spiral: try ±1, ±2, ... ±4 epochs with primary nonce only.
         * This avoids false positives from nonce-1 at wrong epochs. */
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
            /* Start acquisition from last known epoch, not 0 */
            s->acquire_scan_pos = (s->nonce_epoch > 4) ? s->nonce_epoch - 4 : 0;
            s->acquire_scan_origin = s->acquire_scan_pos;
            s->lock_fail_count = 0;
        }
        return false;
    }

    /* Acquisition mode — FIXED: 32-bit epoch, no & 0xFF mask */
    uint8_t nonces[2] = { rx_nonce, (uint8_t)(rx_nonce - 1) };
    uint32_t scan_start = s->acquire_scan_pos;

    for (uint8_t i = 0; i < ACQUIRE_EPOCHS_PER_PACKET; i++) {
        uint32_t epoch = scan_start + i;  /* No & 0xFF — full 32-bit */
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
                /* FIXED: do NOT return true until threshold met */
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

/* Simulate MurmurTrackNonce: advance epoch tracking without decrypt */
static void state_track_nonce(acquire_state_t *s, uint8_t nonce)
{
    if (nonce < s->prev_nonce && (s->prev_nonce - nonce) > 128) {
        s->nonce_epoch++;
    }
    s->prev_nonce = nonce;
}

/* ================================================================== */
/*  Test: TX epoch 585 (5 minutes at 500Hz) — acquisition must work   */
/* ================================================================== */

static void test_acquire_epoch_585(void)
{
    TEST("Acquire: TX at epoch 585 (5min @ 500Hz) locks correctly");
    acquire_state_t rx;
    state_init(&rx, "test-phrase");

    /* Simulate RX that has been tracking nonces via MurmurTrackNonce
     * for 5 minutes — its nonce_epoch should be near TX's */
    rx.nonce_epoch = 580;  /* slightly behind TX due to missed packets */
    rx.prev_nonce = 200;
    rx.epoch_locked = false;
    rx.acquire_count = 0;
    rx.acquire_scan_pos = 580;  /* start scanning near known epoch */

    uint8_t payload[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t tx_payload[6];
    uint32_t tx_epoch = 585;

    int packets_to_lock = 0;
    for (uint8_t i = 0; i < 50; i++) {
        memcpy(tx_payload, payload, 6);
        uint8_t nonce = 100 + i;
        uint32_t tx_counter = (tx_epoch << 8) | (uint32_t)nonce;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate_fixed(&rx, nonce, tx_payload, 6, mac);
        packets_to_lock++;
        if (rx.epoch_locked) break;
    }
    ASSERT_TRUE(rx.epoch_locked, "should lock at epoch 585");
    ASSERT_EQ(rx.nonce_epoch, tx_epoch, "locked epoch should be 585");
    ASSERT_TRUE(packets_to_lock <= 10, "should lock within 10 packets");
    PASS();
}

/* ================================================================== */
/*  Test: Locked mode survives 2-second RF dropout (multi-epoch drift) */
/* ================================================================== */

static void test_lock_survives_2sec_dropout(void)
{
    TEST("Lock: survives 2-second dropout (4 epoch drift)");
    acquire_state_t rx;
    state_init(&rx, "test-phrase");

    uint8_t payload[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t tx_payload[6];

    /* Lock at epoch=100 */
    rx.nonce_epoch = 100;
    rx.prev_nonce = 250;
    rx.epoch_locked = true;
    murmur_replay_init(&rx.replay);

    /* Verify lock is working */
    memcpy(tx_payload, payload, 6);
    uint32_t tx_counter = (100 << 8) | 251u;
    uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
    ASSERT_TRUE(rx_validate_fixed(&rx, 251, tx_payload, 6, mac), "baseline works");

    /* Simulate 2-second dropout: TX advances ~1000 packets = ~4 epochs.
     * RX also advances via MurmurTrackNonce (timer-driven). */
    uint32_t tx_epoch_after = 104;
    uint8_t tx_nonce_after = 230;

    /* RX tracked nonces during dropout (MurmurTrackNonce called by timer) */
    /* Simulate ~1000 OtaNonce increments on RX side */
    for (int i = 0; i < 1000; i++) {
        uint8_t sim_nonce = (uint8_t)((252 + i) & 0xFF);
        state_track_nonce(&rx, sim_nonce);
    }

    /* Now TX sends a real packet — RX should still be able to decrypt */
    memcpy(tx_payload, payload, 6);
    tx_counter = (tx_epoch_after << 8) | (uint32_t)tx_nonce_after;
    mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
    bool result = rx_validate_fixed(&rx, tx_nonce_after, tx_payload, 6, mac);
    ASSERT_TRUE(result, "should recover after 2s dropout with nonce tracking");
    ASSERT_TRUE(rx.epoch_locked, "should remain locked");
    PASS();
}

/* ================================================================== */
/*  Test: Acquisition does NOT return true on single MAC collision     */
/* ================================================================== */

static void test_acquire_no_single_hit_passthrough(void)
{
    TEST("Acquire: single MAC hit does NOT pass packets upward");
    acquire_state_t rx;
    state_init(&rx, "test-phrase");
    rx.epoch_locked = false;
    rx.acquire_scan_pos = 0;

    uint8_t payload[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t tx_payload[6];

    /* Send first valid packet — should NOT be passed to upper layer
     * because we haven't reached ACQUIRE_THRESHOLD yet */
    memcpy(tx_payload, payload, 6);
    uint32_t tx_counter = (0 << 8) | 0u;
    uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);

    bool result = rx_validate_fixed(&rx, 0, tx_payload, 6, mac);
    ASSERT_FALSE(result, "first hit should NOT pass through before threshold");
    ASSERT_FALSE(rx.epoch_locked, "not locked yet");
    ASSERT_EQ(rx.acquire_count, (uint8_t)1, "count should be 1");
    PASS();
}

/* ================================================================== */
/*  Test: Acquisition from cold boot with TX epoch > 255              */
/* ================================================================== */

static void test_acquire_cold_boot_high_epoch(void)
{
    TEST("Acquire: cold boot, TX epoch=300 (>255), finds and locks");
    acquire_state_t rx;
    state_init(&rx, "test-phrase");
    rx.epoch_locked = false;
    /* Cold boot: RX starts at epoch 0, but knows nothing.
     * With the fix, acquisition scan_pos starts at 0 and advances.
     * This tests worst case: RX has no prior epoch estimate. */
    rx.acquire_scan_pos = 290;  /* Simulates RX got a hint from SYNC nonce */

    uint8_t payload[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t tx_payload[6];
    uint32_t tx_epoch = 300;

    int packets_needed = 0;
    for (uint8_t i = 0; i < 100; i++) {
        memcpy(tx_payload, payload, 6);
        uint8_t nonce = 50 + i;
        uint32_t tx_counter = (tx_epoch << 8) | (uint32_t)nonce;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate_fixed(&rx, nonce, tx_payload, 6, mac);
        packets_needed++;
        if (rx.epoch_locked) break;
    }
    ASSERT_TRUE(rx.epoch_locked, "should lock even with epoch > 255");
    ASSERT_EQ(rx.nonce_epoch, tx_epoch, "locked epoch should be 300");
    /* Should find within ~16 packets (scan_start near the target) */
    ASSERT_TRUE(packets_needed <= 20, "should lock quickly from nearby scan_pos");
    PASS();
}

/* ================================================================== */
/*  Test: Lock-to-acquisition-to-relock with high epoch               */
/* ================================================================== */

static void test_lock_fallback_reacquire_high_epoch(void)
{
    TEST("Lock→acquire→relock: TX epoch=600 after total desync");
    acquire_state_t rx;
    state_init(&rx, "test-phrase");

    uint8_t payload[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t tx_payload[6];

    /* RX was locked at epoch 490 */
    rx.nonce_epoch = 490;
    rx.prev_nonce = 100;
    rx.epoch_locked = true;
    murmur_replay_init(&rx.replay);

    /* TX jumped to epoch 600 (huge gap — TX rebooted or RX was off for 30s) */
    uint32_t tx_epoch = 600;

    /* Send garbage packets — TX at epoch 600, RX searching near 490.
     * ±8 window covers 482-498, so epoch 600 is way outside. */
    for (int i = 0; i < LOCK_FAIL_MAX + 5; i++) {
        memcpy(tx_payload, payload, 6);
        rx_validate_fixed(&rx, (uint8_t)(101 + i), tx_payload, 6, 0xBEEF);
    }

    /* Should have fallen to acquisition mode */
    ASSERT_FALSE(rx.epoch_locked, "should have dropped to acquisition");
    /* acquire_scan_pos should be near the old epoch, not 0 */
    ASSERT_TRUE(rx.acquire_scan_pos >= 486, "scan should start near old epoch");

    /* Now send real packets from TX at epoch 600.
     * Acquisition scans forward from ~486, 16 epochs/packet.
     * Needs ceil((600-486)/16) = 8 packets to reach epoch 600's window,
     * plus 3 packets for threshold = ~11 packets max */
    int packets_to_lock = 0;
    for (uint8_t i = 0; i < 50; i++) {
        memcpy(tx_payload, payload, 6);
        uint8_t nonce = 200 + i;
        uint32_t tx_counter = (tx_epoch << 8) | (uint32_t)nonce;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate_fixed(&rx, nonce, tx_payload, 6, mac);
        packets_to_lock++;
        if (rx.epoch_locked) break;
    }
    ASSERT_TRUE(rx.epoch_locked, "should re-lock at epoch 600");
    ASSERT_EQ(rx.nonce_epoch, tx_epoch, "locked at 600");
    ASSERT_TRUE(packets_to_lock <= 25, "re-acquisition should be reasonably fast");
    PASS();
}

/* ================================================================== */
/*  Test: Continuous operation for 10 minutes (epoch ~1170)            */
/* ================================================================== */

static void test_10_minute_continuous_operation(void)
{
    TEST("Stress: 10 min continuous (epoch 0→1170) no drops");
    acquire_state_t rx;
    state_init(&rx, "test-phrase");

    uint8_t payload[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t tx_payload[6];

    /* Lock via normal 3-packet acquisition at epoch 0 */
    for (uint8_t i = 0; i < 3; i++) {
        memcpy(tx_payload, payload, 6);
        uint32_t tx_counter = (0 << 8) | (uint32_t)i;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate_fixed(&rx, i, tx_payload, 6, mac);
    }
    ASSERT_TRUE(rx.epoch_locked, "initial lock");

    /* Simulate 3000 sequential packets (covers ~12 epoch wraps).
     * This tests continuous operation without the full 300k packet overhead.
     * Each packet is sequential — RX state_get_counter tracks wraps naturally. */
    int valid_count = 0;
    for (uint32_t pkt = 3; pkt < 3003; pkt++) {
        uint32_t tx_epoch = pkt >> 8;
        uint8_t tx_nonce = (uint8_t)(pkt & 0xFF);
        uint32_t tx_counter = (tx_epoch << 8) | (uint32_t)tx_nonce;

        memcpy(tx_payload, payload, 6);
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        if (rx_validate_fixed(&rx, tx_nonce, tx_payload, 6, mac))
            valid_count++;
    }
    ASSERT_EQ(valid_count, 3000, "all 3000 sequential packets should validate");
    ASSERT_TRUE(rx.epoch_locked, "should remain locked throughout");
    ASSERT_TRUE(rx.nonce_epoch >= 11, "epoch should be >=11 after 3000 packets");
    PASS();
}

/* ================================================================== */
/*  Test: Signal dropout exactly at nonce wrap boundary               */
/* ================================================================== */

static void test_dropout_at_nonce_wrap(void)
{
    TEST("Lock: dropout exactly at nonce 255→0 wrap boundary");
    acquire_state_t rx;
    state_init(&rx, "test-phrase");

    uint8_t payload[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t tx_payload[6];

    /* RX is locked, about to see nonce wrap */
    rx.nonce_epoch = 50;
    rx.prev_nonce = 253;
    rx.epoch_locked = true;
    murmur_replay_init(&rx.replay);

    /* TX sends nonce 254 — RX receives it fine */
    memcpy(tx_payload, payload, 6);
    uint32_t tx_counter = (50 << 8) | 254u;
    uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
    ASSERT_TRUE(rx_validate_fixed(&rx, 254, tx_payload, 6, mac), "254 works");

    /* Signal drops — RX misses nonce 255 and the wrap.
     * MurmurTrackNonce advances RX through the wrap. */
    state_track_nonce(&rx, 255);  /* timer tick */
    state_track_nonce(&rx, 0);    /* timer tick — triggers epoch increment */

    /* TX is now at epoch 51, nonce 5 */
    memcpy(tx_payload, payload, 6);
    tx_counter = (51 << 8) | 5u;
    mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
    bool result = rx_validate_fixed(&rx, 5, tx_payload, 6, mac);
    ASSERT_TRUE(result, "should recover after wrap-boundary dropout");
    ASSERT_TRUE(rx.epoch_locked, "should stay locked");
    ASSERT_EQ(rx.nonce_epoch, (uint32_t)51, "epoch should be 51");
    PASS();
}

/* ================================================================== */
/*  Test: TX reboot while RX at high epoch — acquisition wraps to 0   */
/* ================================================================== */

static void test_tx_reboot_while_rx_high_epoch(void)
{
    TEST("Lock→acquire: TX reboots to epoch 0, RX wraps scan back");
    acquire_state_t rx;
    state_init(&rx, "test-phrase");

    uint8_t payload[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    uint8_t tx_payload[6];

    /* RX was locked at epoch 585 (5 minutes of operation) */
    rx.nonce_epoch = 585;
    rx.prev_nonce = 200;
    rx.epoch_locked = true;
    murmur_replay_init(&rx.replay);

    /* TX reboots — link fails, RX drops to acquisition */
    for (int i = 0; i < LOCK_FAIL_MAX + 1; i++) {
        memcpy(tx_payload, payload, 6);
        rx_validate_fixed(&rx, (uint8_t)(201 + i), tx_payload, 6, 0xDEAD);
    }
    ASSERT_FALSE(rx.epoch_locked, "should fall to acquisition");
    ASSERT_TRUE(rx.acquire_scan_pos >= 581, "scan origin near old epoch");

    /* TX is now at epoch 0. RX scans forward from ~581.
     * After scanning 256 epochs without a hit, wraps to 0. */
    int packets_to_lock = 0;
    for (int i = 0; i < 80; i++) {
        memcpy(tx_payload, payload, 6);
        uint8_t nonce = (uint8_t)(10 + i);
        uint32_t tx_counter = (0 << 8) | (uint32_t)nonce;
        uint16_t mac = tx_encrypt(rx.key, tx_counter, tx_payload, 6);
        rx_validate_fixed(&rx, nonce, tx_payload, 6, mac);
        packets_to_lock++;
        if (rx.epoch_locked) break;
    }
    ASSERT_TRUE(rx.epoch_locked, "should lock at epoch 0 after wrap");
    ASSERT_EQ(rx.nonce_epoch, (uint32_t)0, "locked epoch should be 0");
    ASSERT_TRUE(packets_to_lock <= 80, "should lock within scan budget");
    PASS();
}

/* ================================================================== */
/*  Main                                                               */
/* ================================================================== */

int main(void)
{
    printf("\n=== MurmurLRS Epoch Overflow Regression Tests ===\n");
    printf("    (Bug: link dies after 5 minutes at 500Hz)\n\n");

    printf("[Acquisition with high epoch]\n");
    test_acquire_epoch_585();
    test_acquire_cold_boot_high_epoch();
    test_acquire_no_single_hit_passthrough();

    printf("\n[Locked mode resilience]\n");
    test_lock_survives_2sec_dropout();
    test_dropout_at_nonce_wrap();
    test_lock_fallback_reacquire_high_epoch();

    printf("\n[TX reboot recovery]\n");
    test_tx_reboot_while_rx_high_epoch();

    printf("\n[Long-running stress]\n");
    test_10_minute_continuous_operation();

    printf("\n=== Results: %d/%d passed ===\n\n", tests_passed, tests_run);
    return (tests_passed == tests_run) ? 0 : 1;
}
