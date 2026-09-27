#include <unity.h>
#include <cstring>
#include <cstdio>
#include "MurmurSession.h"
#include "vendor/SHA256.h"

using S = MurmurSession;
#if defined(MURMUR_SESSION_STANDALONE)
extern "C" void setUp(void) {}
extern "C" void tearDown(void) {}
#endif
static const uint8_t master[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
struct Rng {
    unsigned calls = 0;
    uint8_t seed;
    bool fail = false, stuck = false, zeros = false;
    explicit Rng(uint8_t s) : seed(s) {}
    static bool fill(void *context, uint8_t out[16]) {
        Rng &r = *static_cast<Rng *>(context);
        ++r.calls;
        if (r.fail) return false;
        for (unsigned i = 0; i < 16; ++i)
            out[i] = r.zeros ? 0 : r.seed + i + (r.stuck ? 0 : r.calls);
        return true;
    }
};
struct Pair {
    Rng tr{10}, rr{60};
    S tx{true, master, Rng::fill, &tr}, rx{false, master, Rng::fill, &rr};
    uint8_t hello[50], reply[50], confirm[50], ready[50];
    void establish() {
        TEST_ASSERT_EQUAL(S::Send, tx.start(hello));
        TEST_ASSERT_EQUAL(S::Send, rx.receive(hello, 50, reply));
        TEST_ASSERT_EQUAL(S::Send, tx.receive(reply, 50, confirm));
        TEST_ASSERT_EQUAL(S::Send | S::Activated, rx.receive(confirm, 50, ready));
        TEST_ASSERT_EQUAL(S::Activated, tx.receive(ready, 50, hello));
    }
};
static void hex(const char *text, uint8_t *out, size_t length) {
    for (size_t i = 0; i < length; ++i) {
        unsigned value;
        sscanf(text + 2*i, "%2x", &value);
        out[i] = value;
    }
}
static void checkKeys(const S &a, const S &b) {
    uint8_t au[16], ad[16], bu[16], bd[16];
    TEST_ASSERT_TRUE(a.getKeys(au, ad));
    TEST_ASSERT_TRUE(b.getKeys(bu, bd));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(au, bu, 16);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(ad, bd, 16);
    TEST_ASSERT_NOT_EQUAL(0, memcmp(au, ad, 16));
}

void test_rfc4231_hmac_sha256() {
    uint8_t key[20], actual[32], expected[32];
    memset(key, 0x0b, sizeof(key));
    SHA256 hash;
    hash.resetHMAC(key, sizeof(key));
    hash.update("Hi There", 8);
    hash.finalizeHMAC(key, sizeof(key), actual, sizeof(actual));
    hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7", expected, 32);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, actual, 32);
}
void test_rfc5869_hkdf() {
    uint8_t ikm[22], salt[13], info[10], expected[32], actual[32];
    memset(ikm, 0x0b, sizeof(ikm));
    for (unsigned i=0; i<sizeof(salt); ++i) salt[i]=i;
    for (unsigned i=0; i<sizeof(info); ++i) info[i]=0xf0+i;
    hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf", expected, 32);
    murmur_hkdf_sha256_32(salt, sizeof(salt), ikm, sizeof(ikm), info, sizeof(info), actual);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, actual, 32);
    hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d", expected, 32);
    murmur_hkdf_sha256_32(nullptr, 0, ikm, sizeof(ikm), nullptr, 0, actual);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, actual, 32);
}
void test_key_agreement_and_confirmation() {
    Pair p;
    uint8_t up[16], down[16];
    TEST_ASSERT_FALSE(p.tx.getKeys(up, down));
    TEST_ASSERT_FALSE(p.rx.getKeys(up, down));
    p.tx.start(p.hello);
    p.rx.receive(p.hello, 50, p.reply);
    p.tx.receive(p.reply, 50, p.confirm);
    TEST_ASSERT_FALSE(p.tx.active());
    TEST_ASSERT_FALSE(p.rx.active());
    TEST_ASSERT_EQUAL(S::Send | S::Activated, p.rx.receive(p.confirm, 50, p.ready));
    TEST_ASSERT_FALSE(p.tx.active());
    TEST_ASSERT_EQUAL(S::Activated, p.tx.receive(p.ready, 50, p.hello));
    checkKeys(p.tx, p.rx);
}
void test_independent_python_wire_and_key_vectors() {
    // Generated with Python hashlib/hmac, independently of the vendored code.
    Pair p; uint8_t expected[50], up[16], down[16];
    p.establish();
    hex("01010b0c0d0e0f101112131415161718191a00000000000000000000000000000000e60a8175784f71ca8f62d8d51249f6e6", expected, 50);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, p.hello, 50);
    p.tx.getKeys(up, down);
    hex("22c1428bae7ae3102a172bae492c99e0", expected, 16);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, up, 16);
    hex("38df453b51045bc57878d6ae1a851ea8", expected, 16);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(expected, down, 16);
}

void test_all_message_bytes_authenticated() {
    Pair p;
    p.tx.start(p.hello);
    uint8_t altered[50], out[50];
    for (unsigned i=0; i<50; ++i) {
        memcpy(altered, p.hello, 50); altered[i] ^= 1;
        TEST_ASSERT_EQUAL(S::Ignored, p.rx.receive(altered, 50, out));
    }
    TEST_ASSERT_EQUAL_UINT(0, p.rr.calls);
    TEST_ASSERT_EQUAL(S::Ignored, p.rx.receive(p.hello, 49, out));
    TEST_ASSERT_EQUAL(S::Ignored, p.rx.receive(p.hello, 51, out));
    p.rx.receive(p.hello, 50, p.reply);
    for (unsigned i=0; i<50; ++i) {
        memcpy(altered, p.reply, 50); altered[i] ^= 1;
        TEST_ASSERT_EQUAL(S::Ignored, p.tx.receive(altered, 50, out));
    }
    TEST_ASSERT_FALSE(p.tx.active());
    p.tx.receive(p.reply, 50, p.confirm);
    for (unsigned i=0; i<50; ++i) {
        memcpy(altered, p.confirm, 50); altered[i] ^= 1;
        TEST_ASSERT_EQUAL(S::Ignored, p.rx.receive(altered, 50, out));
    }
    TEST_ASSERT_FALSE(p.rx.active());
    p.rx.receive(p.confirm, 50, p.ready);
    for (unsigned i=0; i<50; ++i) {
        memcpy(altered, p.ready, 50); altered[i] ^= 1;
        TEST_ASSERT_EQUAL(S::Ignored, p.tx.receive(altered, 50, out));
    }
    TEST_ASSERT_FALSE(p.tx.active());
}
void test_wrong_key_and_reflection() {
    Pair p;
    uint8_t other[16] = {}, out[50];
    S stranger(false, other, Rng::fill, &p.rr);
    p.tx.start(p.hello);
    TEST_ASSERT_EQUAL(S::Ignored, stranger.receive(p.hello, 50, out));
    TEST_ASSERT_EQUAL(S::Ignored, p.tx.receive(p.hello, 50, out));
    p.rx.receive(p.hello, 50, p.reply);
    TEST_ASSERT_EQUAL(S::Ignored, p.rx.receive(p.reply, 50, out));
}
void test_loss_retry_and_duplicate_activation() {
    Pair p;
    uint8_t out[50];
    p.tx.start(p.hello);
    TEST_ASSERT_TRUE(p.tx.retry(out));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(p.hello, out, 50);
    p.rx.receive(out, 50, p.reply);
    TEST_ASSERT_EQUAL(S::Send, p.rx.receive(p.hello, 50, out));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(p.reply, out, 50);
    TEST_ASSERT_EQUAL_UINT(1, p.rr.calls);
    p.tx.receive(p.reply, 50, p.confirm);
    TEST_ASSERT_EQUAL(S::Send, p.tx.receive(p.reply, 50, out));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(p.confirm, out, 50);
    TEST_ASSERT_TRUE(p.tx.retry(out));
    p.rx.receive(out, 50, p.ready); // drop READY
    TEST_ASSERT_EQUAL(S::Send, p.rx.receive(p.confirm, 50, out));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(p.ready, out, 50);
    TEST_ASSERT_EQUAL(S::Activated, p.tx.receive(out, 50, p.hello));
    for (unsigned i=0; i<20; ++i) {
        TEST_ASSERT_EQUAL(S::Send, p.rx.receive(p.confirm, 50, out));
        TEST_ASSERT_EQUAL(S::Ignored, p.tx.receive(p.ready, 50, out));
    }
    TEST_ASSERT_FALSE(p.tx.retry(out));
    TEST_ASSERT_FALSE(p.rx.retry(out));
    checkKeys(p.tx, p.rx);
}
void test_both_restart_directions_change_keys() {
    Pair p; p.establish();
    uint8_t old[16], down[16], current[16], out[50];
    p.tx.getKeys(old, down);
    Rng rng(100);
    S newRx(false, master, Rng::fill, &rng);
    p.tx.start(p.hello);
    newRx.receive(p.hello, 50, p.reply);
    p.tx.receive(p.reply, 50, p.confirm);
    newRx.receive(p.confirm, 50, p.ready);
    p.tx.receive(p.ready, 50, out);
    checkKeys(p.tx, newRx);
    p.tx.getKeys(current, down);
    TEST_ASSERT_NOT_EQUAL(0, memcmp(old, current, 16));
    memcpy(old, current, 16);
    Rng txRng(140);
    S newTx(true, master, Rng::fill, &txRng);
    newTx.start(p.hello);
    newRx.receive(p.hello, 50, p.reply);
    newTx.receive(p.reply, 50, p.confirm);
    newRx.receive(p.confirm, 50, p.ready);
    newTx.receive(p.ready, 50, out);
    checkKeys(newTx, newRx);
    newTx.getKeys(current, down);
    TEST_ASSERT_NOT_EQUAL(0, memcmp(old, current, 16));
}
void test_old_transcript_cannot_activate_rebooted_peer() {
    Pair p; p.establish();
    Rng rxRng(110), txRng(150);
    S rx(false, master, Rng::fill, &rxRng), tx(true, master, Rng::fill, &txRng);
    uint8_t out[50];
    TEST_ASSERT_EQUAL(S::Send, rx.receive(p.hello, 50, out));
    TEST_ASSERT_EQUAL(S::Ignored, rx.receive(p.confirm, 50, out));
    TEST_ASSERT_FALSE(rx.active());
    tx.start(out);
    TEST_ASSERT_EQUAL(S::Ignored, tx.receive(p.reply, 50, out));
    TEST_ASSERT_EQUAL(S::Ignored, tx.receive(p.ready, 50, out));
    TEST_ASSERT_FALSE(tx.active());
}
void test_rekey_keeps_active_keys_until_confirmation() {
    Pair p; p.establish();
    uint8_t before[16], after[16], down[16], oldConfirm[50], out[50];
    memcpy(oldConfirm, p.confirm, 50);
    p.tx.getKeys(before, down);
    p.tx.start(p.hello);
    p.rx.receive(p.hello, 50, p.reply);
    p.tx.getKeys(after, down);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(before, after, 16);
    p.rx.getKeys(after, down);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(before, after, 16);
    // Delayed confirmation of the previous exchange cannot cancel the new one.
    TEST_ASSERT_EQUAL(S::Send, p.rx.receive(oldConfirm, 50, out));
    p.tx.receive(p.reply, 50, p.confirm);
    TEST_ASSERT_EQUAL(S::Send | S::Activated, p.rx.receive(p.confirm, 50, p.ready));
    TEST_ASSERT_EQUAL(S::Activated, p.tx.receive(p.ready, 50, out));
    checkKeys(p.tx, p.rx);
    p.tx.getKeys(after, down);
    TEST_ASSERT_NOT_EQUAL(0, memcmp(before, after, 16));
}
void test_entropy_failure_is_closed_and_preserves_active_session() {
    Pair p; uint8_t out[50];
    p.tr.fail = true;
    TEST_ASSERT_EQUAL(S::EntropyFailed, p.tx.start(out));
    TEST_ASSERT_FALSE(p.tx.active());
    p.tr.fail = false;
    p.establish();
    p.tr.fail = true;
    TEST_ASSERT_EQUAL(S::EntropyFailed, p.tx.start(out));
    checkKeys(p.tx, p.rx);
    p.tr.fail = false;
    p.tx.start(p.hello);
    p.rr.fail = true;
    TEST_ASSERT_EQUAL(S::EntropyFailed, p.rx.receive(p.hello, 50, out));
    checkKeys(p.tx, p.rx);
    p.rr.fail = false; p.rr.zeros = true;
    TEST_ASSERT_EQUAL(S::EntropyFailed, p.rx.receive(p.hello, 50, out));
}
void test_stuck_rng_rejected() {
    Pair p; uint8_t out[50];
    p.tr.stuck = true;
    TEST_ASSERT_EQUAL(S::Send, p.tx.start(out));
    TEST_ASSERT_EQUAL(S::EntropyFailed, p.tx.start(out));
}
void test_frame_reordering_duplicates_and_missing_chunk() {
    MurmurSessionFrames sender, receiver;
    uint8_t message[50], out[50], frames[10][6];
    for (unsigned i=0; i<50; ++i) message[i]=i;
    sender.queue(message);
    for (auto &frame : frames) TEST_ASSERT_TRUE(sender.next(frame));
    TEST_ASSERT_FALSE(sender.next(frames[0]));
    for (int i=9; i>0; --i) {
        TEST_ASSERT_FALSE(receiver.receive(frames[i], 6, out));
        TEST_ASSERT_FALSE(receiver.receive(frames[i], 6, out));
    }
    sender.queue(message); // same ID; missing fragment can arrive on a retry
    uint8_t frame[6]; sender.next(frame);
    TEST_ASSERT_EQUAL_UINT8_ARRAY(frames[0], frame, 6);
    TEST_ASSERT_TRUE(receiver.receive(frame, 6, out));
    TEST_ASSERT_EQUAL_UINT8_ARRAY(message, out, 50);
}
void test_malformed_and_conflicting_frames() {
    MurmurSessionFrames sender, receiver;
    uint8_t message[50] = {}, frame[6], other[6], out[50];
    sender.queue(message); sender.next(frame);
    TEST_ASSERT_FALSE(receiver.receive(frame, 5, out));
    TEST_ASSERT_FALSE(receiver.receive(frame, 7, out));
    memcpy(other, frame, 6); other[0] |= 15;
    TEST_ASSERT_FALSE(receiver.receive(other, 6, out));
    TEST_ASSERT_FALSE(receiver.receive(frame, 6, out));
    memcpy(other, frame, 6); other[1] ^= 1;
    TEST_ASSERT_FALSE(receiver.receive(other, 6, out));
    for (unsigned i=1; i<10; ++i) {
        sender.next(frame);
        TEST_ASSERT_FALSE(receiver.receive(frame, 6, out));
    }
}
void test_fragmented_handshake_under_loss_and_duplicates() {
    Pair p;
    MurmurSessionFrames tf, rf;
    uint8_t out[50], assembled[50], frame[6];
    unsigned txActivations=0, rxActivations=0;
    p.tx.start(out); tf.queue(out);
    for (unsigned slot=0; slot<2000 && !p.tx.active(); ++slot) {
        if (!tf.next(frame)) {
            if (p.tx.retry(out)) tf.queue(out);
        } else if (slot%4 != 0 && rf.receive(frame, 6, assembled)) {
            auto result=p.rx.receive(assembled, 50, out);
            rxActivations += !!(result&S::Activated);
            if (result&S::Send) rf.queue(out);
        }
        if (!rf.next(frame)) {
            if (p.rx.retry(out)) rf.queue(out);
        } else if (slot%5 != 0) {
            bool complete=tf.receive(frame, 6, assembled);
            tf.receive(frame, 6, out); // duplicate fragment
            if (complete) {
                auto result=p.tx.receive(assembled, 50, out);
                txActivations += !!(result&S::Activated);
                if (result&S::Send) tf.queue(out);
            }
        }
    }
    TEST_ASSERT_EQUAL_UINT(1, txActivations);
    TEST_ASSERT_EQUAL_UINT(1, rxActivations);
    checkKeys(p.tx, p.rx);
}
void test_frame_id_wrap_and_bounded_memory() {
    MurmurSessionFrames sender, receiver;
    uint8_t message[50] = {}, out[50], frame[6];
    for (unsigned generation=0; generation<40; ++generation) {
        message[0]=generation; sender.queue(message);
        for (unsigned index=0; index<10; ++index) {
            TEST_ASSERT_TRUE(sender.next(frame));
            TEST_ASSERT_EQUAL(index==9, receiver.receive(frame, 6, out));
        }
        TEST_ASSERT_EQUAL_UINT8_ARRAY(message, out, 50);
    }
    TEST_ASSERT_LESS_THAN_UINT(256, sizeof(MurmurSession));
    TEST_ASSERT_LESS_THAN_UINT(128, sizeof(MurmurSessionFrames));
}
int main() {
    UNITY_BEGIN();
    RUN_TEST(test_rfc4231_hmac_sha256);
    RUN_TEST(test_rfc5869_hkdf);
    RUN_TEST(test_key_agreement_and_confirmation);
    RUN_TEST(test_independent_python_wire_and_key_vectors);
    RUN_TEST(test_all_message_bytes_authenticated);
    RUN_TEST(test_wrong_key_and_reflection);
    RUN_TEST(test_loss_retry_and_duplicate_activation);
    RUN_TEST(test_both_restart_directions_change_keys);
    RUN_TEST(test_old_transcript_cannot_activate_rebooted_peer);
    RUN_TEST(test_rekey_keeps_active_keys_until_confirmation);
    RUN_TEST(test_entropy_failure_is_closed_and_preserves_active_session);
    RUN_TEST(test_stuck_rng_rejected);
    RUN_TEST(test_frame_reordering_duplicates_and_missing_chunk);
    RUN_TEST(test_malformed_and_conflicting_frames);
    RUN_TEST(test_fragmented_handshake_under_loss_and_duplicates);
    RUN_TEST(test_frame_id_wrap_and_bounded_memory);
    return UNITY_END();
}
