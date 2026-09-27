#include "MurmurLink.h"
#include <unity.h>
#include <cstring>
#include <memory>

static uint8_t master[16] = {1,2,3,4};
static uint8_t txUp[16], txDown[16], rxUp[16], rxDown[16];
static unsigned txInstalls, rxInstalls, txInvalidations, rxInvalidations;
static void txInstall(const uint8_t *u, const uint8_t *d) { ++txInstalls; memcpy(txUp,u,16); memcpy(txDown,d,16); }
static void rxInstall(const uint8_t *u, const uint8_t *d) { ++rxInstalls; memcpy(rxUp,u,16); memcpy(rxDown,d,16); }
static void txInvalidate() { ++txInvalidations; }
static void rxInvalidate() { ++rxInvalidations; }
struct Random { uint32_t count; bool fail = false; explicit Random(uint32_t n) : count(n) {} };
static bool randomBytes(void *ctx, uint8_t out[16]) {
    auto &r = *static_cast<Random *>(ctx);
    if (r.fail) return false;
    ++r.count;
    memset(out, 0x55, 16);
    for (unsigned i=0; i<4; ++i) out[i] = r.count >> (i*8);
    return true;
}

struct Pair {
    Random a{100}, b{200};
    std::unique_ptr<MurmurLink> tx, rx;
    uint32_t time = 0;
    Pair() {
        txInstalls = rxInstalls = txInvalidations = rxInvalidations = 0;
        bootTx(); bootRx();
    }
    void bootTx() { tx.reset(new MurmurLink(true,master,randomBytes,&a,txInstall,txInvalidate)); }
    void bootRx() { rx.reset(new MurmurLink(false,master,randomBytes,&b,rxInstall,rxInvalidate)); }
    void step(bool loss = false, bool data = true) {
        tx->poll(time); rx->poll(time);
        uint8_t f[6];
        if (tx->takeFrame(f) && (!loss || time % 70 != 0)) {
            rx->receive(f);
            if (loss && time % 110 == 0) rx->receive(f);
        }
        if (rx->takeFrame(f) && (!loss || time % 90 != 0)) {
            tx->receive(f);
            if (loss && time % 130 == 0) tx->receive(f);
        }
        if (data && tx->ready() && rx->ready() && !memcmp(txUp,rxUp,16)) {
            tx->authenticated(); rx->authenticated();
        }
        time += 10;
    }
    void connect(bool loss = false) {
        for (unsigned i=0; i<2500; ++i) {
            step(loss);
            if (tx->ready() && rx->ready() && !memcmp(txUp,rxUp,16)) return;
        }
        TEST_FAIL_MESSAGE("Session did not converge");
    }
};

void test_link_loss_duplicates_and_no_reinstallation() {
    Pair p; p.connect(true);
    TEST_ASSERT_EQUAL_MEMORY(txUp,rxUp,16);
    TEST_ASSERT_EQUAL_MEMORY(txDown,rxDown,16);
    TEST_ASSERT_NOT_EQUAL(0,memcmp(txUp,txDown,16));
    for (unsigned i=0; i<1000; ++i) p.step(true);
    TEST_ASSERT_EQUAL(1,txInstalls); TEST_ASSERT_EQUAL(1,rxInstalls);
}
void test_independent_reboots_rekey() {
    Pair p; p.connect();
    uint8_t old[16]; memcpy(old,txUp,16);
    p.bootRx(); p.connect(true);
    TEST_ASSERT_NOT_EQUAL(0,memcmp(old,txUp,16));
    memcpy(old,txUp,16);
    p.bootTx(); p.connect(true);
    TEST_ASSERT_NOT_EQUAL(0,memcmp(old,txUp,16));
}
void test_entropy_failure_blocks_data_and_recovers() {
    Pair p; p.a.fail = true;
    for (unsigned i=0;i<100;++i) p.step();
    TEST_ASSERT_FALSE(p.tx->ready()); TEST_ASSERT_FALSE(p.rx->ready());
    TEST_ASSERT_EQUAL(0,txInstalls); TEST_ASSERT_EQUAL(0,rxInstalls);
    p.a.fail=false; p.connect();
    TEST_ASSERT_TRUE(p.tx->ready());
}
void test_no_authenticated_downlink_forces_rekey() {
    Pair p; p.connect();
    unsigned old = txInvalidations;
    for (unsigned i=0;i<600;++i) p.step(false,false);
    TEST_ASSERT_GREATER_THAN(old,txInvalidations);
    p.connect();
}
void test_overflow_and_malformed_frames_are_bounded() {
    Pair p;
    uint8_t bad[6] = {15,1,2,3,4,5};
    for (unsigned i=0;i<1000;++i) p.rx->receive(bad);
    bad[0]=0;
    for (unsigned i=0;i<1000;++i) p.rx->receive(bad);
    for (unsigned i=0;i<20;++i) p.step();
    p.connect(true);
    TEST_ASSERT_EQUAL(1,rxInstalls);
    TEST_ASSERT_LESS_THAN(512,sizeof(MurmurLink));
}
void test_counter_exhaustion_requests_fresh_session() {
    Pair p; p.connect();
    uint8_t old[16]; memcpy(old,txUp,16);
    p.tx->requestRestart();
    TEST_ASSERT_FALSE(p.tx->ready());
    p.connect();
    TEST_ASSERT_NOT_EQUAL(0,memcmp(old,txUp,16));
}
void test_millis_wrap_does_not_break_establishment_or_liveness() {
    Pair p; p.time = UINT32_MAX - 300;
    p.connect(true);
    for (unsigned i=0;i<1000;++i) p.step(true);
    TEST_ASSERT_EQUAL(1,txInstalls); TEST_ASSERT_EQUAL(1,rxInstalls);
}

void test_fragments_do_not_count_as_authenticated_data() {
    Pair p;
    for (unsigned i=0;i<500 && !(p.tx->ready() && p.rx->ready());++i) p.step(false,false);
    TEST_ASSERT_TRUE(p.tx->ready()); TEST_ASSERT_TRUE(p.rx->ready());
    TEST_ASSERT_FALSE(p.tx->hasAuthenticatedData());
    TEST_ASSERT_FALSE(p.rx->hasAuthenticatedData());
    p.tx->authenticated(); p.rx->authenticated();
    TEST_ASSERT_TRUE(p.tx->hasAuthenticatedData());
    TEST_ASSERT_TRUE(p.rx->hasAuthenticatedData());
    p.tx->requestRestart();
    TEST_ASSERT_FALSE(p.tx->hasAuthenticatedData());
}

void test_periodic_frame_loss_does_not_starve_same_fragment() {
    Pair p;
    for (unsigned i=0;i<10000;++i) {
        p.tx->poll(i); p.rx->poll(i);
        uint8_t frame[6];
        // Drop exactly the same physical slot on every ten-slot pass.
        if (p.tx->takeFrame(frame) && i%10 != 0) p.rx->receive(frame);
        if (p.rx->takeFrame(frame) && i%10 != 0) p.tx->receive(frame);
        if (p.tx->ready() && p.rx->ready()) break;
        TEST_ASSERT_LESS_THAN(9999,i);
    }
    TEST_ASSERT_TRUE(p.tx->ready()); TEST_ASSERT_TRUE(p.rx->ready());
}

#if defined(MURMUR_SESSION_STANDALONE)
extern "C" void setUp() {}
extern "C" void tearDown() {}
#endif
int main() {
    UNITY_BEGIN();
    RUN_TEST(test_link_loss_duplicates_and_no_reinstallation);
    RUN_TEST(test_independent_reboots_rekey);
    RUN_TEST(test_entropy_failure_blocks_data_and_recovers);
    RUN_TEST(test_no_authenticated_downlink_forces_rekey);
    RUN_TEST(test_overflow_and_malformed_frames_are_bounded);
    RUN_TEST(test_counter_exhaustion_requests_fresh_session);
    RUN_TEST(test_millis_wrap_does_not_break_establishment_or_liveness);
    RUN_TEST(test_fragments_do_not_count_as_authenticated_data);
    RUN_TEST(test_periodic_frame_loss_does_not_starve_same_fragment);
    return UNITY_END();
}
