// Exercise the production OTA hooks, not a second implementation of the protocol.
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <chrono>
#include <cstdio>
#include <vector>
#include "common.h"
#include <unity.h>
#include "OTA.h"
#include "CRSFEndpoint.h"

CRSFEndpoint *crsfEndpoint = nullptr;
uint32_t ChannelData[CRSF_NUM_CHANNELS];
extern void MurmurInit(bool is_tx);
extern void MurmurTrackNonce();
extern void MurmurResetCounter();

static OTA_Packet_s packets[6];
static uint8_t payloadSize;

static void prepare(uint8_t packetSize, bool senderTx = true, uint32_t start = 10)
{
    OtaUpdateSerializers(smWideOr8ch, packetSize);
    payloadSize = (packetSize == OTA4_PACKET_SIZE ? OTA4_CRC_CALC_LEN : OTA8_CRC_CALC_LEN) - 1;
    MurmurInit(senderTx);
    for (uint32_t counter = 0; counter < start; ++counter) {
        OtaNonce = counter;
        MurmurTrackNonce();
    }
    for (unsigned i = 0; i < 6; ++i) {
        OtaNonce = start + i;
        std::memset(&packets[i], 0, sizeof(packets[i]));
        packets[i].std.type = PACKET_TYPE_DATA;
        std::memset(reinterpret_cast<uint8_t *>(&packets[i]) + 1, 0x30 + i, payloadSize);
        OtaGeneratePacketCrc(&packets[i]);
    }
    MurmurInit(!senderTx);
}

static bool receive(unsigned i, uint8_t nonce)
{
    OtaNonce = nonce;
    OTA_Packet_s copy = packets[i];
    bool accepted = OtaValidatePacketCrc(&copy);
    if (accepted) {
        const auto *payload = reinterpret_cast<const uint8_t *>(&copy) + 1;
        for (unsigned j = 0; j < payloadSize; ++j)
            TEST_ASSERT_EQUAL_UINT8(0x30 + i, payload[j]);
    }
    return accepted;
}

void test_uplink_both_sizes()
{
    for (uint8_t size : {OTA4_PACKET_SIZE, OTA8_PACKET_SIZE}) {
        prepare(size);
        TEST_ASSERT_FALSE(receive(0, 10));
        TEST_ASSERT_FALSE(receive(1, 11));
        TEST_ASSERT_TRUE(receive(2, 12));
        TEST_ASSERT_TRUE(receive(4, 14)); // packet loss
        TEST_ASSERT_FALSE(receive(4, 14)); // replay
        TEST_ASSERT_TRUE(receive(5, 15));
    }
}

void test_repeated_packet_cannot_acquire()
{
    for (uint8_t size : {OTA4_PACKET_SIZE, OTA8_PACKET_SIZE}) {
        prepare(size);
        for (unsigned i = 0; i < 8; ++i)
            TEST_ASSERT_FALSE(receive(0, 10));
    }
}

void test_acquisition_packets_remain_replay_protected()
{
    for (uint8_t size : {OTA4_PACKET_SIZE, OTA8_PACKET_SIZE}) {
        prepare(size);
        receive(0, 10); receive(1, 11);
        TEST_ASSERT_TRUE(receive(2, 12));
        TEST_ASSERT_FALSE(receive(0, 10));
        TEST_ASSERT_FALSE(receive(1, 11));
    }
}

void test_downlink_both_sizes()
{
    for (uint8_t size : {OTA4_PACKET_SIZE, OTA8_PACKET_SIZE}) {
        prepare(size, false);
        TEST_ASSERT_TRUE(receive(0, 10));
        TEST_ASSERT_TRUE(receive(2, 12));
        TEST_ASSERT_FALSE(receive(2, 12));
    }
}

void test_tampering_does_not_consume_counter()
{
    for (uint8_t size : {OTA4_PACKET_SIZE, OTA8_PACKET_SIZE}) {
        prepare(size, false);
        OTA_Packet_s damaged = packets[0];
        reinterpret_cast<uint8_t *>(&damaged)[2] ^= 0x80;
        OtaNonce = 10;
        TEST_ASSERT_FALSE(OtaValidatePacketCrc(&damaged));
        TEST_ASSERT_TRUE(receive(0, 10));
    }
}

void test_nonce_wrap()
{
    for (uint8_t size : {OTA4_PACKET_SIZE, OTA8_PACKET_SIZE}) {
        prepare(size, true, 252);
        receive(0, 252); receive(1, 253);
        TEST_ASSERT_TRUE(receive(2, 254));
        TEST_ASSERT_TRUE(receive(3, 255));
        TEST_ASSERT_TRUE(receive(4, 0));
        TEST_ASSERT_TRUE(receive(5, 1));
    }
}

void test_relock_does_not_accept_previous_acquisition()
{
    for (uint8_t size : {OTA4_PACKET_SIZE, OTA8_PACKET_SIZE}) {
        prepare(size);
        receive(0, 10); receive(1, 11);
        TEST_ASSERT_TRUE(receive(2, 12));
        for (unsigned i = 0; i < 16; ++i) {
            OTA_Packet_s damaged = packets[3];
            reinterpret_cast<uint8_t *>(&damaged)[2] ^= 0x80;
            OtaNonce = 13;
            TEST_ASSERT_FALSE(OtaValidatePacketCrc(&damaged));
        }
        TEST_ASSERT_FALSE(receive(0, 10));
        TEST_ASSERT_FALSE(receive(1, 11));
        TEST_ASSERT_FALSE(receive(2, 12));
        receive(3, 13); receive(4, 14);
        TEST_ASSERT_TRUE(receive(5, 15));
    }
}

void test_late_join_beyond_epoch_255()
{
    for (uint8_t size : {OTA4_PACKET_SIZE, OTA8_PACKET_SIZE}) {
        prepare(size, true, 70000);
        bool acquired = false;
        for (unsigned attempt = 0; attempt < 32 && !acquired; ++attempt) {
            for (unsigned i = 0; i < 3 && !acquired; ++i)
                acquired = receive(i, static_cast<uint8_t>(70000 + i));
        }
        TEST_ASSERT_TRUE(acquired);
    }
}

void test_rate_reset_reserves_fresh_counters()
{
    for (uint8_t size : {OTA4_PACKET_SIZE, OTA8_PACKET_SIZE}) {
        OtaUpdateSerializers(smWideOr8ch, size);
        MurmurInit(true);
        OTA_Packet_s first{};
        first.std.type = PACKET_TYPE_DATA;
        OtaNonce = 0;
        OtaGeneratePacketCrc(&first);
        for (unsigned reset = 0; reset < 3; ++reset) {
            OtaNonce = 0;
            MurmurResetCounter();
            OTA_Packet_s next{};
            next.std.type = PACKET_TYPE_DATA;
            OtaGeneratePacketCrc(&next);
            TEST_ASSERT_NOT_EQUAL(0, std::memcmp(&first, &next, size));
            first = next;
        }
        // RX can acquire packets after the transition, using real OTA hooks.
        for (unsigned i = 0; i < 3; ++i) {
            OtaNonce = i + 1;
            packets[i] = {};
            packets[i].std.type = PACKET_TYPE_DATA;
            OtaGeneratePacketCrc(&packets[i]);
        }
        MurmurInit(false);
        for (unsigned i = 0; i < 3; ++i) {
            OtaNonce = i + 1;
            TEST_ASSERT_EQUAL(i == 2, OtaValidatePacketCrc(&packets[i]));
        }
    }
}

void test_silent_ticks_preserve_nonce_epoch()
{
    for (uint8_t size : {OTA4_PACKET_SIZE, OTA8_PACKET_SIZE}) {
        OtaUpdateSerializers(smWideOr8ch, size);
        MurmurInit(true);
        OTA_Packet_s first{};
        first.std.type = PACKET_TYPE_DATA;
        OtaNonce = 0;
        OtaGeneratePacketCrc(&first);
        // Mirror timer ticks while transmitting no packets (e.g. flash commit).
        for (unsigned i = 1; i <= 768; ++i) {
            OtaNonce = i;
            MurmurTrackNonce();
        }
        OTA_Packet_s afterGap{};
        afterGap.std.type = PACKET_TYPE_DATA;
        OtaGeneratePacketCrc(&afterGap);
        TEST_ASSERT_NOT_EQUAL(0, std::memcmp(&first, &afterGap, size));
    }
}

void test_production_packet_timing()
{
    // Host-only baseline, not an ESP32 latency claim or a flaky speed threshold.
    // Pre-encrypt outside the timed region; measure the actual OTA verifier.
    for (uint8_t size : {OTA4_PACKET_SIZE, OTA8_PACKET_SIZE}) {
        const unsigned count = 4096;
        std::vector<OTA_Packet_s> frames(count);
        OtaUpdateSerializers(smWideOr8ch, size);
        MurmurInit(true);
        for (unsigned i = 0; i < count; ++i) {
            OtaNonce = i;
            frames[i].std.type = PACKET_TYPE_DATA;
            OtaGeneratePacketCrc(&frames[i]);
        }
        MurmurInit(false);
        for (unsigned i = 0; i < 3; ++i) {
            OtaNonce = i;
            bool accepted = OtaValidatePacketCrc(&frames[i]);
            TEST_ASSERT_EQUAL(i == 2, accepted);
        }
        unsigned accepted = 0;
        auto start = std::chrono::steady_clock::now();
        for (unsigned i = 3; i < count; ++i) {
            OtaNonce = i;
            accepted += OtaValidatePacketCrc(&frames[i]);
        }
        auto elapsed = std::chrono::duration<double, std::micro>(
            std::chrono::steady_clock::now() - start).count();
        TEST_ASSERT_EQUAL_UINT(count - 3, accepted);
        std::printf("Host OTA%u locked validation: %.3f us/packet (%u packets)\n",
                    size == OTA4_PACKET_SIZE ? 4 : 8, elapsed / (count - 3), count - 3);
    }
}

int main()
{
    UNITY_BEGIN();
    RUN_TEST(test_uplink_both_sizes);
    RUN_TEST(test_repeated_packet_cannot_acquire);
    RUN_TEST(test_acquisition_packets_remain_replay_protected);
    RUN_TEST(test_downlink_both_sizes);
    RUN_TEST(test_tampering_does_not_consume_counter);
    RUN_TEST(test_nonce_wrap);
    RUN_TEST(test_relock_does_not_accept_previous_acquisition);
    RUN_TEST(test_late_join_beyond_epoch_255);
    RUN_TEST(test_rate_reset_reserves_fresh_counters);
    RUN_TEST(test_silent_ticks_preserve_nonce_epoch);
    RUN_TEST(test_production_packet_timing);
    return UNITY_END();
}
