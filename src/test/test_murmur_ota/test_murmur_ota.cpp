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
extern "C" {
#include "murmur.h"
}
extern void MurmurTestSetSendEpoch(uint32_t epoch);

CRSFEndpoint *crsfEndpoint = nullptr;
uint32_t ChannelData[CRSF_NUM_CHANNELS];
extern void MurmurInstallSessionKeys(const uint8_t up[16], const uint8_t down[16]);
static void initSession(bool tx)
{
    const uint8_t up[16] = {1,2,3,4}, down[16] = {5,6,7,8};
    MurmurInit(tx);
    MurmurInstallSessionKeys(up, down);
}
extern void MurmurTrackNonce();
extern void MurmurResetCounter();

static OTA_Packet_s packets[6];
static uint8_t payloadSize;

static void prepare(uint8_t packetSize, bool senderTx = true, uint32_t start = 10)
{
    OtaUpdateSerializers(smWideOr8ch, packetSize);
    payloadSize = (packetSize == OTA4_PACKET_SIZE ? OTA4_CRC_CALC_LEN : OTA8_CRC_CALC_LEN) - 1;
    initSession(senderTx);
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
    initSession(!senderTx);
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
        TEST_ASSERT_FALSE(receive(0, 10));
        TEST_ASSERT_FALSE(receive(1, 11));
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
        TEST_ASSERT_FALSE(receive(0, 10));
        TEST_ASSERT_FALSE(receive(1, 11));
        TEST_ASSERT_TRUE(receive(2, 12));
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
        initSession(true);
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
        initSession(false);
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
        initSession(true);
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
        initSession(true);
        for (unsigned i = 0; i < count; ++i) {
            OtaNonce = i;
            frames[i].std.type = PACKET_TYPE_DATA;
            OtaGeneratePacketCrc(&frames[i]);
        }
        initSession(false);
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


static bool fixtureRandom(void *context, uint8_t out[16])
{
    uint8_t &value = *static_cast<uint8_t *>(context);
    memset(out, ++value, 16);
    return true;
}

void test_unconfirmed_firmware_never_sends_or_accepts_data()
{
    for (uint8_t size : {OTA4_PACKET_SIZE, OTA8_PACKET_SIZE}) {
        prepare(size);
        MurmurInit(false); // reboot, no session keys installed
        TEST_ASSERT_FALSE(receive(2, 12));
        OTA_Packet_s packet{};
        packet.std.type = PACKET_TYPE_RCDATA;
        memset(reinterpret_cast<uint8_t *>(&packet) + 1, 0xAB, 6);
        OtaGeneratePacketCrc(&packet);
        TEST_ASSERT_EQUAL(PACKET_TYPE_SESSION, packet.std.type);
        TEST_ASSERT_EQUAL_UINT8(15, reinterpret_cast<uint8_t *>(&packet)[1]);
        TEST_ASSERT_EQUAL_UINT8(0, reinterpret_cast<uint8_t *>(&packet)[2]);
    }
}

void test_rate_and_sync_cannot_clear_replay_history()
{
    for (uint8_t size : {OTA4_PACKET_SIZE, OTA8_PACKET_SIZE}) {
        prepare(size);
        receive(0,10); receive(1,11); TEST_ASSERT_TRUE(receive(2,12));
        MurmurResetCounter();
        OtaNonce=10; MurmurSyncNonce();
        for (unsigned i=0; i<10; ++i) {
            TEST_ASSERT_FALSE(receive(0,10));
            TEST_ASSERT_FALSE(receive(1,11));
            TEST_ASSERT_FALSE(receive(2,12));
        }
        receive(3,13); receive(4,14); TEST_ASSERT_TRUE(receive(5,15));
    }
}

void test_repeated_slot_and_backwards_sync_use_distinct_nonces()
{
    for (uint8_t size : {OTA4_PACKET_SIZE, OTA8_PACKET_SIZE}) {
        OtaUpdateSerializers(smWideOr8ch,size);
        OtaNonce=100; initSession(false);
        OTA_Packet_s a{},b{},c{};
        a.std.type=b.std.type=c.std.type=PACKET_TYPE_DATA;
        OtaGeneratePacketCrc(&a); OtaGeneratePacketCrc(&b);
        OtaNonce=99; MurmurSyncNonce(); OtaGeneratePacketCrc(&c);
        TEST_ASSERT_NOT_EQUAL(0,memcmp(&a,&b,size));
        TEST_ASSERT_NOT_EQUAL(0,memcmp(&a,&c,size));
        TEST_ASSERT_NOT_EQUAL(0,memcmp(&b,&c,size));
    }
}

void test_handshake_through_production_ota_hooks()
{
    for (uint8_t size : {OTA4_PACKET_SIZE, OTA8_PACKET_SIZE}) {
        for (bool localTx : {false,true}) {
            OtaUpdateSerializers(smWideOr8ch,size);
            uint8_t localRandom=10, peerRandom=60, master[16], message[50];
            MurmurInit(localTx,fixtureRandom,&localRandom);
            MurmurGetEncKey(master);
            MurmurSession peer(!localTx,master,fixtureRandom,&peerRandom);
            MurmurSessionFrames frames;
            if (!localTx) { peer.start(message); frames.queue(message); }
            for (unsigned step=0; step<1000; ++step) {
                OtaNonce=step;
                MurmurTrackNonce();
                MurmurPoll(step*2);
                OTA_Packet_s packet{};
                if (MurmurPrepareSessionPacket(&packet)) {
                    OtaGeneratePacketCrc(&packet);
                    TEST_ASSERT_EQUAL(PACKET_TYPE_SESSION,packet.std.type);
                    if (step%7 && frames.receive(reinterpret_cast<uint8_t *>(&packet)+1,6,message)) {
                        uint8_t reply[50];
                        if (peer.receive(message,50,reply) & MurmurSession::Send) frames.queue(reply);
                    }
                }
                uint8_t frame[6];
                if (frames.next(frame)) {
                    packet={}; packet.std.type=PACKET_TYPE_SESSION;
                    memcpy(reinterpret_cast<uint8_t *>(&packet)+1,frame,6);
                    OtaGeneratePacketCrc(&packet);
                    if (step%13) TEST_ASSERT_TRUE(OtaValidatePacketCrc(&packet));
                } else if (peer.retry(message)) frames.queue(message);
                if (MurmurSessionReady() && peer.active()) break;
                TEST_ASSERT_LESS_THAN(999,step);
            }
            TEST_ASSERT_TRUE(MurmurSessionReady());
            TEST_ASSERT_TRUE(peer.active());
            uint8_t up[16], down[16];
            peer.getKeys(up,down);
            OTA_Packet_s data{};
            data.std.type=PACKET_TYPE_DATA;
            const unsigned payload=(size==OTA4_PACKET_SIZE ? OTA4_CRC_CALC_LEN : OTA8_CRC_CALC_LEN)-1;
            memset(reinterpret_cast<uint8_t *>(&data)+1,0x44,payload);
            OtaGeneratePacketCrc(&data);
            const uint16_t mac = size==OTA4_PACKET_SIZE ? (data.std.crcHigh<<8)|data.std.crcLow : data.full.crc;
            bool decrypted=false;
            for (uint32_t epoch=0; epoch<4 && !decrypted; ++epoch) {
                OTA_Packet_s copy=data;
                decrypted=murmur_decrypt_packet(localTx ? up : down,(epoch<<8)|OtaNonce,
                    PACKET_TYPE_DATA,localTx ? 0 : 1,reinterpret_cast<uint8_t *>(&copy)+1,
                    payload,mac,size==OTA4_PACKET_SIZE ? 14 : 16);
                if (decrypted) {
                    for (unsigned i=0;i<payload;++i)
                        TEST_ASSERT_EQUAL_UINT8(0x44,reinterpret_cast<uint8_t *>(&copy)[i+1]);
                }
            }
            TEST_ASSERT_TRUE_MESSAGE(decrypted,"OTA must use the negotiated directional key");
        }
    }
}


void test_counter_exhaustion_blocks_application_packets()
{
    for (bool tx : {false,true}) {
        for (uint8_t size : {OTA4_PACKET_SIZE,OTA8_PACKET_SIZE}) {
            OtaUpdateSerializers(smWideOr8ch,size);
            OtaNonce=0; initSession(tx);
            MurmurTestSetSendEpoch(0xFFFF00U);
            OTA_Packet_s packet{};
            packet.std.type=PACKET_TYPE_DATA;
            OtaGeneratePacketCrc(&packet);
            TEST_ASSERT_EQUAL(PACKET_TYPE_SESSION,packet.std.type);
            for (unsigned i=0;i<3;++i) {
                packet={}; packet.std.type=PACKET_TYPE_RCDATA;
                OtaGeneratePacketCrc(&packet);
                TEST_ASSERT_EQUAL(PACKET_TYPE_SESSION,packet.std.type);
            }
        }
    }
}

void test_sparse_downlink_acquires_across_epochs()
{
    for (uint8_t size : {OTA4_PACKET_SIZE,OTA8_PACKET_SIZE}) {
        OtaUpdateSerializers(smWideOr8ch,size);
        OtaNonce=0; initSession(false);
        for (unsigned slot=0;slot<=256;++slot) {
            OtaNonce=slot; MurmurTrackNonce();
            if (slot%128==0) {
                packets[slot/128]={}; packets[slot/128].std.type=PACKET_TYPE_DATA;
                OtaGeneratePacketCrc(&packets[slot/128]);
            }
        }
        OtaNonce=0; initSession(true);
        for (unsigned slot=0;slot<=256;++slot) {
            OtaNonce=slot; MurmurTrackNonce();
            if (slot%128==0) {
                OTA_Packet_s packet=packets[slot/128];
                TEST_ASSERT_EQUAL(slot==256,OtaValidatePacketCrc(&packet));
            }
        }
    }
}


void test_cleartext_sync_is_discovery_only()
{
    for (uint8_t size : {OTA4_PACKET_SIZE,OTA8_PACKET_SIZE}) {
        OtaUpdateSerializers(smWideOr8ch,size);
        MurmurInit(true);
        OTA_Packet_s packet{};
        packet.std.type=PACKET_TYPE_SYNC;
        OtaGeneratePacketCrc(&packet);
        OTA_Packet_s copy=packet;
        TEST_ASSERT_FALSE(OtaValidatePacketCrc(&copy)); // no downlink SYNC
        MurmurInit(false);
        TEST_ASSERT_TRUE(OtaValidatePacketCrc(&packet));
        TEST_ASSERT_FALSE(MurmurSessionReady());
        TEST_ASSERT_FALSE(MurmurHasAuthenticatedData());
    }
}

#if defined(MURMUR_LINK_DIAGNOSTICS)
void test_diagnostics_preserve_authentication_and_replay_results()
{
    prepare(OTA4_PACKET_SIZE);
    const auto before = MurmurGetDiagnostics();
    TEST_ASSERT_TRUE(before.keysReady);
    TEST_ASSERT_FALSE(before.epochLocked);
    TEST_ASSERT_FALSE(receive(0, 10));
    TEST_ASSERT_FALSE(receive(1, 11));
    TEST_ASSERT_TRUE(receive(2, 12));
    TEST_ASSERT_FALSE(receive(2, 12));
    const auto after = MurmurGetDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(before.accepted + 1, after.accepted);
    TEST_ASSERT_EQUAL_UINT32(before.rejected + 3, after.rejected);
    TEST_ASSERT_TRUE(after.epochLocked);
    MurmurResetCounter();
    const auto reset = MurmurGetDiagnostics();
    TEST_ASSERT_EQUAL_UINT32(after.resets + 1, reset.resets);
    TEST_ASSERT_TRUE(reset.keysReady);
    TEST_ASSERT_FALSE(reset.epochLocked);
}
#endif

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
    RUN_TEST(test_unconfirmed_firmware_never_sends_or_accepts_data);
    RUN_TEST(test_rate_and_sync_cannot_clear_replay_history);
    RUN_TEST(test_repeated_slot_and_backwards_sync_use_distinct_nonces);
    RUN_TEST(test_handshake_through_production_ota_hooks);
    RUN_TEST(test_counter_exhaustion_blocks_application_packets);
    RUN_TEST(test_sparse_downlink_acquires_across_epochs);
    RUN_TEST(test_cleartext_sync_is_discovery_only);
#if defined(MURMUR_LINK_DIAGNOSTICS)
    RUN_TEST(test_diagnostics_preserve_authentication_and_replay_results);
#endif
    return UNITY_END();
}
