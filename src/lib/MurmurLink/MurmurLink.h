#pragma once
#if defined(MURMUR_ENCRYPT)
#include "targets.h"
#include "MurmurSession.h"

// Main-loop handshake with bounded ISR mailboxes. Call begin/poll only from the
// loop task. The radio ISR may call receive/takeFrame/authenticated/ready.
class MurmurLink {
public:
    using Install = void (*)(const uint8_t up[16], const uint8_t down[16]);
    using Invalidate = void (*)();
    MurmurLink(bool tx, const uint8_t key[16], MurmurSession::Random random,
               void *context, Install install, Invalidate invalidate);
    void poll(uint32_t now);
    void ICACHE_RAM_ATTR receive(const uint8_t frame[6]);
    bool ICACHE_RAM_ATTR takeFrame(uint8_t frame[6]);
    void ICACHE_RAM_ATTR authenticated();
    bool ICACHE_RAM_ATTR ready() const;
    bool ICACHE_RAM_ATTR hasAuthenticatedData() const;
    void ICACHE_RAM_ATTR requestRestart();
private:
    MurmurSession session_;
    MurmurSessionFrames assembler_;
    Install install_;
    Invalidate invalidate_;
    bool tx_, started_ = false;
    bool haveData_ = false, healthy_ = false, ready_ = false, goodData_ = false, restart_ = false;
    bool output_ = false;
    uint8_t outgoing_[50] = {}, incoming_[8][6] = {};
    uint8_t id_ = 0, cursor_ = 0, head_ = 0, count_ = 0, sparse_ = 0;
    uint32_t lastGood_ = 0, lastStart_ = 0;
    void publish(const uint8_t message[50]);
};

// Seed once at the very beginning of setup, before ADC, WiFi and devices init.
// Challenge generation thereafter uses a boot-seeded HMAC counter PRF.
void MurmurEntropyInit();
bool MurmurRandom(void *, uint8_t out[16]);
#endif
