#include "MurmurLink.h"
#if defined(MURMUR_ENCRYPT)
#include "MurmurLock.h"
#include <string.h>
#include "vendor/Crypto.h"
#if defined(PLATFORM_ESP32)
portMUX_TYPE murmurMux = portMUX_INITIALIZER_UNLOCKED;
#endif

MurmurLink::MurmurLink(bool tx, const uint8_t key[16], MurmurSession::Random random,
                     void *context, Install install, Invalidate invalidate)
    : session_(tx, key, random, context), install_(install), invalidate_(invalidate), tx_(tx) {}

void MurmurLink::publish(const uint8_t message[50])
{
    MurmurLock lock;
    if (!output_ || memcmp(message, outgoing_, 50)) {
        memcpy(outgoing_, message, 50);
        id_ = (id_ + 1) & 15;
        cursor_ = 0;
    }
    output_ = true;
}

void ICACHE_RAM_ATTR MurmurLink::receive(const uint8_t frame[6])
{
    if ((frame[0] & 15) >= 10) return;
    MurmurLock lock;
    if (count_ == 8) return; // Drop whole frames on overflow; sender cycles them.
    memcpy(incoming_[(head_ + count_) % 8], frame, 6);
    ++count_;
}

bool ICACHE_RAM_ATTR MurmurLink::takeFrame(uint8_t frame[6])
{
    MurmurLock lock;
    // While carrying valid traffic, a replayed HELLO must not monopolize TLM.
    if (!output_ || (healthy_ && outgoing_[1] == 2 && (++sparse_ & 15))) return false;
    // Rotate the first fragment on each pass. A periodic RF loss or slow main
    // loop must not discard the same fragment forever on every retransmission.
    const uint8_t index = (cursor_ % 10 + cursor_ / 10) % 10;
    frame[0] = (id_ << 4) | index;
    memcpy(frame + 1, outgoing_ + index * 5, 5);
    cursor_ = (cursor_ + 1) % 100;
    return true;
}

void ICACHE_RAM_ATTR MurmurLink::authenticated()
{
    MurmurLock lock;
    goodData_ = true;
    haveData_ = true;
    // Valid uplink proves TX received READY. Stop repeating READY only then.
    if (!tx_ && output_ && outgoing_[1] == 4) output_ = false;
}

bool ICACHE_RAM_ATTR MurmurLink::ready() const
{
    MurmurLock lock;
    return ready_;
}

bool ICACHE_RAM_ATTR MurmurLink::hasAuthenticatedData() const
{
    MurmurLock lock;
    return ready_ && haveData_;
}

void ICACHE_RAM_ATTR MurmurLink::requestRestart()
{
    MurmurLock lock;
    restart_ = true;
    ready_ = false;
}

void MurmurLink::poll(uint32_t now)
{
    bool restart, ready;
    {
        MurmurLock lock;
        if (goodData_) { lastGood_ = now; goodData_ = false; }
        restart = restart_;
        restart_ = false;
        ready = ready_;
        healthy_ = ready_ && now - lastGood_ < 1000;
    }
    uint8_t out[50];
    // Loss of authenticated downlink includes independent RX reboot. Do not
    // derive a new key from a reset public counter or keep sending stale RC.
    if (tx_ && (!started_ || restart ||
        (ready ? now - lastGood_ >= 5000 : now - lastStart_ >= 10000))) {
        {
            MurmurLock lock;
            ready_ = false;
            output_ = false;
            invalidate_();
        }
        uint8_t result = session_.start(out);
        started_ = true;
        lastStart_ = now;
        if (result & MurmurSession::Send) publish(out);
    } else if (restart) {
        MurmurLock lock;
        invalidate_();
    }

    // At most one received frame per loop, and therefore at most one HMAC
    // exchange step. An unauthenticated RF flood cannot make an unbounded loop.
    uint8_t frame[6], message[50];
    {
        MurmurLock lock;
        if (!count_) return;
        memcpy(frame, incoming_[head_], 6);
        head_ = (head_ + 1) % 8;
        --count_;
    }
    if (!assembler_.receive(frame, 6, message)) return;
    const uint8_t result = session_.receive(message, sizeof(message), out);
    if (result & MurmurSession::Activated) {
        uint8_t up[16], down[16];
        session_.getKeys(up, down);
        {
            MurmurLock lock;
            install_(up, down);
            ready_ = true;
            output_ = false;
            goodData_ = false;
            haveData_ = false;
            lastGood_ = now;
        }
        clean(up); clean(down);
    }
    if (result & MurmurSession::Send) publish(out);
}
#endif
