#pragma once

#if defined(MURMUR_ENCRYPT)
#include <stddef.h>
#include <stdint.h>

// Experimental protocol core. Not connected to the production radio path yet.
// Call from the main loop, never an ISR. Random must provide 16 fresh CSPRNG
// bytes per call and return false on failure. Deterministic test RNGs are not
// suitable for firmware. A single instance must not be used concurrently.
class MurmurSession {
public:
    static constexpr size_t MessageSize = 50;
    using Random = bool (*)(void *context, uint8_t out[16]);
    enum Result : uint8_t { Ignored = 0, Send = 1, Activated = 2, EntropyFailed = 4 };

    MurmurSession(bool isTx, const uint8_t master[16], Random random, void *context);
    ~MurmurSession();
    MurmurSession(const MurmurSession &) = delete;
    MurmurSession &operator=(const MurmurSession &) = delete;

    // TX starts/restarts a pending handshake without discarding an active key.
    // Results are bit flags; reset data counters ONLY on Activated.
    uint8_t start(uint8_t out[MessageSize]);
    uint8_t receive(const uint8_t *message, size_t length, uint8_t out[MessageSize]);
    bool retry(uint8_t out[MessageSize]) const;
    bool getKeys(uint8_t uplink[16], uint8_t downlink[16]) const;
    bool active() const { return active_; }

private:
    enum Phase : uint8_t { Idle, HelloSent, ReplySent, ConfirmSent, Established };
    enum Type : uint8_t { Hello = 1, Reply = 2, Confirm = 3, Ready = 4 };
    bool isTx_, active_, haveNonce_;
    Phase phase_;
    Random random_;
    void *randomContext_;
    uint8_t master_[16], lastNonce_[16];
    uint8_t pending_[32], completed_[32]; // TX challenge || RX challenge
    uint8_t uplink_[16], downlink_[16];

    bool fresh(uint8_t out[16]);
    void message(Type type, const uint8_t transcript[32], uint8_t out[MessageSize]) const;
    void activate();
};

// Bounded, allocation-free framing for six-byte OTA payloads. Full-resolution
// packets use the same envelope; the adapter must clear unused bytes and apply
// the existing outer CRC. Only a fully authenticated message may change state.
class MurmurSessionFrames {
public:
    static constexpr size_t FrameSize = 6;
    MurmurSessionFrames();
    void queue(const uint8_t message[MurmurSession::MessageSize]);
    bool next(uint8_t out[FrameSize]);
    bool receive(const uint8_t *frame, size_t length,
                 uint8_t out[MurmurSession::MessageSize]);
private:
    uint8_t outgoing_[50], incoming_[50];
    uint16_t seen_;
    uint8_t sendId_, receiveId_, cursor_;
    bool haveOutgoing_, sending_, receiving_;
};

// RFC 5869 extract/expand, fixed to SHA-256 and one output block (32 bytes).
// Internal protocol helper exposed for independent RFC known-answer tests.
void murmur_hkdf_sha256_32(const uint8_t *salt, size_t saltLength,
                          const uint8_t *ikm, size_t ikmLength,
                          const uint8_t *info, size_t infoLength, uint8_t out[32]);
#endif
