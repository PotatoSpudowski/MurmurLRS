#include "MurmurSession.h"
#if defined(MURMUR_ENCRYPT)
#include "vendor/SHA256.h"
#include "vendor/Crypto.h"
#include <string.h>

namespace {
const uint8_t version = 1;
const char authDomain[] = "MurmurLRS/session-auth/v1";
const char upDomain[] = "MurmurLRS/session-key/v1/uplink";
const char downDomain[] = "MurmurLRS/session-key/v1/downlink";

bool equal(const uint8_t *a, const uint8_t *b, size_t length)
{
    return secure_compare(a, b, length);
}

bool zero(const uint8_t *p, size_t length)
{
    uint8_t value = 0;
    for (size_t i = 0; i < length; ++i) value |= p[i];
    return value == 0;
}

void tag(const uint8_t key[16], const uint8_t message[34], uint8_t out[16])
{
    SHA256 hash;
    hash.resetHMAC(key, 16);
    hash.update(authDomain, sizeof(authDomain) - 1);
    hash.update(message, 34);
    hash.finalizeHMAC(key, 16, out, 16);
}
}

void murmur_hkdf_sha256_32(const uint8_t *salt, size_t saltLength,
                          const uint8_t *ikm, size_t ikmLength,
                          const uint8_t *info, size_t infoLength, uint8_t out[32])
{
    SHA256 hash;
    uint8_t prk[32];
    const uint8_t zeroSalt[32] = {};
    if (!saltLength) {
        salt = zeroSalt;
        saltLength = sizeof(zeroSalt);
    }
    hash.resetHMAC(salt, saltLength);
    hash.update(ikm, ikmLength);
    hash.finalizeHMAC(salt, saltLength, prk, sizeof(prk));
    hash.resetHMAC(prk, sizeof(prk));
    hash.update(info, infoLength);
    const uint8_t block = 1;
    hash.update(&block, 1);
    hash.finalizeHMAC(prk, sizeof(prk), out, 32);
    clean(prk);
}

MurmurSession::MurmurSession(bool isTx, const uint8_t master[16], Random random, void *context)
    : isTx_(isTx), active_(false), haveNonce_(false), phase_(Idle),
      random_(random), randomContext_(context)
{
    memcpy(master_, master, 16);
    memset(lastNonce_, 0, sizeof(lastNonce_));
    memset(pending_, 0, sizeof(pending_));
    memset(completed_, 0, sizeof(completed_));
    memset(uplink_, 0, sizeof(uplink_));
    memset(downlink_, 0, sizeof(downlink_));
}

MurmurSession::~MurmurSession()
{
    clean(master_); clean(lastNonce_); clean(pending_); clean(completed_);
    clean(uplink_); clean(downlink_);
}

bool MurmurSession::fresh(uint8_t out[16])
{
    if (!random_ || !random_(randomContext_, out) || zero(out, 16) ||
        (haveNonce_ && equal(out, lastNonce_, 16))) {
        clean(out, 16);
        return false;
    }
    memcpy(lastNonce_, out, 16);
    haveNonce_ = true;
    return true;
}

void MurmurSession::message(Type type, const uint8_t transcript[32], uint8_t out[MessageSize]) const
{
    out[0] = version;
    out[1] = type;
    memcpy(out + 2, transcript, 32);
    tag(master_, out, out + 34);
}

uint8_t MurmurSession::start(uint8_t out[MessageSize])
{
    if (!isTx_) return Ignored;
    uint8_t nonce[16];
    if (!fresh(nonce)) return EntropyFailed;
    memcpy(pending_, nonce, 16);
    memset(pending_ + 16, 0, 16);
    clean(nonce);
    phase_ = HelloSent;
    message(Hello, pending_, out);
    return Send;
}

bool MurmurSession::retry(uint8_t out[MessageSize]) const
{
    if (phase_ == HelloSent) message(Hello, pending_, out);
    else if (phase_ == ReplySent) message(Reply, pending_, out);
    else if (phase_ == ConfirmSent) message(Confirm, pending_, out);
    else return false;
    return true;
}

void MurmurSession::activate()
{
    uint8_t key[32];
    murmur_hkdf_sha256_32(pending_, 32, master_, 16,
        reinterpret_cast<const uint8_t *>(upDomain), sizeof(upDomain) - 1, key);
    memcpy(uplink_, key, 16);
    murmur_hkdf_sha256_32(pending_, 32, master_, 16,
        reinterpret_cast<const uint8_t *>(downDomain), sizeof(downDomain) - 1, key);
    memcpy(downlink_, key, 16);
    clean(key);
    memcpy(completed_, pending_, 32);
    active_ = true;
    phase_ = Established;
}

bool MurmurSession::getKeys(uint8_t uplink[16], uint8_t downlink[16]) const
{
    if (!active_) return false;
    memcpy(uplink, uplink_, 16);
    memcpy(downlink, downlink_, 16);
    return true;
}

uint8_t MurmurSession::receive(const uint8_t *in, size_t length, uint8_t out[MessageSize])
{
    if (length != MessageSize || in[0] != version) return Ignored;
    const uint8_t type = in[1];
    if (isTx_ ? (type != Reply && type != Ready) : (type != Hello && type != Confirm))
        return Ignored;
    uint8_t expected[16];
    tag(master_, in, expected);
    bool valid = equal(expected, in + 34, 16);
    clean(expected);
    if (!valid) return Ignored;
    const uint8_t *transcript = in + 2;
    if (zero(transcript, 16)) return Ignored;

    if (!isTx_ && type == Hello) {
        if (!zero(transcript + 16, 16)) return Ignored;
        if (active_ && equal(transcript, completed_, 16)) return Ignored;
        if (phase_ == ReplySent && equal(transcript, pending_, 16)) {
            message(Reply, pending_, out);
            return Send;
        }
        uint8_t nonce[16];
        if (!fresh(nonce)) return EntropyFailed;
        memcpy(pending_, transcript, 16);
        memcpy(pending_ + 16, nonce, 16);
        clean(nonce);
        phase_ = ReplySent;
        message(Reply, pending_, out);
        return Send;
    }

    if (zero(transcript + 16, 16)) return Ignored;
    if (isTx_ && type == Reply) {
        if (phase_ == ConfirmSent && equal(transcript, pending_, 32)) {
            message(Confirm, pending_, out);
            return Send;
        }
        if (phase_ != HelloSent || !equal(transcript, pending_, 16)) return Ignored;
        memcpy(pending_ + 16, transcript + 16, 16);
        phase_ = ConfirmSent;
        message(Confirm, pending_, out);
        return Send;
    }

    if (!isTx_ && type == Confirm) {
        // An old confirmation may help a peer recover a lost READY, but MUST
        // NOT reinstall keys, reset counters, or replace a newer pending HELLO.
        if (active_ && equal(transcript, completed_, 32)) {
            message(Ready, completed_, out);
            return Send;
        }
        if (phase_ != ReplySent || !equal(transcript, pending_, 32)) return Ignored;
        activate();
        message(Ready, completed_, out);
        return Send | Activated;
    }

    if (isTx_ && type == Ready && phase_ == ConfirmSent && equal(transcript, pending_, 32)) {
        activate();
        return Activated;
    }
    return Ignored;
}

MurmurSessionFrames::MurmurSessionFrames()
    : seen_(0), sendId_(0), receiveId_(0), cursor_(0),
      haveOutgoing_(false), sending_(false), receiving_(false)
{
    memset(outgoing_, 0, sizeof(outgoing_));
    memset(incoming_, 0, sizeof(incoming_));
}

void MurmurSessionFrames::queue(const uint8_t message[MurmurSession::MessageSize])
{
    // Preserve partial delivery across retransmissions, including ID wrap.
    if (!haveOutgoing_ || memcmp(outgoing_, message, sizeof(outgoing_))) {
        memcpy(outgoing_, message, sizeof(outgoing_));
        sendId_ = (sendId_ + 1) & 15;
        cursor_ = 0;
    }
    haveOutgoing_ = sending_ = true;
}

bool MurmurSessionFrames::next(uint8_t out[FrameSize])
{
    if (!sending_) return false;
    out[0] = (sendId_ << 4) | cursor_;
    memcpy(out + 1, outgoing_ + cursor_ * 5, 5);
    if (++cursor_ == 10) {
        cursor_ = 0;
        sending_ = false;
    }
    return true;
}

bool MurmurSessionFrames::receive(const uint8_t *frame, size_t length,
                                  uint8_t out[MurmurSession::MessageSize])
{
    if (length != FrameSize) return false;
    const uint8_t id = frame[0] >> 4;
    const uint8_t index = frame[0] & 15;
    if (index >= 10) return false;
    if (!receiving_ || receiveId_ != id) {
        seen_ = 0;
        receiveId_ = id;
        receiving_ = true;
    }
    const uint16_t bit = static_cast<uint16_t>(1) << index;
    if (seen_ & bit) {
        if (memcmp(incoming_ + index * 5, frame + 1, 5)) {
            seen_ = 0;
            receiving_ = false;
        }
        return false;
    }
    memcpy(incoming_ + index * 5, frame + 1, 5);
    seen_ |= bit;
    if (seen_ != 0x3FF) return false;
    memcpy(out, incoming_, sizeof(incoming_));
    seen_ = 0;
    return true;
}
#endif
