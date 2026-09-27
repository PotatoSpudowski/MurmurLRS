# Authenticated session core

This module implements and tests a session handshake and bounded message framing.
**It is not connected to the firmware's OTA callbacks or hardware RNG.** Current
firmware still uses the compiled packet key and retains the boot/session limits
in the repository README. Do not treat this module's tests as a radio security
qualification or as evidence that boot-time nonce reuse is fixed in firmware.

## Threat model and prerequisites

Assume a unique, high-entropy 16-byte pre-shared key per TX/RX pair, a functioning
CSPRNG at each endpoint, and an attacker who can capture, reorder, modify, inject,
and replay RF packets. UID disclosure must not reveal the PSK. A captured old
exchange must not activate its keys after either peer reboots. An authenticated
message retransmission must not reset packet counters or reinstall old keys.

The protocol authenticates possession of the pair's PSK, not a device identity.
Sharing a PSK with other devices makes those devices equally trusted. It does not
protect against PSK/flash extraction, a compromised endpoint, weak phrases,
traffic analysis, jamming, or resource exhaustion by a nearby transmitter. It
has **no forward secrecy**: captured challenges plus a later PSK compromise are
sufficient to derive past traffic keys. The protocol has not undergone external
security review and is not a standardized key exchange.

## Version 1 messages

All messages are exactly 50 bytes, with explicit byte serialization:

```
byte 0       version = 1
byte 1       type: HELLO=1, REPLY=2, CONFIRM=3, READY=4
bytes 2..17  TX challenge (16 bytes)
bytes 18..33 RX challenge (16 bytes; zero in HELLO only)
bytes 34..49 first 16 bytes of the HMAC-SHA-256 tag
```

The tag input is ASCII `MurmurLRS/session-auth/v1` (without a terminating NUL),
followed by bytes 0..33. The HMAC key is the PSK. Version, role/message type, and
both challenges are authenticated. Unsupported versions, wrong message types,
wrong lengths, and invalid tags do not change handshake state. Tag comparison
uses the vendored constant-time comparison routine.

1. TX draws a fresh challenge and sends HELLO.
2. RX verifies HELLO, draws a fresh challenge, and sends REPLY with both values.
3. TX verifies REPLY against its pending challenge and sends CONFIRM.
4. RX verifies CONFIRM against its pending pair, installs keys once, and sends
   READY. TX installs keys once after verifying READY for that same pair.

Lost messages are handled by retries of the same exchange. An RX that receives a
repeated CONFIRM for its current session re-sends READY without an `Activated`
event. A delayed confirmation for the current active session also leaves a newer
pending exchange intact. Starting a pending exchange keeps active keys available
until confirmation. The application must interpret the result as bit flags, send
output only on `Send`, and install keys/reset counters **only on `Activated`**.

RX and TX activation is not simultaneous: after CONFIRM, RX can have new keys
while TX is waiting for READY. The adapter must handle that transition explicitly;
this module does not promise uninterrupted traffic during rekeying. A new TX
exchange must be initiated after a peer restart or an expired pending attempt.
Peer-restart detection and retry timeouts belong to the adapter and are not yet
implemented here.

## Key derivation

Use RFC 5869 HKDF-SHA-256:

```
salt = TX challenge || RX challenge
IKM = PSK
uplink key   = HKDF(salt, IKM, "MurmurLRS/session-key/v1/uplink",   32)[0:16]
downlink key = HKDF(salt, IKM, "MurmurLRS/session-key/v1/downlink", 32)[0:16]
```

The implementation supports one 32-byte expand block. Traffic directions use
different keys. Challenges are public; the secret PSK supplies key entropy.
RFC 4231 HMAC vectors, RFC 5869 HKDF vectors, and independent Python message/key
vectors test the implementation. SHA-256/HMAC is vendored from a pinned revision
of rweather's Arduino Crypto library; see [vendor/README.md](vendor/README.md).

## Framing and cost

Each fragment is six bytes: four bits of transfer ID, four bits of fragment
index (0..9), then five message bytes. Ten fragments carry a message, so the
four-message handshake requires at least 40 radio packets, before retries and
other RF traffic. This fits the six-byte standard payload and also fits the
full-resolution payload without growing OTA packet sizes. The transfer ID wraps
at 16; it is an assembly aid, not an authentication or replay mechanism.

Assembly uses a fixed 50-byte buffer and bitmap. Out-of-order fragments are
accepted, identical duplicates ignored, and conflicting duplicates discard the
partial assembly. Retransmitting the same message retains its transfer ID and
send position so repeated HELLOs cannot continually restart a pending response.
Fragment assembly alone never authenticates a message; the caller must pass the
complete result through `MurmurSession::receive()`.

There is no heap allocation. The tests bound a session object to less than 256
bytes and a bidirectional frame object to less than 128 bytes. Cryptography runs
when processing complete handshake messages, not on each data packet. These are
structural bounds, not measurements of device execution time.

## Integration requirements

- Run cryptography and entropy collection in the main loop. ISR adapters should
  only transfer bounded buffers. Use an explicit ownership/critical-section
  policy when exchanging buffers and activating keys.
- Provide fresh 128-bit CSPRNG output for every new local challenge, across boots
  as well as retries. Return failure when entropy is unavailable. Zero and
  consecutively repeated values are rejected as obvious failures; these checks
  do not establish RNG quality or prevent all historical repeats.
- Initialize entropy before RF/ADC use where the SDK requires it. The ESP32 RNG
  has prerequisites when WiFi/Bluetooth are disabled; merely calling
  `esp_random()` is not sufficient evidence of fresh entropy. ESP8266 must also
  have a separately verified entropy source. Never substitute UID, millis(),
  unconditioned RSSI, or the deterministic test RNG.
- Reserve an OTA control discriminator, apply outer CRC for corruption detection,
  and authenticate the complete message before activating anything. No plaintext
  or master-key data fallback is allowed while session establishment is pending.
- Specify telemetry scheduling, telemetry-off behavior, timeouts, peer restart
  discovery, rate changes, and application failsafe behavior. The handshake
  needs traffic in both directions, even for an otherwise uplink-only link.
- Keep keyed FHSS boot discovery independent of transient traffic keys.
- Give each direction monotonic packet counters and separate replay state. Never
  reset a counter under a retained key. Rekey before counter exhaustion and stop
  application traffic if rekeying fails. Unauthenticated SYNC must not rewind a
  transmit counter or erase an established replay window.
- Test the completed radio adapter with the actual OTA implementation and on
  hardware before enabling it by default. This core is not that adapter.

## Tests

From `src/`:

```
MURMUR_BINDING_PHRASE=ci-only-not-a-secret ../venv/bin/pio test -e native_murmur -f test_murmur_session
```

Coverage includes both reboot directions, full recorded-transcript replay,
wrong PSKs, reflection, mutation of every byte of every message, entropy failure,
key agreement and direction separation, preserved active keys during negotiation,
loss of READY, duplicate activation prevention, fragment loss, reordering,
conflicting duplicates, and transfer-ID wrap. CI additionally runs AddressSanitizer
and UndefinedBehaviorSanitizer on this same code.

References: [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231),
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869),
[Espressif RNG prerequisites](https://docs.espressif.com/projects/esp-idf/en/v4.4.5/esp32/api-reference/system/random.html).
