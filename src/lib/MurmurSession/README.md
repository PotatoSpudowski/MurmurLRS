# Authenticated session core

This module implements the authenticated handshake and message framing used by
[MurmurLink](../MurmurLink/) and the firmware's OTA callbacks. TX/RX install
separate traffic keys only after confirming fresh challenges. Hardware entropy
is collected at boot; handshake cryptography runs in the main loop.

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
The adapter implements peer-restart detection and retry timeouts as described below.

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

## Firmware integration

- OTA type `0b11` carries session fragments with the stock outer CRC. The CRC
  detects corruption; only the complete HMAC-authenticated message can install
  keys. An index of 15 denotes idle padding. These packets never enter RC/data
  dispatch. Standard and full-resolution packet sizes are unchanged.
- Each retransmission rotates its starting fragment to avoid repeatedly losing
  the same fragment under periodic loss.
- An eight-frame mailbox bounds ISR input. The ISR copies one outgoing fragment;
  the main loop consumes at most one incoming fragment per iteration. Handshake
  HMAC/HKDF runs outside the shared critical section. Key publication, counters,
  and mailboxes use an ESP32 critical section or a saved ESP8266 interrupt state.
- TX starts at boot and restarts negotiation after five seconds without accepted
  encrypted downlink, or after ten seconds without completing an attempt.
  Starting a new TX exchange suspends application traffic. No plaintext or
  persistent-master-key data fallback exists.
- RX repeats READY until authenticated uplink proves the TX received it. Repeated
  confirmations never reinstall keys. HELLO replies are limited to one in 16
  downlink opportunities while the RX has recent authenticated traffic.
- Negotiation uses telemetry 1:2. Encrypted mode requires a return channel:
  telemetry Off/Disarmed-Off becomes 1:16, as do configured ratios with more than
  500 ms between opportunities. RX Force Telemetry Off is ignored in encrypted
  mode. Other telemetry behavior is unchanged for stock builds.
- Discovery FHSS continues to use the provisioned master key, independently of
  transient traffic keys. Each traffic direction has its own key; outgoing
  counters and incoming replay state are separate. Rate/disconnect/SYNC handling
  retains replay history. Outgoing counters never rewind, including multiple
  packets in a Gemini slot. Traffic stops and requests rekey before exhaustion.
- RX marks a control connection established only after authenticated data, and
  CRC-only SYNC/session fragments do not refresh its control-link timeout.
  Installing a new session clears channel assembly to avoid mixing old channels.
- Counter acquisition requires three distinct authenticated packets in the same
  or successive epochs, accommodating sparse telemetry. Each search revisits the
  last known neighborhood alongside a bounded forward scan, so a damaged first
  packet cannot strand a new peer far from epoch zero.

## Boot entropy

ESP32/S3/C3 enable the SDK's internal entropy source with
`bootloader_random_enable()`, collect a 32-byte seed, then disable that source
before device/ADC/WiFi initialization. ESP8266 temporarily wakes the WiFi RF
subsystem in station mode without joining a network, samples `ESP.random()`, and
turns WiFi off. This operation occurs at the start of `setup()`.

Subsequent challenges are the first 16 bytes of
`HMAC-SHA256(seed, "MurmurLRS/challenge/v1" || LE64(counter))`, with the counter
starting at one and failing closed on exhaustion. Seed material stays in RAM.
Zero/repeating-word seeds and failed initialization block challenge generation;
these checks are not entropy certification. No UID, timestamp, RSSI, or test RNG
is used as firmware entropy. Freshness across boots depends on the SDK entropy
source operating correctly on the target hardware.

## Wi-Fi management

An encrypted image contains the pair's master key. Its `/firmware.bin` export is
therefore disabled, including for authenticated administrators. Obtain recovery
backups through the wired device interface and keep them private.

Wi-Fi management is disabled by default. To enable it, set `MURMUR_WIFI_PASSWORD`
in the build environment to a separately generated 128-bit random value encoded
as 32 hexadecimal characters. For example, generate it locally with
`python3 -c 'import secrets; print(secrets.token_hex(16))'`, store it privately,
and supply it through the environment. Do not reuse the binding phrase or put
the credential in compiler flags or user defines. The build writes it into an
ignored generated header, not logs, options JSON, or compiler command lines.
The credential is compiled into the firmware; rebuilding changes it, and
resetting runtime configuration does not clear or replace it.

Connect directly to the device's AP using this credential, then open its local
IP address (normally `http://10.0.0.1`) and log in as **admin** with the same
credential. All HTTP routes require authentication before upload/JSON callbacks
can run. Cross-origin requests and unexpected Host values are rejected; wildcard
CORS is omitted. Saved home-network credentials are not used in encrypted mode.
State-changing requests use POST. Command-line clients without browser origin
headers must also send `X-Murmur-Request: 1`; that marker does not replace
authentication or bypass origin checks.
TCP/MSP bridging and UDP joystick services are disabled because they have no
equivalent authentication. Wired flashing remains available when management is
unprovisioned or the credential is lost.

This is HTTP Basic authentication over the protected Wi-Fi AP, not HTTPS,
firmware signing, or protection against physical flash extraction. Anyone given
the management credential is trusted to change configuration and install firmware.
Stock builds retain upstream management behavior. Public CI credentials are
test fixtures, never deployment credentials.

## On-device validation

Native tests exercise the production OTA wrappers and recovery adapter; firmware
builds check compilation and size. On-device entropy behavior, RF timing, packet
loss, independent power cycles, and failsafe recovery still require measurements
on the intended hardware. The short data tags, unauthenticated SYNC, denial of
service exposure, and lack of forward secrecy remain protocol limitations.

## Tests

For wired link diagnosis, add `-DMURMUR_LINK_DIAGNOSTICS` to an encrypted
build. The receiver exposes a read-only **Murmur Diagnostics** CRSF info field:
key availability (`K`), receive epoch lock (`L`), send/receive epochs (`E`),
accepted/rejected application packets (`OK`/`FAIL`), maximum validation time
(`MAX`), session key installations (`NEW`), and counter resets (`RESET`).
Rejected counts include acquisition trials and replays. Counters accumulate
until reboot; a read's first chunk refreshes its snapshot. No key material or
channel payload is exported. The timing instrumentation is absent when the
flag is omitted. Run `native_murmur` with the same flag to include the
diagnostic authentication/replay regression.

The separate **Murmur Timing** field reports receiver connection state (`S`),
timer lock state (`T`), current nonce (`N`), hop index (`H`), time since the last
authenticated application packet (`AGE`), and phase-detector offset/derivative
(`PFD`). ESP8285 builds also report maximum timer callback lateness (`LATE`).
These are diagnostic snapshots, not proof that control output is continuous.

`RH` is the FNV-1a fingerprint of the wire bytes of the last rejected application
packet. It helps correlate a bench transmission with a receiver rejection.
It is not an authentication tag and does not identify the reason for rejection.

From `src/`:

```
MURMUR_BINDING_PHRASE=ci-only-not-a-secret ../venv/bin/pio test -e native_murmur -f test_murmur_session
```

Coverage includes both reboot directions, full recorded-transcript replay,
wrong PSKs, reflection, mutation of every byte of every message, entropy failure,
key agreement and direction separation, preserved active keys during negotiation,
loss of READY, duplicate activation prevention, fragment loss, reordering,
conflicting duplicates, and transfer-ID wrap. CI additionally runs AddressSanitizer
and UndefinedBehaviorSanitizer on the core and recovery adapter. The separate
`test_murmur_ota` suite drives the production CRC/AEAD and session mailbox hooks.

References: [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231),
[RFC 5869](https://www.rfc-editor.org/rfc/rfc5869),
[Espressif RNG prerequisites](https://docs.espressif.com/projects/esp-idf/en/v4.4.5/esp32/api-reference/system/random.html),
[ESP8266 RNG implementation](https://github.com/esp8266/Arduino/blob/3.1.2/cores/esp8266/Esp.cpp).
