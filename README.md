<div align="center">

<img alt="MurmurLRS" src="/docs/logo.svg" width="50%" height="50%">

Encrypted [ExpressLRS](https://github.com/ExpressLRS/ExpressLRS) with keyed frequency hopping.

[![Murmur encrypted checks](https://github.com/PotatoSpudowski/MurmurLRS/actions/workflows/murmur.yml/badge.svg)](https://github.com/PotatoSpudowski/MurmurLRS/actions/workflows/murmur.yml)
[![Ascon-128](https://img.shields.io/badge/cipher-Ascon--128-blue?style=flat-square)](src/lib/MurmurEncrypt/)
[![Reddit](https://img.shields.io/badge/r%2Ffpv-423%2B%20upvotes-orange?style=flat-square&logo=reddit)](https://www.reddit.com/r/fpv/comments/1sl5hf1/)
[![License](https://img.shields.io/github/license/PotatoSpudowski/MurmurLRS?style=flat-square)](https://github.com/PotatoSpudowski/MurmurLRS/blob/master/LICENSE)

</div>

---

MurmurLRS is an open-source radio-link security project that adds Ascon-128 packet encryption, truncated authentication tags, and keyed frequency hopping to ExpressLRS. Packet sizes stay unchanged; cleartext SYNC packets are still used for radio synchronization. Protocol guarantees and current limitations are documented below.

## Upstream compatibility

The current branch is based on **ExpressLRS 4.1.0 plus subsequent upstream development**, not ExpressLRS 3.x or an unmodified 4.1.0 release. The latest upstream merge incorporates [`46f1f7ad`](https://github.com/ExpressLRS/ExpressLRS/commit/46f1f7ad) through merge `e2f55f26`.

Use the same MurmurLRS revision, binding phrase, and compatible RF settings on both endpoints. Stock ExpressLRS cannot exchange encrypted RC/data packets with MurmurLRS. Use the Lua script shipped in this repository.

## Features

### Implemented

- **Packet encryption and authentication.** RC/data packets pass through Ascon-128; handshake messages use HMAC-SHA-256. A 14-bit tag for standard packets or 16-bit tag for full-resolution packets replaces the CRC. These short tags provide limited forgery resistance, not full-strength authentication.
- **Cryptographic FHSS (FHSSv2).** ASCON-XOF generates a keyed hop sequence, with rejection sampling and Fisher–Yates shuffling. Its secrecy depends on the encryption key's secrecy.
- **Replay window.** A 64-packet sliding window checks reconstructed counters and survives connection/rate resets within a session. New sessions install fresh directional keys after an authenticated challenge exchange.
- **Epoch acquisition.** The RX searches candidate epochs and requires consecutive authentication matches before locking. Acquisition and reboot recovery remain important hardware test cases.
- **Link diagnostics.** Optional receiver counters expose authentication outcomes, session installations, epoch lock, and packet-validation timing without exporting keys or channel payloads. See the [session protocol and diagnostics](src/lib/MurmurSession/README.md).

### Roadmap

- **Adaptive TX power** ([#8](https://github.com/PotatoSpudowski/MurmurLRS/issues/8)). Three-priority dynamic power: emergency ramp on LQ drop, RSSI-based stepping, and power decay when the link is healthy. A proposed additional timed decay policy would build on the existing upstream power increases and decreases. This reduces unnecessary RF output and saves battery.

- **Telemetry modes** ([#9](https://github.com/PotatoSpudowski/MurmurLRS/issues/9)). Priority filtering could reduce application telemetry while retaining handshake, recovery, and link-health traffic. Zero-emission RX operation would require a different session protocol; encrypted mode currently requires return traffic.

- **N-band diversity** ([#10](https://github.com/PotatoSpudowski/MurmurLRS/issues/10)). ELRS Gemini supports 2 simultaneous bands. Support for three or more radios/bands is a protocol and hardware proposal, not an implemented mode.

- **Repeater mode** ([#11](https://github.com/PotatoSpudowski/MurmurLRS/issues/11)). A relay node retransmits control packets, extending range beyond line-of-sight without extra ground infrastructure.

- **Swarm ID** ([#12](https://github.com/PotatoSpudowski/MurmurLRS/issues/12)). Multiple RX addresses on one TX. One operator, multiple craft, no channel conflicts.

- **Forward secrecy** ([#14](https://github.com/PotatoSpudowski/MurmurLRS/issues/14)). Ephemeral key agreement is under discussion. The current PSK-based session protocol does not provide forward secrecy.

---

## Getting started

```bash
git clone https://github.com/PotatoSpudowski/MurmurLRS
```

1. Open [ELRS Configurator](https://github.com/ExpressLRS/ExpressLRS-Configurator/releases)
2. Go to the **Local** tab, point it at the `src` folder
3. Set a long, randomly generated binding phrase at build time (same on TX and RX)
4. Flash TX, flash RX

Source builds enable encryption and provision the key from `MURMUR_BINDING_PHRASE` in the build environment, or `MY_BINDING_PHRASE` in `user_defines.txt` / `super_defines.txt`. The environment variable takes precedence. Encrypted builds without a nonempty build-time phrase fail. You'll see in the build log:

```
MurmurLRS: encryption enabled
```

For command-line builds, set `MURMUR_BINDING_PHRASE` in the environment, then run PlatformIO from `src/`. Use `PLATFORMIO_BUILD_FLAGS` for regulatory settings, not the phrase. The generated key header stays in the ignored build directory; compiler flags and build logs do not contain the phrase or key.

**Migration:** rebuild and flash both endpoints. Session-enabled firmware requires the new handshake on both TX and RX; it cannot exchange application packets with earlier MurmurLRS images. The full-phrase key format is incompatible with older UID-derived firmware, even for the same phrase. Changing the phrase in the device's WiFi UI changes ELRS binding settings but does not replace the compiled encryption key; rebuild both endpoints to change that key. Firmware images and build directories contain the key and must be treated as secret.

## How it works

The build derives a 16-byte master key from the complete UTF-8 binding phrase using SHA-256 with a versioned MurmurLRS domain prefix. The six-byte ELRS UID is an identifier, not key material. This removes the UID-sized key-space limit; actual key strength still depends on the phrase. Phrase derivation runs on the build computer. The handshake derives directional traffic keys on-device; neither operation adds per-packet hashing cost. The standalone ASCON-XOF phrase KDF in the C library is not the firmware provisioning path.

```
TX:  RC data -> encrypt + authenticate -> transmit
RX:  receive -> verify -> decrypt -> output
```

RC/data packet sizes and air rates stay unchanged; the authentication tag replaces the data CRC field. Session establishment uses separate control packets.

## Security limits

- Authentication tags are only 14 or 16 bits. An idealized single independent tag guess succeeds with probability 1/16,384 or 1/65,536; trying several counter candidates increases the number of verification opportunities.
- Phrase derivation is a fast hash, not password stretching. The ELRS UID also permits checking phrase guesses, so use a high-entropy, unique phrase. Disclosure of the UID alone no longer directly determines the key.
- Session freshness depends on boot entropy. The firmware negotiates directional traffic keys before accepting application packets, preserves replay history through rate/connection changes, and suspends traffic for rekey before counter exhaustion. On-device entropy and restart behavior require hardware validation.
- SYNC packets remain cleartext and use the stock CRC; they are not authenticated by the packet AEAD.
- No forward secrecy is implemented. The project does not claim resistance to physical key extraction, jamming, or all packet injection attacks.

The [authenticated session protocol](src/lib/MurmurSession/README.md) is integrated into TX/RX through bounded radio mailboxes. It provides two-way challenge exchange, separate directional keys, retry-safe confirmation, and recovery after loss of authenticated downlink. Encrypted mode requires return traffic: telemetry Off/Disarmed-Off uses 1:16, very sparse ratios are capped, and RX Force Telemetry Off is ignored. Handshake and recovery temporarily suspend application traffic.

These constraints need to be considered together; cipher test vectors alone do not establish the security of the radio protocol. See [the PrivacyLRS discussion](https://github.com/PotatoSpudowski/MurmurLRS/issues/16) and [session-key proposal](https://github.com/PotatoSpudowski/MurmurLRS/issues/14).

## Hardware and performance

The source contains ESP32, ESP32-S3, ESP32-C3, and ESP8285 targets and SX127x, SX1280, LR1121, and LR2021 radio paths. A successful build is not hardware qualification. Board pin assignments, RF switches, oscillator settings, and power calibration must match the actual board.

Packet sizes remain unchanged. Encryption and epoch searches add processing time; measure timing and link behavior on the intended hardware and packet rate.

## Tests

```
cd src/lib/MurmurEncrypt
make test
```

The C suite contains 62 tests covering cipher vectors, packet authentication, replay checks, FHSSv2, acquisition, and simulated long-running sessions. The stock native PlatformIO suite contains 147 tests.

`MURMUR_BINDING_PHRASE=ci-only-not-a-secret ../venv/bin/pio test -e native_murmur` (from `src/`) runs 44 tests exercising the production encrypted OTA hooks for both packet sizes, replay-resistant acquisition/relock, packet loss, tampering, nonce wrap, rate transitions, and late joins beyond epoch 255. It also tests session negotiation through the OTA hooks, independent reboots, entropy failure, counter exhaustion, and bounded recovery mailboxes. Adding `PLATFORMIO_BUILD_FLAGS=-DMURMUR_LINK_DIAGNOSTICS` includes the diagnostic regression for 45 tests; both configurations run in CI. Python provisioning tests run with `python -m unittest discover -s src/python/tests -p test_murmur_key.py` from the repo root.

The [encrypted CI workflow](.github/workflows/murmur.yml) compiles seven firmware targets with `MURMUR_ENCRYPT`, including both LilyGO bench roles; the upstream workflow exercises native tests and stock builds. Simulation does not replace over-the-air testing.

<details>
<summary>Technical details</summary>

**Cipher:** Ascon-128 as implemented in `src/lib/MurmurEncrypt/ascon.c`; this is not a claim of conformance to the final NIST Ascon-AEAD128 standard.

**Key derivation:**
```
ELRS binding-phrase define -> MD5 -> UID (first 6 bytes)
"MurmurLRS/packet-key/v1" || NUL || UTF-8 phrase -> SHA-256 -> master_key (first 16B)
master_key -> ASCON-XOF("MurmurFHSS" || master_key) -> fhss_key (16B)
master_key + authenticated TX/RX challenges -> HKDF-SHA256 -> uplink_key, downlink_key
fhss_key -> ASCON-XOF("FHSSv1" || fhss_key || domain_id) -> hop sequence
```

**FHSS:** Cryptographic hop sequence via ASCON-XOF CSPRNG. Rejection sampling eliminates modulo bias. Fisher-Yates shuffle per block. Domain separation for dual-band (LR1121).

**Replay protection:** 64-packet sliding window with 32-bit counter reconstructed from 8-bit OtaNonce

**Nonce construction:** counter + packet_type + direction (uplink=0, downlink=1)

**What changed from stock ELRS:**

| File | What |
|:--|:--|
| `src/lib/MurmurEncrypt/*` | Encryption + FHSS module (pure C) |
| `src/lib/FHSS/FHSS.cpp` | Secure FHSS sequence generation (FHSSv2) |
| `src/lib/OTA/OTA.cpp` | Encrypt/decrypt hooks, counter tracking |
| `src/python/build_flags.py` | Auto-enable when binding phrase is set |
| `src/src/tx_main.cpp` | Init at boot, counter reset on rate change |
| `src/src/rx_main.cpp` | Init at boot, counter reset on SYNC/disconnect |

**Epoch acquisition:**

The RX tries 16 candidate epochs per acquisition call and requires three consecutive matches before locking. The production scan wraps after a bounded range. Cold-start recovery at high TX epochs must be tested against the actual OTA implementation; standalone acquisition simulations are not sufficient evidence.

</details>

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

- **Flash and test** -- report what works and what breaks
- **Review the crypto** -- self-contained C implementation in `src/lib/MurmurEncrypt/`
- **ESP8285/ESP32-S3/C3 testing** -- primary dev is on ESP32

## Community

Started with a [post on r/fpv](https://www.reddit.com/r/fpv/comments/1sl5hf1/) (423+ upvotes, 155+ comments). Looking for testers.

## Changes

See [CHANGELOG.md](CHANGELOG.md).

---

Based on [ExpressLRS](https://github.com/ExpressLRS/ExpressLRS). See [README_ELRS.md](README_ELRS.md) for upstream docs.
