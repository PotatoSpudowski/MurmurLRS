<div align="center">

<img alt="MurmurLRS" src="/docs/logo.svg" width="50%" height="50%">

Experimental encrypted [ExpressLRS](https://github.com/ExpressLRS/ExpressLRS) with keyed frequency hopping.

[![Murmur encrypted checks](https://github.com/PotatoSpudowski/MurmurLRS/actions/workflows/murmur.yml/badge.svg)](https://github.com/PotatoSpudowski/MurmurLRS/actions/workflows/murmur.yml)
[![Ascon-128](https://img.shields.io/badge/cipher-Ascon--128-blue?style=flat-square)](src/lib/MurmurEncrypt/)
[![Reddit](https://img.shields.io/badge/r%2Ffpv-423%2B%20upvotes-orange?style=flat-square&logo=reddit)](https://www.reddit.com/r/fpv/comments/1sl5hf1/)
[![License](https://img.shields.io/github/license/PotatoSpudowski/MurmurLRS?style=flat-square)](https://github.com/PotatoSpudowski/MurmurLRS/blob/master/LICENSE)

</div>

---

MurmurLRS adds Ascon-128 packet encryption, truncated authentication tags, and keyed frequency hopping to ExpressLRS. Packet sizes stay unchanged; cleartext SYNC packets are still used for connection establishment. This is a research/hobby implementation, with security limitations described below.

## Upstream compatibility

The current branch is based on **ExpressLRS 4.1.0 plus subsequent upstream development**, not ExpressLRS 3.x or an unmodified 4.1.0 release. The latest upstream merge incorporates [`46f1f7ad`](https://github.com/ExpressLRS/ExpressLRS/commit/46f1f7ad) through merge `e2f55f26`.

Use the same MurmurLRS revision, binding phrase, and compatible RF settings on both endpoints. Stock ExpressLRS cannot exchange encrypted RC/data packets with MurmurLRS. Use the Lua script shipped in this repository.

## Features

### Implemented

- **Packet encryption and authentication.** Non-SYNC packets pass through Ascon-128. A 14-bit tag for standard packets or 16-bit tag for full-resolution packets replaces the CRC. These short tags provide limited forgery resistance, not full-strength authentication.
- **Cryptographic FHSS (FHSSv2).** ASCON-XOF generates a keyed hop sequence, with rejection sampling and Fisher–Yates shuffling. Its secrecy depends on the encryption key's secrecy.
- **Replay window.** A 64-packet sliding window checks reconstructed counters during a locked connection. It is not a persistent replay barrier across restarts.
- **Epoch acquisition.** The RX searches candidate epochs and requires consecutive authentication matches before locking. Acquisition and reboot recovery remain important hardware test cases.

### Roadmap

- **Adaptive TX power** ([#8](https://github.com/PotatoSpudowski/MurmurLRS/issues/8)). Three-priority dynamic power: emergency ramp on LQ drop, RSSI-based stepping, and power decay when the link is healthy. A proposed additional timed decay policy would build on the existing upstream power increases and decreases. This reduces unnecessary RF output and saves battery.

- **Telemetry modes** ([#9](https://github.com/PotatoSpudowski/MurmurLRS/issues/9)). Full (default), minimal (critical alerts only), or silent (uplink-only, zero RX emissions). The existing telemetry ratio already provides an Off setting; priority filtering remains a separate proposal.

- **N-band diversity** ([#10](https://github.com/PotatoSpudowski/MurmurLRS/issues/10)). ELRS Gemini supports 2 simultaneous bands. Support for three or more radios/bands is a protocol and hardware proposal, not an implemented mode.

- **Repeater mode** ([#11](https://github.com/PotatoSpudowski/MurmurLRS/issues/11)). A relay node retransmits control packets, extending range beyond line-of-sight without extra ground infrastructure.

- **Swarm ID** ([#12](https://github.com/PotatoSpudowski/MurmurLRS/issues/12)). Multiple RX addresses on one TX. One operator, multiple craft, no channel conflicts.

- **Forward secrecy** ([#14](https://github.com/PotatoSpudowski/MurmurLRS/issues/14)). Session-key design under discussion. Deriving keys from a static master key and public counters alone does not provide forward secrecy.

---

## Getting started

```bash
git clone https://github.com/PotatoSpudowski/MurmurLRS
```

1. Open [ELRS Configurator](https://github.com/ExpressLRS/ExpressLRS-Configurator/releases)
2. Go to the **Local** tab, point it at the `src` folder
3. Set your binding phrase (3-4 random words minimum, same on TX and RX)
4. Flash TX, flash RX

Source builds enable encryption when a binding phrase is processed from `user_defines.txt` or `super_defines.txt`. The dedicated bench targets enable it explicitly. Setting a phrase only through runtime configuration does not enable code that was compiled without `MURMUR_ENCRYPT`. You'll see in the build log:

```
MurmurLRS: encryption enabled
```

For command-line smoke builds, explicitly set `-DMURMUR_ENCRYPT`: a binding phrase passed only through `PLATFORMIO_BUILD_FLAGS` does not run the phrase-processing hook. Build success alone does not prove an encrypted over-the-air link.

For two LilyGO T3-S3 LR1121 boards, use the [dedicated bench guide](bench/lilygo-t3s3.md). It includes checked-in pin/RF-switch settings, build and upload commands, and a repeatable test checklist.

## How it works

The current firmware hashes the ELRS six-byte UID with ASCON-XOF to obtain its 16-byte encryption key. A 16-byte output does not create 128 bits of entropy: this path is limited by the UID's 48-bit input space. The separate phrase KDF in the crypto library is not the firmware initialization path.

```
TX:  RC data -> encrypt + authenticate -> transmit
RX:  receive -> verify -> decrypt -> output
```

Zero extra bytes. Same packet structure. Same air rate. The authentication tag replaces the CRC field.

## Security limits

- Authentication tags are only 14 or 16 bits. An idealized single independent tag guess succeeds with probability 1/16,384 or 1/65,536; trying several counter candidates increases the number of verification opportunities.
- Keys are currently derived from the six-byte UID. Treat UID disclosure as key disclosure.
- Counter state resets on boot and can repeat within an epoch after a TX rate reset. Unique nonces across sessions and rate changes need a protocol-level fix.
- SYNC packets remain cleartext and use the stock CRC; they are not authenticated by the packet AEAD.
- No forward secrecy is implemented. The project does not claim resistance to physical key extraction, jamming, or all packet injection attacks.

These constraints need to be considered together; cipher test vectors alone do not establish the security of the radio protocol. See [the PrivacyLRS discussion](https://github.com/PotatoSpudowski/MurmurLRS/issues/16) and [session-key proposal](https://github.com/PotatoSpudowski/MurmurLRS/issues/14).

## Hardware and performance

The source contains ESP32, ESP32-S3, ESP32-C3, and ESP8285 targets and SX127x, SX1280, LR1121, and LR2021 radio paths. A successful build is not hardware qualification. Board pin assignments, RF switches, oscillator settings, and power calibration must match the actual board.

Packet sizes remain unchanged. Encryption and epoch searches add processing time; measure timing and link behavior on the intended hardware and packet rate.

## Tests

```
cd src/lib/MurmurEncrypt
make test
```

The C suite contains 62 tests covering cipher vectors, packet authentication, replay checks, FHSSv2, acquisition, and simulated long-running sessions. The native PlatformIO suite currently contains 147 tests. The [encrypted CI workflow](.github/workflows/murmur.yml) compiles six firmware targets with `MURMUR_ENCRYPT`, including both LilyGO bench roles; the upstream workflow exercises native tests and stock builds. Simulation does not replace over-the-air testing.

<details>
<summary>Technical details</summary>

**Cipher:** Ascon-128 as implemented in `src/lib/MurmurEncrypt/ascon.c`; this is not a claim of conformance to the final NIST Ascon-AEAD128 standard.

**Key derivation:**
```
ELRS binding-phrase define -> MD5 -> UID (first 6 bytes)
UID -> ASCON-XOF -> enc_key (16B)
enc_key -> ASCON-XOF("MurmurFHSS" || enc_key) -> fhss_key (16B)
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
