<div align="center">

<img alt="MurmurLRS" src="/docs/logo.svg" width="50%" height="50%">

Encrypted [ExpressLRS](https://github.com/ExpressLRS/ExpressLRS). Every packet authenticated. Same hardware, same speed.

[![Crypto Tests](https://img.shields.io/badge/crypto%20tests-52%2F52%20pass-brightgreen?style=flat-square)](src/lib/MurmurEncrypt/)
[![ASCON-128](https://img.shields.io/badge/ASCON--128%20AEAD-NIST%20SP%20800--232-blue?style=flat-square)](https://csrc.nist.gov/pubs/sp/800/232/ipd)
[![Reddit](https://img.shields.io/badge/r%2Ffpv-423%2B%20upvotes-orange?style=flat-square&logo=reddit)](https://www.reddit.com/r/fpv/comments/1sl5hf1/)
[![License](https://img.shields.io/github/license/PotatoSpudowski/MurmurLRS?style=flat-square)](https://github.com/PotatoSpudowski/MurmurLRS/blob/master/LICENSE)

</div>

---

MurmurLRS is a hardened fork of ExpressLRS. Same hardware, same configurator, same performance. Stock ELRS isn't encrypted. Anyone with an SDR can read your stick inputs or inject commands. MurmurLRS fixes that.

## Features

### Shipped

- **ASCON-128 AEAD encryption.** Every RC packet is encrypted and authenticated. Your binding phrase goes through an ASCON-XOF KDF to produce real 128-bit keys. Captured packets are just ciphertext. Tampered or replayed packets get rejected. Zero extra bytes on the wire because the MAC replaces the CRC field.

- **Cryptographic FHSS (FHSSv2).** Stock ELRS uses an invertible LCG for frequency hopping. Watch a few transmissions and you can reconstruct the full hop schedule. We replaced it with an ASCON-XOF keyed CSPRNG and Fisher-Yates shuffled blocks. The hop sequence derives from the 128-bit encryption key with proper domain separation, so it's unpredictable even if you're watching every transmission.

- **Replay protection.** 64-packet sliding window with a 32-bit monotonic counter. Out-of-order packets within the window are fine. Duplicates and stale packets get dropped.

- **Epoch acquisition.** RX doesn't need to boot at the same time as TX. On connect, RX searches the full 32-bit epoch space with a sliding window (16 epochs per packet) and needs 3 consecutive hits to lock. Handles reboots, signal dropouts, and long continuous sessions without losing sync.

- **Anti-spoofing.** Every non-SYNC packet carries a keyed authentication tag. Commands from someone who doesn't know the binding phrase get rejected. There's no protocol downgrade path.

### Roadmap

- **Adaptive TX power** ([#8](https://github.com/PotatoSpudowski/MurmurLRS/issues/8)). Three-priority dynamic power: emergency ramp on LQ drop, RSSI-based stepping, and power decay when the link is healthy. Stock ELRS skips the decay step. This reduces unnecessary RF output and saves battery.

- **Telemetry modes** ([#9](https://github.com/PotatoSpudowski/MurmurLRS/issues/9)). Full (default), minimal (critical alerts only), or silent (uplink-only, zero RX emissions). Bidirectional telemetry doubles the link's RF footprint. Silent mode halves it.

- **N-band diversity** ([#10](https://github.com/PotatoSpudowski/MurmurLRS/issues/10)). ELRS Gemini supports 2 simultaneous bands. We're generalizing to 3+. Add a third LR1121 for 433 MHz and all three bands transmit every hop. An adversary must jam all bands at once to kill the link.

- **Repeater mode** ([#11](https://github.com/PotatoSpudowski/MurmurLRS/issues/11)). A relay node retransmits control packets, extending range beyond line-of-sight without extra ground infrastructure.

- **Swarm ID** ([#12](https://github.com/PotatoSpudowski/MurmurLRS/issues/12)). Multiple RX addresses on one TX. One operator, multiple craft, no channel conflicts.

- **Extended failsafe** ([#13](https://github.com/PotatoSpudowski/MurmurLRS/issues/13)). Stock ELRS failsafes in about 1 second on signal loss. Extended failsafe holds last commands for 10-20s so the craft can clear interference or return home.

- **Forward secrecy** ([#14](https://github.com/PotatoSpudowski/MurmurLRS/issues/14)). Session key ratchet so compromise of one session doesn't expose past or future traffic.

---

## Getting started

```bash
git clone https://github.com/PotatoSpudowski/MurmurLRS
```

1. Open [ELRS Configurator](https://github.com/ExpressLRS/ExpressLRS-Configurator/releases)
2. Go to the **Local** tab, point it at the `src` folder
3. Set your binding phrase (3-4 random words minimum, same on TX and RX)
4. Flash TX, flash RX

Encryption turns on automatically when a binding phrase is set. You'll see in the build log:

```
MurmurLRS: encryption enabled
```

To verify, connect over USB (420000 baud) and check for:

```
MurmurLRS: encryption active (TX)
```

Both TX and RX must run MurmurLRS. A MurmurLRS device won't link with stock ELRS.

## How it works

Your binding phrase becomes your encryption key. In stock ELRS it's just for pairing. In MurmurLRS it gets fed through a key derivation function to produce real cryptographic material.

```
TX:  RC data -> encrypt + authenticate -> transmit
RX:  receive -> verify -> decrypt -> output
```

Zero extra bytes. Same packet structure. Same air rate. The authentication tag replaces the CRC field.

## Performance

Identical to stock ELRS. Encryption adds about 22 microseconds per packet. At 500 Hz that's 1.3% CPU. You won't notice it.

| | MurmurLRS | Stock ELRS |
|:--|:--|:--|
| Latency added | ~22 us/pkt | -- |
| Packet size | Same | Same |
| Air rate | Same | Same |
| Range | Same | Same |

## vs PrivacyLRS

Both add encryption to ELRS. The differences are authentication and FHSS.

| | MurmurLRS | PrivacyLRS |
|:--|:--|:--|
| Cipher | ASCON-128 AEAD | ChaCha20 |
| Authentication | Yes (keyed MAC) | No (CRC only) |
| Tampered packets | Rejected | Accepted silently |
| Replay protection | 64-packet sliding window | 8-bit counter |
| FHSS | ASCON-XOF CSPRNG (unpredictable) | LCG (invertible) |
| Adaptive TX power | Planned | None |

PrivacyLRS encrypts. MurmurLRS encrypts, authenticates, and hides the hop pattern. If someone flips bits in your encrypted packet, MurmurLRS rejects it. If someone watches your transmissions, they still can't predict where you'll hop next.

## Hardware

Everything ELRS supports. ESP32, ESP32-S3, ESP32-C3, ESP8285. 900 MHz and 2.4 GHz. Same radios, same modules.

## Tests

```
cd src/lib/MurmurEncrypt
make test
```

52/52 tests pass. Covers ASCON-128 NIST vectors, OTA header authentication, FHSSv2 sequence generation, epoch acquisition, and 10-minute stress tests.

<details>
<summary>Technical details</summary>

**Cipher:** [ASCON-128](https://csrc.nist.gov/pubs/sp/800/232/ipd) AEAD (NIST SP 800-232, lightweight crypto standard selected 2023)

**Key derivation:**
```
binding_phrase -> ASCON-XOF -> master_key -> ASCON-XOF -> enc_key (16B) + UID (6B)
enc_key -> ASCON-XOF("MurmurFHSS" || enc_key) -> fhss_key (16B)
fhss_key -> ASCON-XOF("FHSSv1" || fhss_key || domain_id) -> hop sequence
```

**FHSS:** Cryptographic hop sequence via ASCON-XOF CSPRNG. Rejection sampling eliminates modulo bias. Fisher-Yates shuffle per block. Domain separation for dual-band (LR1121).

**Replay protection:** 64-packet sliding window with 32-bit counter reconstructed from 8-bit OtaNonce

**Nonce construction:** counter + packet_type + direction (uplink=0, downlink=1)

**What changed from stock ELRS:**

| File | What |
|:--|:--|
| `src/lib/MurmurEncrypt/*` | Encryption + FHSS module (~500 LOC, pure C) |
| `src/lib/FHSS/FHSS.cpp` | Secure FHSS sequence generation (FHSSv2) |
| `src/lib/OTA/OTA.cpp` | Encrypt/decrypt hooks, counter tracking |
| `src/python/build_flags.py` | Auto-enable when binding phrase is set |
| `src/src/tx_main.cpp` | Init at boot, counter reset on rate change |
| `src/src/rx_main.cpp` | Init at boot, counter reset on SYNC/disconnect |

**Epoch acquisition:**

RX doesn't need to boot at the same time as TX. On connect, it searches the full 32-bit epoch space with a sliding window (16 epochs per packet) and requires 3 consecutive hits to lock. Handles nonce drift from timer convergence. If the link loses sync (say TX reboots), RX falls back to acquisition after 16 consecutive failures, scans forward from near the last known epoch, and wraps to 0 after 256 epochs without a hit. MurmurTrackNonce keeps the RX epoch in sync during signal dropouts.

**Known limitations:**
- 14-bit MAC (forgery probability: 1/16384 per attempt)
- SYNC packets are cleartext (needed for connection establishment)
- No forward secrecy yet (session key ratchet is on the roadmap)

</details>

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

- **Flash and test** -- report what works and what breaks
- **Review the crypto** -- under 500 lines of C in `src/lib/MurmurEncrypt/`
- **ESP8285/ESP32-S3/C3 testing** -- primary dev is on ESP32

## Community

Started with a [post on r/fpv](https://www.reddit.com/r/fpv/comments/1sl5hf1/) (423+ upvotes, 155+ comments). Looking for testers.

## Changes

See [CHANGELOG.md](CHANGELOG.md).

---

Based on [ExpressLRS](https://github.com/ExpressLRS/ExpressLRS). See [README_ELRS.md](README_ELRS.md) for upstream docs.
