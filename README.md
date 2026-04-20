<div align="center">

<img alt="MurmurLRS" src="/docs/logo.svg" width="50%" height="50%">

Encrypted [ExpressLRS](https://github.com/ExpressLRS/ExpressLRS). Every packet authenticated. Same hardware, same speed.

[![Crypto Tests](https://img.shields.io/badge/crypto%20tests-29%2F29%20pass-brightgreen?style=flat-square)](src/lib/MurmurEncrypt/)
[![ASCON-128](https://img.shields.io/badge/ASCON--128%20AEAD-NIST%20SP%20800--232-blue?style=flat-square)](https://csrc.nist.gov/pubs/sp/800/232/ipd)
[![Reddit](https://img.shields.io/badge/r%2Ffpv-423%2B%20upvotes-orange?style=flat-square&logo=reddit)](https://www.reddit.com/r/fpv/comments/1sl5hf1/)
[![License](https://img.shields.io/github/license/PotatoSpudowski/MurmurLRS?style=flat-square)](https://github.com/PotatoSpudowski/MurmurLRS/blob/master/LICENSE)

</div>

---

MurmurLRS is a fork of ExpressLRS that encrypts every packet between your transmitter and receiver. Nobody can sniff your stick inputs or inject commands into your link.

Works on all ELRS hardware. Same configurator. No performance loss.

## Getting started

```bash
git clone https://github.com/PotatoSpudowski/MurmurLRS
```

1. Open [ELRS Configurator](https://github.com/ExpressLRS/ExpressLRS-Configurator/releases)
2. Go to **Local** tab, point it at the `src` folder
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

Your binding phrase becomes your encryption key. In stock ELRS it's just for pairing. In MurmurLRS it's fed through a key derivation function to produce real cryptographic keys.

```
TX:  RC data -> encrypt + authenticate -> transmit
RX:  receive -> verify -> decrypt -> output
```

Zero extra bytes. Same packet structure. Same air rate. The authentication tag replaces the CRC field.

## Performance

Identical to stock ELRS. The encryption adds ~22 microseconds per packet. At 500 Hz that's 1.3% CPU. You won't notice it.

| | MurmurLRS | Stock ELRS |
|:--|:--|:--|
| Latency added | ~22 us/pkt | -- |
| Packet size | Same | Same |
| Air rate | Same | Same |
| Range | Same | Same |

## vs PrivacyLRS

Both add encryption to ELRS. The difference is authentication.

| | MurmurLRS | PrivacyLRS |
|:--|:--|:--|
| Cipher | ASCON-128 AEAD | ChaCha20 |
| Authentication | Yes (keyed) | No (CRC only) |
| Tampered packets | Rejected | Accepted silently |
| Replay protection | 64-packet window | 8-bit counter |

PrivacyLRS encrypts. MurmurLRS encrypts and authenticates. If someone flips bits in your encrypted packet, MurmurLRS rejects it. PrivacyLRS can't tell.

## Hardware

Everything ELRS supports. ESP32, ESP8285, STM32. 900 MHz and 2.4 GHz. Same radios, same modules.

## Tests

```
cd src/lib/MurmurEncrypt
make test
```

29/29 tests pass, including official ASCON-128 test vectors.

<details>
<summary>Technical details</summary>

**Cipher:** [ASCON-128](https://csrc.nist.gov/pubs/sp/800/232/ipd) AEAD (NIST SP 800-232, lightweight crypto standard selected 2023)

**Key derivation:**
```
binding_phrase -> ASCON-XOF -> master_key -> ASCON-XOF -> enc_key (16B) + UID (6B)
```

**Replay protection:** 64-packet sliding window with 32-bit counter reconstructed from 8-bit OtaNonce

**Nonce construction:** counter + packet_type + direction (uplink=0, downlink=1)

**What changed from stock ELRS:**

| File | What |
|:--|:--|
| `src/lib/MurmurEncrypt/*` | Encryption module (~400 LOC, pure C) |
| `src/lib/OTA/OTA.cpp` | Encrypt/decrypt wrapping, counter tracking |
| `src/python/build_flags.py` | Auto-enable when binding phrase is set |
| `src/src/tx_main.cpp` | Init at boot, counter reset on rate change |
| `src/src/rx_main.cpp` | Init at boot, counter reset on SYNC/disconnect |

**Known limitations:**
- 14-bit MAC (forgery probability: 1/16384 per attempt)
- SYNC packets are cleartext (needed for connection establishment)
- No forward secrecy
- LCG hop sequence inherited from ELRS (see [#3](https://github.com/PotatoSpudowski/MurmurLRS/issues/3))

</details>

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

- **Flash and test** -- report what works and breaks
- **Review the crypto** -- under 500 lines of C in `src/lib/MurmurEncrypt/`
- **ESP8266/STM32 testing** -- primary dev is on ESP32

## Community

Started with a [post on r/fpv](https://www.reddit.com/r/fpv/comments/1sl5hf1/) (423+ upvotes, 155+ comments). Looking for testers.

## Changes

See [CHANGELOG.md](CHANGELOG.md).

---

Based on [ExpressLRS](https://github.com/ExpressLRS/ExpressLRS). See [README_ELRS.md](README_ELRS.md) for upstream docs.
