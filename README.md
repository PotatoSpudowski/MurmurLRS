# MurmurLRS

[![Crypto Tests](https://img.shields.io/badge/crypto%20tests-29%2F29%20pass-brightgreen?style=flat-square)](src/lib/MurmurEncrypt/)
[![ASCON-128](https://img.shields.io/badge/ASCON--128%20AEAD-NIST%20SP%20800--232-blue?style=flat-square)](https://csrc.nist.gov/pubs/sp/800/232/ipd)
[![Reddit](https://img.shields.io/badge/r%2Ffpv-423%2B%20upvotes-orange?style=flat-square&logo=reddit)](https://www.reddit.com/r/fpv/comments/1sl5hf1/)
[![License](https://img.shields.io/github/license/PotatoSpudowski/MurmurLRS?style=flat-square)](https://github.com/PotatoSpudowski/MurmurLRS/blob/master/LICENSE)

**A privacy-focused fork of ExpressLRS with authenticated encryption.**

MurmurLRS encrypts and authenticates every RC packet over the air. Your stick inputs, telemetry, and channel data are protected with ASCON-128 -- nobody can read your link or inject commands.

## How do I use MurmurLRS?

### Step 1: Clone the repo

```bash
git clone https://github.com/PotatoSpudowski/MurmurLRS
```

### Step 2: Flash with ELRS Configurator

1. Open the [ELRS Configurator](https://github.com/ExpressLRS/ExpressLRS-Configurator/releases)
2. Go to the **Local** tab
3. Point it at the `src` folder inside the cloned repo
4. **Set your binding phrase** as you normally would. Use a strong phrase (3-4 random words minimum). **Same phrase on both TX and RX.**
5. Select your TX target, flash
6. Select your RX target, flash

That's it. Encryption is automatically enabled when a binding phrase is set. No extra flags or config files needed -- the build system detects the binding phrase and activates MurmurLRS encryption. In the build log you'll see:

```
MurmurLRS: encryption enabled
```

### Step 3: Verify

Connect your TX or RX over USB and open a serial monitor (420000 baud). You should see at boot:

```
MurmurLRS: encryption active (TX)
```
or
```
MurmurLRS: encryption active (RX)
```

If you don't see this, make sure your binding phrase is set in the Configurator and that you're building from the MurmurLRS source (Local tab), not from stock ELRS.

**Important:** Both TX and RX must be flashed with MurmurLRS. A MurmurLRS TX will not connect to a stock ELRS RX (and vice versa). If one side has encryption and the other doesn't, SYNC packets will get through but all data packets will fail -- you'll see the link flicker but never fully connect.

## FAQ

### How's the performance?

Identical to stock ELRS at the same version. MurmurLRS uses [ASCON-128](https://csrc.nist.gov/pubs/sp/800/232/ipd), the NIST lightweight cryptography standard (SP 800-232), selected in 2023 specifically for resource-constrained devices. It does authenticated encryption in a single pass -- no separate encrypt and MAC steps.

Benchmarked on ESP32 at 240 MHz, 10,000 iterations per measurement:

| Implementation        | Packet4 (6B) | Packet8 (10B) | Notes                                    |
| :-------------------- | :----------- | :------------ | :--------------------------------------- |
| AES-128 CTR+CMAC (SW) | ~94 us/pkt  | ~94 us/pkt    | Software AES, 3 block ops + key expansion per call |
| AES-128 CTR+CMAC (HW) | ~34 us/pkt  | ~34 us/pkt    | ESP32 hardware AES accelerator via mbedTLS |
| ChaCha20 (encrypt-only) | ~24 us/pkt | ~25 us/pkt   | No authentication, no MAC (PrivacyLRS approach) |
| **ASCON-128 AEAD**    | **~22 us/pkt** | **~26 us/pkt** | **Pure software, single-pass AEAD**     |

ASCON-128 is 3.5-4.3x faster than software AES and still ~35% faster than hardware-accelerated AES on ESP32. And since ASCON is pure software with no hardware dependencies, it runs at the same speed on ESP8285 and STM32 targets that lack AES acceleration.

Notable: ChaCha20 encrypt-only (no authentication) clocks in at ~24 us/pkt. ASCON-128 does full authenticated encryption at ~22 us/pkt for small packets. So ASCON with authentication is the same speed or faster than ChaCha20 without it.

At 500 Hz, ASCON adds 1.3% CPU overhead. At 250 Hz, 0.6%. You won't notice it.

| Feature              | MurmurLRS      | Stock ELRS |
| :------------------- | :------------- | :--------- |
| Latency added        | ~22-26 us/pkt  | --         |
| CPU overhead (500Hz) | 1.3%           | --         |
| Packet size          | Same           | Same       |
| Air rate             | Same           | Same       |
| Range                | Same           | Same       |

### Why ASCON over AES?

[ASCON](https://csrc.nist.gov/pubs/sp/800/232/ipd) was selected by NIST in 2023 as the standard for lightweight cryptography after a multi-year competition. It was designed from the ground up for exactly this use case: authenticated encryption on microcontrollers with tight CPU and memory budgets.

The previous MurmurLRS implementation used AES-128-CTR for encryption and AES-128-CMAC for authentication as separate steps (encrypt-then-MAC). This worked correctly but had two downsides:

1. **Performance**: Three separate AES block operations per packet, each requiring a full key schedule expansion. Software AES measured ~94 us/pkt -- 10x slower than originally estimated.
2. **Complexity**: Manually composing CTR mode encryption with CMAC authentication is an error-prone pattern. ASCON does both in a single AEAD call, eliminating composition bugs by construction.

ASCON-128 provides the same security guarantees (128-bit key, authenticated encryption, replay protection) in a single-pass sponge construction with no key schedule overhead.

### What's different from PrivacyLRS?

Both projects add encryption to ELRS. The difference is **authentication**:

| Feature               | MurmurLRS                 | PrivacyLRS                               |
| :-------------------- | :------------------------ | :--------------------------------------- |
| Encryption            | ASCON-128 AEAD            | ChaCha20                                 |
| Packet authentication | ASCON-128 AEAD (keyed)    | CRC only (not keyed)                     |
| Bit-flip resistance   | Tampered packets rejected | Vulnerable (stream cipher is malleable)  |
| Replay protection     | 64-packet sliding window  | 8-bit counter (wraps at 256)             |
| Key derivation        | ASCON-XOF KDF             | Binding phrase direct                    |
| Overhead              | ~22 us/pkt (full AEAD)    | ~24 us/pkt (encrypt-only)                |

Both projects add encryption to ELRS. PrivacyLRS uses ChaCha20 for encryption, MurmurLRS uses [ASCON-128 AEAD](https://csrc.nist.gov/pubs/sp/800/232/ipd) which combines encryption and authentication in a single pass. The main difference is that MurmurLRS authenticates every packet, so tampered or injected packets are rejected rather than silently accepted.

### Is this compatible with stock ELRS?

No. Both TX and RX must run MurmurLRS. You cannot mix MurmurLRS and stock ELRS devices on the same link.

### What hardware is supported?

Everything ELRS supports -- ESP32, ESP8285, STM32 targets, 900 MHz and 2.4 GHz. Same radios, same modules.

## Status

**Beta -- testers needed.**

The encryption module passes its test suite including official ASCON-128 vectors. What it needs is real-world validation:

- [x] Crypto correctness
- [x] Zero packet overhead (same air rate, same packet size)
- [ ] Over-the-air TX/RX encrypted link test
- [ ] Range testing (should be identical to stock)
- [ ] Failsafe behavior under encryption
- [ ] Rate switching / reconnection
- [ ] ESP8266 and STM32 target testing

**Set failsafe on your flight controller. Bench test before flying.**

### Run the test suite

```
cd src/lib/MurmurEncrypt
make test
```

```
=== MurmurLRS Crypto Test Suite (ASCON) ===
[ASCON-128 AEAD]        2/2  PASS
[ASCON-XOF]             2/2  PASS
[Packet encrypt/decrypt] 8/8  PASS
[Counter reconstruction] 5/5  PASS
[Replay protection]      7/7  PASS
[Key derivation]         3/3  PASS
[Integration]            2/2  PASS
=== Results: 29/29 passed ===
```

## Binding phrase = encryption key

In stock ELRS, the binding phrase is just for pairing -- it's not a security feature. In MurmurLRS, the binding phrase is fed through an ASCON-XOF key derivation function to produce your encryption key.

**Use a strong phrase.** 3-4 random words minimum. Same phrase on TX and RX.

## How it works

MurmurLRS replaces the CRC field with authenticated encryption. Zero extra bytes, same packet structure:

```
TX:  RC data -> ASCON-128 AEAD -> MAC replaces CRC -> transmit
RX:  receive -> verify MAC -> decrypt -> replay check -> RC output
```

SYNC packets remain unencrypted for connection establishment.

<details>
<summary>Technical details</summary>

**Cryptographic primitives:**
- [ASCON-128](https://csrc.nist.gov/pubs/sp/800/232/ipd) AEAD for encryption and authentication (NIST SP 800-232)
- ASCON-XOF for key derivation (NIST SP 800-232)
- Direction-separated nonces (uplink=0, downlink=1) to prevent keystream reuse
- 32-bit counter derived from OtaNonce with epoch tracking
- Counter, packet type, and direction bound via nonce (authenticated through ASCON initialization)
- 64-packet sliding window replay protection
- Automatic counter reset on SYNC resync, link loss, and rebind

**Key derivation:**
```
binding_phrase -> ASCON-XOF(phrase) -> master_key
master_key -> ASCON-XOF(master) -> encryption_key (16 bytes) + UID (6 bytes, ELRS compatible)
```

**Files changed from stock ELRS:**

| File                        | Change                                                         |
| :-------------------------- | :------------------------------------------------------------- |
| `src/lib/MurmurEncrypt/*`   | New: encryption module (~400 LOC pure C)                       |
| `src/lib/OTA/OTA.cpp`       | Wraps CRC functions with encrypt/decrypt, counter tracking     |
| `src/python/build_flags.py` | Auto-enable encryption when binding phrase is set              |
| `src/src/tx_main.cpp`       | Init encryption at boot, counter reset on rate change          |
| `src/src/rx_main.cpp`       | Init encryption at boot, counter reset on SYNC/disconnect/bind |

The encryption module is pure C with no external dependencies. ~1 KB code size. Tested against official ASCON vectors.

**Known limitations (v1):**
- 14-bit MAC gives forgery probability of 1/16384 per attempt
- SYNC packets are cleartext (needed for initial connection)
- No forward secrecy -- same key per session
- LCG hop sequence is inherited from ELRS

</details>

## Community

This project started with a [post on r/fpv](https://www.reddit.com/r/fpv/comments/1sl5hf1/) that hit #1 for the day (423+ upvotes, 155+ comments). The thread has detailed discussion on the crypto design, performance tradeoffs, and comparisons with stock ELRS.

Looking for people willing to bench test or fly with it, especially on ESP8266 and STM32 targets. You flash through the normal ELRS Configurator using the Local tab -- same workflow you're used to.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for details on testing, code changes, and syncing with upstream.

Quick ways to help:
- **Flash and test** -- report what works and what breaks
- **Review the crypto** -- < 500 lines of auditable C in `src/lib/MurmurEncrypt/`
- **ESP8266/STM32 testing** -- primary development is on ESP32

## Recent changes

### v0.5.1 (2026-04-20)
- Synced with upstream ExpressLRS (up to 87d2d4d3)
- Fix screen joystick broken by MSP bind phrase changes

### v0.5 (2026-04-16)
- Replaced AES-128-CTR + AES-CMAC with ASCON-128 AEAD ([NIST SP 800-232](https://csrc.nist.gov/pubs/sp/800/232/ipd))
- Single-pass authenticated encryption: 3.5-4.3x faster than software AES

See [CHANGELOG.md](CHANGELOG.md) for the full history.

## About ExpressLRS

ExpressLRS is an open-source radio control link for RC applications. It supports Semtech SX127x/SX1280 hardware across 900 MHz and 2.4 GHz bands with packet rates up to 1000 Hz. MurmurLRS is a fork that adds encryption on top of this foundation.

See [README_ELRS.md](README_ELRS.md) for the original ExpressLRS documentation.
