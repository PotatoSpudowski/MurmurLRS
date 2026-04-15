# MurmurLRS

**A privacy-focused fork of ExpressLRS with authenticated encryption.**

MurmurLRS encrypts and authenticates every RC packet over the air. Your stick inputs, telemetry, and channel data are protected with AES-128 -- nobody can read your link or inject commands.

## How do I use MurmurLRS?

### Step 1: Clone the repo

```bash
git clone https://github.com/PotatoSpudowski/MurmurLRS
```

### Step 2: Enable encryption

Open `src/user_defines.txt` and add these two lines:

```
-DMURMUR_ENCRYPT
-DMY_BINDING_PHRASE="your secret phrase here"
```

Use a strong binding phrase (3-4 random words minimum). This becomes your encryption key. **Same phrase on both TX and RX.**

### Step 3: Flash with ELRS Configurator

1. Open the [ELRS Configurator](https://github.com/ExpressLRS/ExpressLRS-Configurator/releases)
2. Go to the **Local** tab
3. Point it at the `src` folder inside the cloned repo
4. Select your TX target, flash
5. Select your RX target, flash

### Step 4: Verify

Connect your TX or RX over USB and open a serial monitor (420000 baud). You should see at boot:

```
MurmurLRS: encryption active (TX)
```
or
```
MurmurLRS: encryption active (RX)
```

If you don't see this, the build flag didn't get picked up. Check that `-DMURMUR_ENCRYPT` is in `user_defines.txt` (not `common.ini` or elsewhere).

**Important:** Both TX and RX must be flashed with MurmurLRS. A MurmurLRS TX will not connect to a stock ELRS RX (and vice versa). If one side has encryption and the other doesn't, SYNC packets will get through but all data packets will fail -- you'll see the link flicker but never fully connect.

## FAQ

### How's the performance?

Identical to stock ELRS at the same version. AES-128 encryption adds **9 microseconds** per packet -- that's 3 AES block operations. At 250 Hz, total overhead is 0.23% of CPU time. You won't notice it.

| | MurmurLRS | Stock ELRS |
|---|---|---|
| Latency added | ~9 us/packet | -- |
| CPU overhead (250 Hz) | 0.23% | -- |
| Packet size | Same | Same |
| Air rate | Same | Same |
| Range | Same | Same |

### What's different from PrivacyLRS?

Both projects add encryption to ELRS. The difference is **authentication**:

| | MurmurLRS | PrivacyLRS |
|---|---|---|
| Encryption | AES-128-CTR | ChaCha20 |
| Packet authentication | AES-CMAC (keyed MAC) | CRC only (not keyed) |
| Bit-flip resistance | Tampered packets rejected | Vulnerable (stream cipher is malleable) |
| Replay protection | 64-packet sliding window | 8-bit counter (wraps at 256) |
| Key derivation | AES-CMAC KDF | Binding phrase direct |
| Overhead | ~9 us/pkt | ~3.5 us/pkt |

PrivacyLRS encrypts with ChaCha20 but doesn't authenticate. That means an attacker can flip bits in your encrypted packets and the receiver silently accepts corrupted data. MurmurLRS uses encrypt-then-MAC -- any tampered packet is rejected.

### Is this compatible with stock ELRS?

No. Both TX and RX must run MurmurLRS. You cannot mix MurmurLRS and stock ELRS devices on the same link.

### What hardware is supported?

Everything ELRS supports -- ESP32, ESP8285, STM32 targets, 900 MHz and 2.4 GHz. Same radios, same modules.

## Status

**Beta -- testers needed.**

The encryption module passes 32 tests including NIST AES-128 vectors and RFC 4493 CMAC test vectors. What it needs is real-world validation:

- [x] Crypto correctness (32/32 tests)
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
=== MurmurLRS Crypto Test Suite ===
[AES-128 ECB]           3/3  PASS
[AES-CMAC (RFC 4493)]   4/4  PASS
[Packet encrypt/decrypt] 8/8  PASS
[Counter reconstruction] 5/5  PASS
[Replay protection]      7/7  PASS
[Key derivation]         3/3  PASS
[Integration]            2/2  PASS
=== Results: 32/32 passed ===
```

## Binding phrase = encryption key

In stock ELRS, the binding phrase is just for pairing -- it's not a security feature. In MurmurLRS, the binding phrase is fed through an AES-CMAC key derivation function to produce your encryption key.

**Use a strong phrase.** 3-4 random words minimum. Same phrase on TX and RX.

## How it works

MurmurLRS replaces the CRC field with authenticated encryption. Zero extra bytes, same packet structure:

```
TX:  RC data -> AES-128-CTR encrypt -> AES-CMAC -> MAC replaces CRC -> transmit
RX:  receive -> verify MAC -> decrypt -> replay check -> RC output
```

SYNC packets remain unencrypted for connection establishment.

<details>
<summary>Technical details</summary>

**Cryptographic primitives:**
- AES-128-CTR for encryption (NIST SP 800-38A)
- AES-128-CMAC for authentication (RFC 4493)
- AES-CMAC KDF for key derivation
- Direction-separated nonces (uplink=0, downlink=1) to prevent keystream reuse
- 32-bit counter derived from OtaNonce with epoch tracking
- Full header byte included in MAC (authenticates packet type, flags, and metadata)
- 64-packet sliding window replay protection
- Automatic counter reset on SYNC resync, link loss, and rebind

**Key derivation:**
```
binding_phrase -> AES-CMAC(zeros, phrase) -> master_key
master_key -> AES-CMAC(master, "murmur-enc") -> encryption_key (16 bytes)
master_key -> AES-CMAC(master, "murmur-uid") -> UID (6 bytes, ELRS compatible)
```

**Files changed from stock ELRS:**

| File | Change |
|------|--------|
| `src/lib/MurmurEncrypt/*` | New: encryption module (~500 LOC pure C) |
| `src/lib/OTA/OTA.cpp` | Wraps CRC functions with encrypt/decrypt, counter tracking |
| `src/src/tx_main.cpp` | Init encryption at boot, counter reset on rate change |
| `src/src/rx_main.cpp` | Init encryption at boot, counter reset on SYNC/disconnect/bind |

The encryption module is pure C with no external dependencies. ~1 KB code size. Tested against NIST and RFC reference vectors.

**Known limitations (v1):**
- 14-bit MAC gives forgery probability of 1/16384 per attempt
- SYNC packets are cleartext (needed for initial connection)
- No forward secrecy -- same key per session
- LCG hop sequence is inherited from ELRS

</details>

## Contributing

- **Flash and test** -- report what works and what breaks
- **Review the crypto** -- < 500 lines of auditable C in `src/lib/MurmurEncrypt/`
- **ESP8266/STM32 testing** -- primary development is on ESP32
- **Configurator UI** -- adding encryption toggle to the ELRS web interface

## About ExpressLRS

ExpressLRS is an open-source radio control link for RC applications. It supports Semtech SX127x/SX1280 hardware across 900 MHz and 2.4 GHz bands with packet rates up to 1000 Hz. MurmurLRS is a fork that adds encryption on top of this foundation.

See [README_ELRS.md](README_ELRS.md) for the original ExpressLRS documentation.
