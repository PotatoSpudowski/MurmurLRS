# Contributing to MurmurLRS

MurmurLRS is a privacy-focused fork of ExpressLRS. Contributions are welcome -- whether that's testing on hardware, reviewing crypto, fixing bugs, or improving docs.

## Getting started

1. Fork the repo and clone it
2. Create a branch from `master`
3. Make your changes
4. Open a pull request against `master`

## Ways to contribute

### Flash and test

The most valuable contribution right now is real-world testing. Flash MurmurLRS on your hardware and report what works and what breaks.

**What to test:**
- TX/RX link establishment and stability
- Rate switching and reconnection
- Failsafe behavior under encryption
- Range (should be identical to stock ELRS)
- Different hardware targets (ESP32, ESP32-S3, ESP32-C3, ESP8285)
- 900 MHz and 2.4 GHz

**How to report:** Open an issue with your hardware, firmware version, what you tested, and what happened.

### Review the crypto

The encryption module is under 500 lines of auditable C in `src/lib/MurmurEncrypt/`. If you have cryptography experience, review the ASCON-128 AEAD integration, nonce construction, replay protection, and key derivation.

### Code changes

**Before writing code:**
- Check existing issues to avoid duplicate work
- For larger changes, open an issue first to discuss the approach

**Code style:**
- Follow the existing ELRS code style
- Keep changes minimal and focused -- one concern per PR
- Don't refactor surrounding code in a bug fix PR

**Encryption module (`src/lib/MurmurEncrypt/`):**
- Pure C, no external dependencies
- Any changes must pass the existing test suite: `cd src/lib/MurmurEncrypt && make test`
- Add tests for new functionality
- Document security-relevant design decisions in comments

### Build system

- MurmurLRS uses the standard ELRS build via PlatformIO and ELRS Configurator
- Encryption is auto-enabled in `src/python/build_flags.py` when a binding phrase is set
- Don't break the stock ELRS build path -- MurmurLRS code must be behind `#if defined(MURMUR_ENCRYPT)` guards

## Running tests

### Crypto test suite

```bash
cd src/lib/MurmurEncrypt
make test
```

### PlatformIO tests

```bash
cd src
pio test -e native
```

## Syncing with upstream ExpressLRS

MurmurLRS tracks upstream ExpressLRS. When merging upstream changes:

1. Fetch upstream: `git fetch upstream master`
2. Merge: `git merge upstream/master`
3. Resolve conflicts -- our `MURMUR_ENCRYPT` blocks must be preserved
4. Verify no stale function references (upstream renames happen)
5. Run the crypto test suite
6. Check that all `MURMUR_ENCRYPT` guards are balanced

## What lives where

| Path | What it is |
| :--- | :--------- |
| `src/lib/MurmurEncrypt/` | ASCON-128 AEAD library and Murmur encryption wrapper |
| `src/lib/OTA/OTA.cpp` | CRC-to-encryption hook, counter tracking |
| `src/python/build_flags.py` | Auto-enable encryption flag |
| `src/src/tx_main.cpp` | TX-side init and counter reset |
| `src/src/rx_main.cpp` | RX-side init and counter reset |

## Reporting security issues

If you find a security vulnerability in the encryption layer, please open an issue. MurmurLRS is pre-release beta software and benefits from public scrutiny.

## License

By contributing, you agree that your contributions will be licensed under the same license as the project (GPL-3.0).
