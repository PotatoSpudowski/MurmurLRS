# Changelog

All notable changes to MurmurLRS are documented here.

## v0.6 (2026-05-01)

### Encryption fixes

- Fix OTA4 authentication failure: header byte contamination from crcHigh bits caused every OTA4 packet MAC to fail. OTA4 now uses only packet type bits (2-bit) as AEAD associated data. OTA8 continues to authenticate the full header byte.
- Fix epoch desync: TX and RX could permanently lose sync if TX had been running longer than RX (epoch drift). TX nonce space is now monotonic (never resets epoch). RX enters acquisition mode after SYNC — searches epoch 0-255 with 3-packet confirmation before locking in. No weakening of authentication.
- 3 new OTA header-as-AD tests (32/32 total)

### Upstream sync

- Synced with upstream ExpressLRS (up to cf582b1b)
- Separate FIFO locations for TX & RX on SX1280 (upstream PR #3620)
- Reject unsupported rate switch from SYNC packet instead of crashing (upstream PR #3610)
- Feature flag optimisation for web UI size reduction (upstream PR #3606)
- VTX admin visibility fix (upstream PR #3608)
- Web UI improvements: save button fixes, hardware page float support, lazy loading, reduced asset size, favicons

## v0.5.1 (2026-04-20)

- Synced with upstream ExpressLRS (up to 87d2d4d3)
- Fix screen joystick broken by MSP bind phrase changes (upstream PR #3614)

## v0.5 (2026-04-16)

- Synced with upstream ExpressLRS (up to 34a68884)
- MSP bind phrase support -- configure binding phrase over MSP without rebuilding firmware
- Dynamic power management improvements (flight-tested mean - 1sd for power-down)
- CRSF int16/int32 parameter types
- DCDC logging for LR1121 and SX1280 drivers
- WiFi WebUI password revealer
- elrs.lua folder/sub-folder improvements
- GitHub CI deprecation fixes
- Autoupload safety gate (requires explicit opt-in)
- Vite build fixes for Windows
- Vite dev server proxy plugin

## v0.4 (2026-04-16)

- Replaced AES-128-CTR + AES-CMAC with ASCON-128 AEAD ([NIST SP 800-232](https://csrc.nist.gov/pubs/sp/800/232/ipd))
- Single-pass authenticated encryption: 3.5-4.3x faster than software AES, ~35% faster than hardware-accelerated AES
- ASCON-XOF key derivation replaces AES-CMAC KDF
- Benchmarked on ESP32 at 240 MHz: ~22 us/pkt (Packet4), ~26 us/pkt (Packet8)
- 29/29 crypto tests including official ASCON-128 vectors

## v0.3 (2025-04-15)

- Encryption now auto-enables when a binding phrase is set -- no manual flags needed
- Synced with upstream ExpressLRS (up to 6cd45f56)
- Added community section and badges to README

## v0.2 (2025-04-14)

- Fixed counter desync: counter now derived from OtaNonce with epoch tracking
- Added direction-separated nonces (uplink=0, downlink=1) to prevent keystream reuse
- Full header byte authenticated in MAC (not just 2-bit packet type)
- Added MurmurResetCounter() at all connection lifecycle points (SYNC resync, link loss, rebind, rate change)
- 32/32 crypto tests (added direction validation tests)

## v0.1 (2025-04-13)

- Initial release: AES-128-CTR encryption + AES-128-CMAC authentication
- Zero packet overhead (MAC replaces CRC field)
- 64-packet sliding window replay protection
- AES-CMAC key derivation from binding phrase
- 30/30 crypto tests including NIST and RFC reference vectors
