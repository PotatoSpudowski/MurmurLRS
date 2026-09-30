# Changelog

All notable changes to MurmurLRS are documented here.

## Unreleased

- Add a private TX/RX pair builder with explicit board profiles, isolated source checkout, restricted output permissions, matching Lua script, and revision/checksum manifest. Add packaging regressions to CI and document source-release policy.
- Secure the Wi-Fi maintenance interface separately from the encrypted TX/RX radio link. Previously, unauthenticated firmware downloads could expose the compiled packet key; encrypted builds now block firmware export.
- Require a separate build-time management password for the protected device hotspot and HTTP Basic login (`admin`). Authenticate requests before upload/configuration bodies reach their handlers, reject cross-origin requests, and disable home-network management and unauthenticated TCP/MSP and UDP joystick services.
- Leave Wi-Fi management off unless `MURMUR_WIFI_PASSWORD` is provisioned; wired flashing remains available. The management password is separate from the binding phrase. This protects network access, but does not add HTTPS, firmware signing, or protection against physical flash extraction. Preserve stock-build behavior and add management/provisioning regressions.
- Fix encrypted 2.4 GHz hopping between SX128x receivers and LR1121/LR2021 transmitters by assigning FHSS domain IDs by RF band rather than primary/secondary slot (`1766c1b8`).
- Add opt-in receiver authentication, epoch, session, and validation-time diagnostics through a read-only CRSF info field. Refresh the snapshot on the first parameter chunk; omit instrumentation from normal builds (`fcc517e5`).
- Exercise diagnostics in encrypted CI alongside the normal OTA tests (`1494c204`); the suite now includes 52 tests normally, 53 with diagnostics.
- Clarify telemetry requirements for authenticated sessions.

- Integrated the HMAC-SHA-256/HKDF session protocol into TX/RX, with boot-seeded challenges, directional traffic keys, bounded ISR mailboxes, and retry/reboot recovery. Application traffic waits for confirmation; hardware validation remains separate from host tests and build checks.
- Preserve replay history across rate/connection changes, separate outgoing counters from receive synchronization, and stop traffic before counter exhaustion.
- Require bidirectional telemetry in encrypted mode and add recovery-adapter and production OTA integration tests.

- Derive firmware encryption keys from the complete build-time phrase rather than the six-byte ELRS UID. Both endpoints must be rebuilt; older encrypted firmware is incompatible.
- Require a nonempty phrase for encrypted builds and keep generated key material out of compiler flags and build logs.
- Track TX counter wraps on timer ticks, including periods with no transmitted packets.
- Advance the TX epoch on rate/binding resets to avoid reusing counters within a running session. Session keys now change on authenticated boot/recovery handshakes, subject to fresh hardware entropy.
- Reject repeated acquisition evidence and retain replay protection for acquisition packets through lock and relock.
- Continue bounded acquisition searches beyond epoch 255 so late joins can find long-running transmitters.
- Add CI tests against the production encrypted OTA hooks and build-time key provisioning.

- Fixed the duplicate `MurmurTrackNonce` definition that prevented encrypted firmware builds (#17).
- Restored ESP8285 TX EEPROM initialization and separate backpack/USB UARTs on classic ESP32.
- Added a dedicated CI workflow for crypto tests, production OTA/session tests, sanitizers, provisioning tests, and seven explicitly encrypted firmware builds.
- Added experimental non-PA LilyGO T3-S3 LR1121 TX/RX bench targets, a checked-in 2.4 GHz hardware profile, and an optional TX free-run mode.
- Documented the ExpressLRS 4.1.0-derived upstream base (#18), actual UID-based key derivation, short authentication tags, and session/nonce limitations.

## v0.8 (2026-05-17)

### Fix: link dies after 5 minutes at 500Hz

Bug reported by community tester: LQ drops to 0-2 after ~131 seconds at 500Hz. Root cause: 8-bit epoch masking in acquisition mode. After 65536 packets (131s at 500Hz), `murmur_nonce_epoch` exceeds 255. Acquisition searched `epoch & 0xFF`, so it could never find the correct counter.

- **32-bit epoch acquisition**: Removed `& 0xFF` mask. Acquisition state (`acquire_epoch`, `acquire_scan_pos`) widened to `uint32_t`.
- **Outward-spiral locked search**: Replaced linear ±256 search with outward spiral (±1, ±2, ... ±4 epochs). Eliminates MAC false-positive ordering issues.
- **Nonce-1 epoch boundary fix**: When `nonce=0`, `nonce-1=255` correctly uses the previous epoch for decryption.
- **Acquisition threshold gate**: Acquisition no longer returns `true` on single MAC hits. Requires 3 consecutive same-epoch matches before passing packets upward.
- **MurmurTrackNonce**: ISR hook on OtaNonce++ keeps RX epoch synchronized during RF dropout, preventing multi-epoch drift on signal recovery.
- **TX reboot recovery (scan wrap)**: If acquisition scans 256 epochs forward without locking, wraps scan position to 0. Handles TX reboot while RX was at high epoch.
- **MurmurResetCounter resets epoch to 0**: Handles TX reboot on full disconnect path.
- 50 total tests (32 crypto + 10 acquisition + 8 epoch overflow regression)

## v0.7 (2026-05-10)

### Epoch acquisition state machine

Fixes the "timing" bug where TX and RX only connect if powered on within ~1 second of each other. Previously, if TX had been running longer than RX, the RX could never find the correct encryption epoch.

- **Sliding window epoch search**: RX scans 16 epochs per received packet, sliding forward on each miss. Finds any epoch within 16 packets worst-case (~32ms at 500Hz).
- **Nonce-1 tolerance**: Acquisition accepts nonce or nonce-1 to handle ±1 drift during PFD phase-lock convergence.
- **Consecutive-hit requirement**: 3 consecutive matches at the same epoch required to lock. Misses reset the count (prevents non-consecutive false hits from accumulating).
- **Lock fallback**: If locked RX gets 16 consecutive decryption failures (TX rebooted at different epoch), drops back to acquisition instead of staying permanently stuck.
- **MurmurSyncNonce**: SYNC packets in tentative state re-sync the nonce without resetting acquisition progress. Only a full disconnect triggers MurmurResetCounter.
- ISR-safe: bounded to 32 decrypt attempts per packet (~0.7ms worst case at 500Hz)
- 9 new acquisition mode tests (41/41 total)

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
