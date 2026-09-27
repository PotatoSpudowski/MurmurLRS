# Two-board T3-S3 LR1121 bench test

These profiles target the **non-PA LilyGO T3-S3 LR1121 V1.2/V1.3**, one LR1121 per board. They are experimental and have not yet been exercised on physical boards. They are not for the LR1121 PA version, T-Beam, or T-LoRa Dual. Verify the silkscreen before flashing.

The first test uses **2.4 GHz only, 10 mW**, with no Gemini or sub-GHz modes exposed. One board is TX and one RX. No vehicle, motors, or propellers are needed. Connect the separate 2.4 GHz antenna on the radio module before powering either board; the sub-GHz SMA antenna is not a substitute. Start several metres apart.

## Hardware profile

The shared [JSON profile](../src/board_profiles/lilygo_t3s3_lr1121.json) uses SPI SCK/MISO/MOSI 5/3/6, NSS 7, reset 8, busy 34, and DIO9 interrupt 36. UART RX/TX are GPIO44/43. LED is GPIO37 and BOOT is GPIO0. There is no second radio, external PA, display driver, or PSRAM dependency in this profile.

The LR1121 RF-switch bytes are `[3, 0, 1, 2, 2, 0, 0, 0]`: DIO5/DIO6 enable mask, standby, RX, TX, TX high-power, TX high-frequency, unused, high-frequency RX. TCXO voltage code 6 selects 3.0 V; 164 ticks at approximately 30.52 microseconds provide about 5 ms startup time. The power table contains only the direct 10 dBm high-frequency setting. Actual RF output is not calibrated by this profile.

Sources: [LilyGO hardware notes](https://github.com/Xinyuan-LilyGO/LilyGo-LoRa-Series/blob/master/docs/en/t3_s3_lr1121/t3_s3_lr1121_hw.md), [LilyGO factory RF-switch/TCXO setup](https://github.com/Xinyuan-LilyGO/LilyGo-LoRa-Series/blob/master/examples/T3S3Factory/T3S3Factory.ino), and [RadioLib TCXO encoding](https://github.com/jgromes/RadioLib/blob/master/src/modules/LR11x0/LR11x0.cpp). The profile is stored outside the downloaded `src/hardware` directory so target refreshes cannot overwrite it.

## Build before connecting

From the repository root, with PlatformIO installed in `venv`:

```sh
export MURMUR_BINDING_PHRASE='replace-with-your-own-bench-phrase'
# Optional: transmit without a handset. Bench only; this does not generate a stick sweep.
export MURMUR_BENCH_FREERUN=1
cd src
../venv/bin/pio run -e Murmur_LilyGO_T3S3_LR1121_TX_via_UART
../venv/bin/pio run -e Murmur_LilyGO_T3S3_LR1121_RX_via_UART
```

Run PlatformIO builds/tests sequentially in one checkout. Both targets explicitly enable encryption, use a 4 MB flash layout, and attach the profile and same phrase-derived UID to the binary. The build prints `Murmur bench: attached T3-S3 LR1121 ... profile`. The phrase is not printed. CI uses a public test phrase solely for compile checks.

The regulatory flags enable the existing 2.4 GHz CE/LBT code path. A sub-GHz domain is also required by the LR1121 build script, but the absent primary power table excludes sub-GHz rates. This is a bench configuration, not a regulatory certification. Do not add an empty `power_values` array: the power code expects an absent table to be a null pointer.

## First upload

Connect **one board at a time**, identify its port with `../venv/bin/pio device list`, and label it TX or RX. Keep the phrase and free-run environment variables set in this shell. Upload with the appropriate role:

```sh
../venv/bin/pio run -e Murmur_LilyGO_T3S3_LR1121_TX_via_UART -t upload --upload-port /dev/cu.YOUR_TX_PORT
../venv/bin/pio run -e Murmur_LilyGO_T3S3_LR1121_RX_via_UART -t upload --upload-port /dev/cu.YOUR_RX_PORT
```

If the bootloader does not enumerate, hold BOOT, tap RESET, release BOOT, then retry. Do not manually flash the application binary at address zero; PlatformIO supplies the bootloader, partition table, and application offsets.

The ELRS LR1121 driver can update the radio chip's own firmware on first startup. Leave power connected during initialization. A previous ELRS configuration can override compiled options: reset saved configuration through the device Web UI before comparing results if these boards were used with ELRS previously. Save any configuration you need first.

## Observe the link

Free-run starts RF without a handset. For changing RC inputs, rebuild TX after `unset MURMUR_BENCH_FREERUN` and supply CRSF using a handset or a 3.3 V UART test source on GPIO44 (RX), GPIO43 (TX), and common ground. This bench profile uses a full-duplex UART; do not wire a half-duplex module-bay signal blindly.

To verify delivered channels, capture the receiver's CRSF output from GPIO43 with a 3.3 V USB/UART adapter at 420000 baud or a flight controller. Two boards alone can exercise acquisition/reconnection; they do not provide an independent measurement of channel delivery or latency. USB-C on the RX is not configured here as a CRSF output port. A logic analyser is useful but optional.

Automatic WiFi entry is disabled in the bench image so a disconnected soak does not switch to WiFi after a minute. Enter WiFi using the configured BOOT/button action if needed; WiFi mode stops normal RF operation. Neither USB enumeration nor a successful flash proves a working encrypted link.

## Acceptance record

Record the commit, board revisions, antennas, power supplies, build flags, packet rate, telemetry ratio, reset order, and observed output. Attach UART captures when available.

- [ ] TX and RX initialize their LR1121 successfully; no reset loop.
- [ ] Cold boot both, then independently boot TX first and RX first.
- [ ] Verify changing channels at RX, not only a connected LED.
- [ ] Run continuously for at least 30 minutes; record any gaps/reboots.
- [ ] Reboot RX after TX has run 1, 5, and 15 minutes; measure reacquisition time. This specifically checks the bounded production epoch scan.
- [ ] Reboot TX with RX still running; verify recovery and output behavior.
- [ ] Interrupt the link, check failsafe at the output, then restore it.
- [ ] Try supported 2.4 GHz rates and telemetry ratios; record any rate-change failure.
- [ ] Rebuild one endpoint with a different phrase; verify no RC/data acceptance. Restore the matching phrase afterward.

Do not mark replay resistance, timing limits, or nonce uniqueness as proven by these checks. Replay injection needs a controlled packet injector, and session/nonce security still needs a protocol fix. Single-radio boards cannot validate Gemini, simultaneous dual-band operation, relay mode, or a multi-RX swarm.
