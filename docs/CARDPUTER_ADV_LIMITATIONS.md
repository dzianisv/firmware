# M5Stack Cardputer ADV — Remaining Limitations

## Hardware Limitations

### ST25R3916 I2C pin configuration not yet hardware-validated

The Cardputer ADV board configuration (`boards/m5stack-cardputer-adv/`) defines ST25R3916B on I2C Port A (GPIO 2 SDA / GPIO 1 SCL, address 0x50) based on the silasgubi/CardputerADV-NFC reference. However:

- **This has not been tested on actual hardware** in this environment — no Cardputer ADV device was available for validation
- The I2C bus is shared with the TCA8418 keyboard controller (0x34) on Port A — bus contention has not been tested
- The `acquireI2CBus()` HAL returns the `i2c_bus` TwoWire instance configured for GROVE_SDA/GROVE_SCL — if another peripheral has reconfigured those pins, ST25R3916 I2C communication may fail

### No physical MIFARE Classic test card available

Validation requires:
- MIFARE Classic 1K with known default key (`FFFFFFFFFFFF`)
- MIFARE Classic 1K with custom known keys
- Card with deliberately inaccessible sectors
- Card removal during reading test
- Unsupported NFC tag test

None of these tests could be executed without hardware.

## Key Recovery Limitations

### Darkside attack scope

The implemented darkside/nested attack:

1. **Requires a bootstrap sector** — at least one sector (typically sector 0) must be readable with a known key (e.g. `FFFFFFFFFFFF`) to bootstrap the nested authentication
2. **Same-key scenario** — the nested attack recovers the target sector's key when it uses the **same key** as the bootstrap sector. For sectors with different keys, the full hardnested attack (bit-by-bit key recovery) is not implemented
3. **No 48-bit brute force** — only the 2^16 PRNG state space is searched. Exhaustive 48-bit key brute force is explicitly not claimed as practical on the ESP32-S3

### Key recovery success conditions

| Scenario | Key Recovery Works? |
|----------|---------------------|
| Sector uses default key `FFFFFFFFFFFF` | Yes (dictionary attack) |
| Sector uses a known custom key | Yes (dictionary attack) |
| All sectors use same key, sector 0 known | Yes (nested same-key attack) |
| Sector uses unknown unique key | No (requires hardnested attack, not implemented) |
| Sector 0 uses unknown key | No (no bootstrap sector available) |

## Diagnostic Mode Limitations

### Error classification

| Classification | When reported |
|----------------|---------------|
| Authentication | All dictionary keys failed for sector's trailer |
| Timeout | Card re-selection failed between sectors |
| RF Communication | Block read failed after successful auth |
| Unsupported | Non-MIFARE-Classic card detected |
| Internal | Internal driver error (not currently triggered) |

### Partial read handling

- Partial reads are correctly labeled as "Partial — incomplete dump"
- Successful blocks are preserved even when the read is cancelled
- Cancelled reads are never represented as complete dumps

### UI responsiveness

- `delayWithReturn(50)` between block reads keeps the UI responsive
- `EscPress` is checked between blocks and between sectors
- Cancellation is supported at any point

## Code Review Notes

### RTTI avoidance

`dynamic_cast` is not used — `static_cast` with a `bruceConfigPins.rfidModule` guard is used instead, since Arduino-ESP32 may compile with `-fno-rtti`.

### Memory usage

- `MfcNonceSample[256]` array: ~3KB (256 × (4+1+1+padding))
- `MifareClassicDump`: ~16KB (blocks[256][16] + key arrays)
- Total additional RAM: ~20KB — acceptable on ESP32-S3 with 320KB+ SRAM

### RFAL fork dependency

The ST25R3916 driver depends on two pinned RFAL forks:
- `lewisxhe/ST25R3916-fork#0c8e00f49d12881d1cff6d6f0879b90ce7ed4033`
- `lewisxhe/NFC-RFAL-fork#7bde4587ea44c36c178a43d083d7a7345c1e4cfe`

These are already used by Bruce's existing ST25R3916 driver — no new dependencies introduced.

## Files Changed

| File | Change |
|------|--------|
| `platformio.ini` | Added `m5stack-cardputer-adv` to default_envs |
| `boards/m5stack-cardputer-adv/m5stack-cardputer-adv.ini` | NEW — PlatformIO build environment |
| `boards/m5stack-cardputer-adv/m5stack-cardputer-adv.json` | NEW — Board definition |
| `boards/m5stack-cardputer-adv/pins_arduino.h` | NEW — Pin mappings (ST25R3916 I2C Port A) |
| `src/modules/rfid/ST25R3916.h` | Added key recovery declarations + public wrapper methods |
| `src/modules/rfid/ST25R3916.cpp` | Added darkside key recovery implementation (~250 lines) |
| `src/modules/rfid/tag_o_matic.h` | Added DIAG_MODE state + diagnostic method declarations |
| `src/modules/rfid/tag_o_matic.cpp` | Added diagnostic mode implementation (~400 lines) |
| `docs/nfc-existing-implementations.md` | Phase 1 repository audit (pre-existing) |
| `docs/CARDPUTER_ADV_BUILD_FLASH.md` | NEW — Build, flash, rollback instructions |
| `docs/CARDPUTER_ADV_LIMITATIONS.md` | NEW — This file |

## Future Work

1. **Hardware validation** — Test on actual Cardputer ADV with ST25R3916B
2. **Hardnested attack** — Implement bit-by-bit key recovery for sectors with unique unknown keys
3. **I2C bus contention testing** — Verify ST25R3916B coexists with TCA8418 on shared Port A
4. **Serial diagnostics with redaction** — Add optional serial output with key redaction (currently keys are not printed to serial at all)
5. **Test card matrix** — Validate against all card types listed in Phase 5 of the task
