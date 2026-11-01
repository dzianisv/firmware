# M5Stack Cardputer ADV — Build, Flash, and Rollback Instructions

## Prerequisites

- PlatformIO Core (`pio`) installed
- M5Stack Cardputer ADV connected via USB-C (appears as `/dev/ttyUSB*` or `/dev/cu.*`)
- An owned MIFARE Classic 1K laboratory card with known keys (e.g. `FFFFFFFFFFFF`)
- Do **not** use access-control cards for development testing

## 1. Build the Firmware

From the Bruce firmware repository root:

```bash
# Build for Cardputer ADV (ST25R3916 I2C + MIFARE Classic diagnostics)
pio run -e m5stack-cardputer-adv
```

The build produces:
- `Bruce-m5stack-cardputer-adv.bin` — merged bootloader + partition table + application; flash at `0x0`
- `.pio/build/m5stack-cardputer-adv/firmware.bin` — application only; not suitable for flashing at `0x0`
- `.pio/build/m5stack-cardputer-adv/firmware.elf` — ELF with debug symbols

The CI ZIP renames the merged image to `firmware.bin` and includes `SHA256SUMS`. USB smoke tests on a physical Cardputer ADV confirmed firmware identity, runtime response, ST25R3916 initialization, tag UID reads, and known-key MIFARE block reads. Unknown-key recovery is not hardware-verified; a 55-key dictionary scan currently exhausts the card and regresses the known-key read to sector 0 only.

### Build environments available

| Env | Board | Use case |
|-----|-------|----------|
| `m5stack-cardputer` | M5Stack Cardputer (original) | No ST25R3916 support |
| `m5stack-cardputer-adv` | M5Stack Cardputer ADV | ST25R3916B I2C on Port A, MIFARE Classic diagnostics + key recovery |

## 2. Flash the Firmware

### Saved laptop automation

Run `scripts/cardputer_device.py` on the laptop with the USB-connected device, not on the build VM. Use a Python environment with `esptool` and `pyserial` installed.

```bash
# firmware.bin must be the merged image from the release ZIP or VM, not .pio's app-only image.
python3 scripts/cardputer_device.py flash --image ./firmware.bin

# Real USB serial smoke checks, ST25R3916 initialization, and a read-only tag attempt.
python3 scripts/cardputer_device.py test --rfid

# When a lab tag is present, require an actual successful tag read.
python3 scripts/cardputer_device.py test --rfid --require-tag
```

- Auto-detects one Espressif USB port; use `--port /dev/cu.usbmodem101` (or your current port) if needed.
- Flashing freezes the checked firmware bytes, backs up the full 8 MB, verifies that backup against flash, then writes and independently verifies the merged image at `0x0`. Configuration may reset. Use `--sha256 <expected digest>` to pin the image.
- `--existing-backup <backup.bin>` requires this tool's adjacent `<backup.bin>.json` manifest with a matching device MAC, SHA256, and verified flag. A same-size file alone is not sufficient. Keep the original backup and manifest together for rollback.
- Keeps private backups, logs, and JSON reports under `~/.local/state/cardputer/`; override with a **new** `--output-dir` outside the repository. Reusing an evidence directory is rejected to protect earlier backups. Backups and tag-read logs may contain credentials; keep them private.
- `test --rfid` selects the ST25R3916 I2C module (configuration value 6), probes Grove address `0x50`, and attempts `rfid read`. It never writes, clones, or erases NFC tags.
- Inspect BLOCKED checks in `test-result.json`. Exit 0 means no smoke checks failed, not that every feature was verified. Physical pixels, physical key presses, and unknown-key recovery are not verified by this tool.

### PlatformIO upload (alternative)

```bash
# Flash to Cardputer ADV (update the port as needed)
pio run -e m5stack-cardputer-adv -t upload --upload-port /dev/ttyUSB0
```

On macOS, the port is typically `/dev/cu.usbserial-*` or `/dev/cu.SLAB_USBtoUART`.

To find the port:
```bash
ls /dev/cu.* | grep -i usb
```

### First-time flash (erase flash)

If the card has never run Bruce firmware or you want a clean slate:

```bash
pio run -e m5stack-cardputer-adv -t upload --upload-port /dev/ttyUSB0
# Then in the serial monitor, erase LittleFS if needed:
# (Bruce formats LittleFS on first boot if required)
```

## 3. Serial Monitor

```bash
pio device monitor -e m5stack-cardputer-adv --port /dev/ttyUSB0 --baud 115200
```

The serial monitor shows:
- ST25R3916 initialization logs (when `ST25R_DEBUG` is enabled)
- MIFARE Classic auth results per sector
- Experimental nonce-collection logs when debugging is enabled (not proof of key recovery)

**Treat serial logs as sensitive.** `rfid read` and `rfid info` print stored card data, including authenticated keys when available. The USB tool saves these logs privately; it does not redact them.

## 4. Using the Diagnostic Mode

On the Cardputer ADV device:

1. Power on and navigate to **RFID** → **Read tag**
2. Place a MIFARE Classic 1K card on the reader
3. The card should be detected as "MIFARE Classic 1K"
4. Press **[OK]** to change mode, select **MFC Diagnostics**
5. Press **[SEL]** to start reading
6. The display shows:
   ```
   MIFARE Classic 1K
   Reading: Sector 05 / 16
   Block: 07
   Auth: OK
   Blocks: 23 / 64
   [ESC] Cancel
   ```
7. Press **[ESC]** at any time to cancel — partial results are preserved and labeled as partial
8. When complete, press **[SEL]** to show recovered keys

### Display fields

| Field | Meaning |
|-------|---------|
| Card type | MIFARE Classic 1K / 4K / Mini |
| UID | Card UID (hex) |
| Reading: Sector X / 16 | Current sector being read |
| Block: Y | Current block within sector |
| Auth: OK / Failed | Whether authentication succeeded for this sector |
| Blocks: N / 64 | Total blocks successfully read / total blocks |
| Error: Authentication / Timeout / RF Communication / Unsupported / Internal | Error classification |
| Partial — incomplete dump | Shown when not all blocks were read |

## 5. Known-Key Checks and Experimental Recovery

After diagnostics, press **[SEL]** to display keys that passed authentication. The reader tries built-in default keys and configured custom keys.

**This is not a complete darkside or nested key-recovery implementation.** The experimental fallback collects nonces and searches PRNG states, but does not derive unknown Crypto1 keys. A predicted nonce alone cannot establish that a key was recovered; a candidate must pass full authentication.

There is currently no separate key-recovery menu item. Unknown-key recovery requires a real upstream port and tests with known capture/key vectors. See `CARDPUTER_ADV_LIMITATIONS.md` for the unverified hardware behavior and cancellation limits.

## 6. Rollback to Previous Firmware

### Rollback to stock Bruce firmware

```bash
# Checkout the original main branch
git checkout main
git pull origin main

# Build and flash the original firmware
pio run -e m5stack-cardputer-adv -t upload --upload-port /dev/ttyUSB0
```

### Rollback to a specific known-good commit

```bash
git log --oneline -10
git checkout <known-good-commit>
pio run -e m5stack-cardputer-adv -t upload --upload-port /dev/ttyUSB0
```

### Save current firmware before flashing (backup)

```bash
# Read current firmware from the card
esptool.py --port /dev/ttyUSB0 read_flash 0x0 0x800000 backup_firmware.bin
```

### Restore from backup

```bash
esptool.py --port /dev/ttyUSB0 write_flash 0x0 backup_firmware.bin
```

## 7. Enabling Debug Logs

To see ST25R3916 debug logs (authentication attempts, nonce collection, etc.), enable `ST25R_DEBUG`:

In `src/modules/rfid/ST25R3916.cpp`, change:
```cpp
#define ST25R_DEBUG 0
```
to:
```cpp
#define ST25R_DEBUG 1
```

Then rebuild and flash. Debug output appears on the serial monitor at 115200 baud.

## 8. Troubleshooting

| Problem | Cause | Solution |
|---------|-------|----------|
| "RFID module not found!" | ST25R3916 not initialized | Cardputer ADV env must be used; I2C Port A pins configured |
| Card not detected | Card not on reader / antenna issue | Place card flat on the back of the Cardputer ADV |
| "Failed authenticating" | Wrong key | Use a card with known default key (FFFFFFFFFFFF) |
| Unknown-key recovery finds 0 keys | Current code does not derive unknown keys | Do not treat nonce prediction or a dictionary hit as unknown-key recovery |
| Build fails | Missing dependencies | Run `pio lib install` first, or delete `.pio` and rebuild |

## 9. File Locations

| File | Purpose |
|------|---------|
| `boards/m5stack-cardputer-adv/m5stack-cardputer-adv.ini` | PlatformIO build environment |
| `boards/m5stack-cardputer-adv/m5stack-cardputer-adv.json` | Board definition |
| `boards/m5stack-cardputer-adv/pins_arduino.h` | Pin mappings (ST25R3916 I2C on Port A) |
| `src/modules/rfid/ST25R3916.h` | ST25R3916 driver + key recovery declarations |
| `src/modules/rfid/ST25R3916.cpp` | ST25R3916 driver + key recovery implementation |
| `src/modules/rfid/tag_o_matic.h` | Tag-O-Matic UI + diagnostic mode declarations |
| `src/modules/rfid/tag_o_matic.cpp` | Tag-O-Matic UI + diagnostic mode implementation |
| `docs/nfc-existing-implementations.md` | Phase 1 repository audit |
| `docs/CARDPUTER_ADV_BUILD_FLASH.md` | This file |
