# M5Stack Cardputer ADV — Build, Flash, and Rollback Instructions

## Prerequisites

- PlatformIO Core (`pio`) installed
- M5Stack Cardputer ADV connected via USB-C (appears as `/dev/ttyUSB*` or `/dev/cu.*`)
- An owned MIFARE Classic 1K laboratory card with known keys (e.g. `FFFFFFFFFFFF`)
- Do **not** use access-control cards for development testing

## 1. Build the Firmware

From the Bruce firmware repository root:

```bash
# Build for Cardputer ADV (includes ST25R3916 I2C + MIFARE Classic diagnostics + key recovery)
pio run -e m5stack-cardputer-adv
```

The build produces:
- `.pio/build/m5stack-cardputer-adv/firmware.bin` — full firmware binary
- `.pio/build/m5stack-cardputer-adv/firmware.elf` — ELF with debug symbols

### Build environments available

| Env | Board | Use case |
|-----|-------|----------|
| `m5stack-cardputer` | M5Stack Cardputer (original) | No ST25R3916 support |
| `m5stack-cardputer-adv` | M5Stack Cardputer ADV | ST25R3916B I2C on Port A, MIFARE Classic diagnostics + key recovery |

## 2. Flash the Firmware

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
- Darkside key recovery progress (nonce collection, PRNG state recovery)
- Key recovery results

Sensitive key values are **redacted** in serial output by default (only key indices are shown, not the actual key bytes).

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

## 5. Key Recovery (Darkside Attack)

Key recovery is available from the diagnostic screen:

1. After a diagnostic read (complete or partial), press **[SEL]** to show recovered keys
2. Or navigate to **MFC Diagnostics** → the key recovery option runs automatically on all sectors
3. Recovered keys are displayed as:
   ```
   S03 A: FFFFFFFFFFFF
   S07 B: A0A1A2A3A4A5
   Total: 2 keys recovered
   ```

### How key recovery works

1. **Dictionary attack**: Tries built-in default keys (including `FFFFFFFFFFFF`) and custom keys from `/BruceRFID/keys.conf`
2. **Darkside (nested) attack**: For sectors where no dictionary key works:
   - Collects card nonces (Nt) from failed authentication attempts — the MIFARE Classic protocol leaks Nt before key verification
   - Recovers the weak 16-bit PRNG state by brute-forcing 2^16 LFSR initial states
   - Predicts the next nonce and performs a nested authentication from a bootstrapped sector (sector 0 with known key)
   - If the target sector uses the same key as the bootstrap sector, the key is recovered

**No exhaustive 48-bit brute force is performed.** Only the 2^16 PRNG state space is searched, which is trivial on the ESP32-S3.

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
| Key recovery finds 0 keys | No bootstrap sector with known key | Sector 0 must be readable with FFFFFFFFFFFF or another known key |
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
