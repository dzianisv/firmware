# NFC / MIFARE Classic / ST25R3916 Existing-Implementation Audit

**Task:** Phase 1 — Improve MIFARE Classic 1K diagnostics and authenticated sector reading on the M5Stack Cardputer ADV using its existing ST25R3916 NFC module (Bruce firmware).

**Primary rule:** Do not reinvent the wheel. Find and evaluate existing implementations before writing code. Reuse order: (1) fix existing Bruce implementation, (2) reuse compatible ST25R3916 components, (3) adapt driver only if defective, (4) new low-level code only when nothing suitable exists.

**Note on history:** All reference repos were cloned `--depth 1`, so only the latest commit (HEAD) is available; full commit/branch/PR history beyond HEAD is not visible in this audit.

---

## 1. BruceDevices/firmware — TARGET (the code being improved)

| Field | Value |
|-------|-------|
| URL | https://github.com/BruceDevices/firmware |
| HEAD commit | `a59213f` "fix(headless): don't block boot forever waiting for USB CDC host (#2861)" (2026-09-10) |
| Branch | `main` (single branch, no tags) |
| License | GNU Affero GPL v3 |
| Build env for Cardputer | `m5stack-cardputer` (platformio.ini), board = `m5stack-cardputer` (variant `pinouts`, URL `docs.m5stack.com/en/core/StampS3`) |

### 1.1 Relevant source files

All under `src/modules/rfid/` and `src/core/`:

| File | Role |
|------|------|
| `ST25R3916.h` / `ST25R3916.cpp` | ST25R3916 driver over RFAL fork. Contains **Milestone 5 MIFARE Classic (1K/4K/Mini)**, Crypto1, key-dictionary sector auth, block read/write, Flipper `.mfd` save. |
| `crypto1.h` / `crypto1.cpp` | Software Crypto1 stream cipher used by the ST25R3916 driver (RFAL fork has no native Crypto1). |
| `RFIDInterface.h` / `RFIDInterface.cpp` | Common RFID interface. Defines `ReturnCode {SUCCESS, FAILURE, TAG_NOT_PRESENT, TAG_NOT_MATCH, TAG_AUTH_ERROR, NOT_IMPLEMENTED}` and the builtin 15-entry MIFARE key dictionary. `statusMessage(FAILURE)` returns **"Failed reading data blocks"**; `statusMessage(TAG_AUTH_ERROR)` returns **"Failed authenticating"**. |
| `tag_o_matic.h` / `tag_o_matic.cpp` | Tag-O-Matic UI (read/scan/clone/write/emulate). `read_card()` calls `_rfid->read()` and `dump_card_details()` prints `statusMessage(pageReadStatus)` when read fails. |
| `mifare_keys_manager.h` / `mifare_keys_manager.cpp` | Custom MIFARE key dictionary persisted to `/BruceRFID/keys.conf` (SD + LittleFS). Default seeds: `FFFFFFFFFFFF`, `A0A1A2A3A4A5`, `D3F7D3F7D3F7`. |
| `RFIDMenu.h` / `RFIDMenu.cpp` | RFID menu; exposes `ST25R3916_SPI_MODULE` / `ST25R3916_I2C_MODULE` options. |
| `RFID2.h` / `RFID2.cpp`, `PN532.h` / `PN532.cpp` | RC522 (SPI) and PN532 (I2C/SPI) drivers — other supported modules, not ST25R3916. |
| `src/core/serial_commands/rfid_commands.{h,cpp}` | Serial CLI `rfid` commands (read/load/save/emulate). |

### 1.2 Supported hardware & communication interfaces

| Module | Transport | Bruce enum | Wired boards (pins defined) |
|--------|-----------|------------|------------------------------|
| PN532 | I2C / SPI | `PN532_I2C_MODULE`, `PN532_SPI_MODULE`, `PN532_I2C_SPI_MODULE` | various |
| RC522 | SPI | `RC522_SPI_MODULE` | various |
| M5 RFID2 | — | `M5_RFID2_MODULE` | M5Stack RFID2 unit |
| **ST25R3916** | **SPI** | `ST25R3916_SPI_MODULE` | `lilygo-t-lora-pager`, `reaper` |
| **ST25R3916** | **I2C** | `ST25R3916_I2C_MODULE** | (no board defines pins) |

**Critical gap for Cardputer ADV:** The `m5stack-cardputer` env (which covers both Cardputer and Cardputer ADV via the `ES8311_CODEC` flag) does **not** define `ST25R_SCLK/MISO/MOSI/CS/IRQ`, so `BruceConfigPins::ST25R_bus` is all `GPIO_NUM_NC`. `ST25R3916::_initSPI()` calls `acquireSPIBus(sck, miso, mosi)`, which returns `nullptr` when any pin is `GPIO_NUM_NC` (`bus_HAL.cpp:365`). Therefore `ST25R3916::begin()` fails and Tag-O-Matic reports **"RFID module not found"** — the ST25R3916 path cannot even initialize on Cardputer as currently configured. The silasgubi/CardputerADV-NFC repo (see §5) confirms the Cardputer ADV NFC hardware is an ST25R3916B (M5 NFC Unit) at I²C `0x50` on Port A; Bruce has no I²C ST25R3916 pin config for Cardputer either.

The ST25R3916 driver depends on two pinned RFAL forks (applied via `patch_library_conflicts.py`):
- `lewisxhe/ST25R3916-fork#0c8e00f49d12881d1cff6d6f0879b90ce7ed4033` (IRQ-less I²C polling)
- `lewisxhe/NFC-RFAL-fork#7bde4587ea44c36c178a43d083d7a7345c1e4cfe` (NFC-A anti-collision timing/retries)

### 1.3 Working features vs README claims

**MIFARE Classic (Milestone 5) — actually implemented in `ST25R3916.cpp`:**

- Card detection: YES — `_parseDevice` maps SAK `0x08/0x88` → "MIFARE Classic 1K", `0x18` → "MIFARE Classic 4K", `0x09` → "MIFARE Mini".
- Authentication with supplied keys: YES — tries builtin 15-key dictionary (`RFIDInterface::keys`, Key A then Key B per sector) then custom keys from `bruceConfig.mifareKeys`.
- Sector reading: YES — `_readMifareClassic` authenticates per sector, then reads every data block (skipping trailers implicitly by reading all blocks).
- Diagnostics: **WEAK** — `_readMifareClassic` returns only `SUCCESS` or `FAILURE`. `TAG_AUTH_ERROR` is defined but never returned for MIFARE Classic. No per-sector/per-block failure reporting to the UI.
- Key dictionaries: YES — builtin 15 keys + persistent custom-key file.
- Partial-read handling: **DEFECTIVE** — `mfcLoaded = (blocksOk > 0)`, so reading **one** block of 64 is reported as a complete success; partial reads are not labeled as partial.
- Hardware-tested on ST25R3916: driver is written for ST25R3916 over RFAL, but Cardputer ADV ST25R3916 is not wired (see §1.2), so it cannot be verified on Cardputer ADV from this repo alone.

**Root cause of `Failed reading data blocks` (detailed in Phase 2):**

`statusMessage(RFIDInterface::FAILURE)` == `"Failed reading data blocks"`. `_readMifareClassic` returns `FAILURE` when `blocksOk == 0`, i.e. when authentication failed for **every** sector with **every** key in both dictionaries, OR when a mid-read `_pollForTag` re-acquisition fails. The message therefore conflates:

1. Authentication failure (wrong/absent key) — should be "Failed authenticating" (`TAG_AUTH_ERROR`).
2. RF/transport failure (card removed, timeout, poll failure) — should be a transport error.
3. Partial-read success mislabeled as complete.

### 1.4 Licensing & dependencies

- License: AGPL-3.0 (strong copyleft).
- Dependencies: Arduino-ESP32 core, RFAL forks above, `crypto1.h/cpp` (in-tree). No external MIFARE Classic library dependency — the MIFARE Classic logic is in-tree.
- Integration into Bruce: already part of Bruce's NFC stack; no second stack needed.

### 1.5 Can it integrate without replacing Bruce's NFC stack?

Yes — the MIFARE Classic code already lives inside Bruce's `ST25R3916` driver, which is one of several drivers behind the `RFIDInterface` abstraction used by Tag-O-Matic. The fix should be a patch to `_readMifareClassic`/`_mifareAuth`/`_mifareReadBlock` plus a diagnostic display, not a new stack.

---

## 2. wilson-elechouse/ST25R3916 — BEST CANDIDATE FOR REUSE

| Field | Value |
|-------|-------|
| URL | https://github.com/wilson-elechouse/ST25R3916 |
| HEAD commit | `16eb6c7` "Add low-power wakeup and current profile examples" (2026-07-09) |
| Branch | `main` |
| License | SLA0052 Rev3 (Elechouse / ST software license agreement) |
| Library properties | `name=ELECHOUSE ST25R3916 for ESP32`, version 1.1.1, depends on `ELECHOUSE NFC-RFAL for ESP32`, architectures esp32 |

### 2.1 Relevant source files

`ST25R3916_ELECHOUSE/src/`:

| File | Role |
|------|------|
| `rfal_mf1.h` / `rfal_mf1.cp` | **Complete MIFARE Classic 1K/4K authentication + block read/write over ST25R3916 RFAL.** Self-contained Crypto1 (reimplementation in anonymous namespace). Standalone `RfalMf1Class(RfalRfST25R3916Class*)`. |
| `st25r3916.{h,cpp}`, `st25r3916_com.{h,cpp}`, `st25r3916_aat.{h,cpp}`, `st25r3916_timer.cpp`, `st25r3916_interrupt.cpp` | ST25R3916 low-level driver. |
| `rfal_rfst25r3916_*.{h,cpp}` | RFAL ST25R3916 binding. |
| `rfal_rfst25r3916_analogConfigTbl.h/.cpp` | Analog config tables. |

### 2.2 Supported hardware & communication interfaces

- ESP32, ESP32-S3, ESP32-C3 (Arduino core).
- **SPI** is the primary, hardware-validated transport (examples for ESP32 SCK18/MISO19/MOSI23/SS5 IRQ4; ESP32-S3 SCK12/MISO13/MOSI11/SS10 IRQ4; ESP32-C3 SCK2/MISO10/MOSI3/SS7 IRQ6).
- **I2C** examples also present (ESP32 I2C chip probe, ISO14443A, S70 read/auth/dump diagnostics, ICODE SLIX2).
- Recommended hardware: Elechouse ST25R3916B NFC module.

### 2.3 Working features vs README claims

The README explicitly scopes validation:
- SPI: ISO15693 card profiling, A/B/V scanning, ICODE block read/write/restore, ISO15693/Type 5 NDEF, **MIFARE Classic S70 read/write + sector dump** (ESP32-C3 validated, Arduino-ESP32 core 3.3.8).
- I2C: chip probe, ISO14443A, **S70 read/auth/dump diagnostics**, ICODE SLIX2, ISO14443B/Type 4B NDEF.

The `rfal_mf1.cpp` implementation provides:
- `authenticate(state, device, blockNo, key, authCmd=A|B, &cardNonce)` — full Crypto1 first-auth + nested-auth exchange, AT verification (`prng_successor(nt, 96)`).
- `readBlock(state, blockNo, blockData)` — encrypted READ (0x30), 16 data + 2 CRC, parity + CRC validation.
- `writeBlock(state, blockNo, blockData)` — encrypted WRITE (0xA0), ACK nibble verification.
- Helpers: `sectorFirstBlock`, `sectorBlockCount`, `blockToSector`, `isTrailerBlock`, `getUid32` (4-byte UID only).

**Notably:** `rfal_mf1` is a **reader-side MIFARE Classic auth/read/write** library, not a key-recovery/cracking tool. It requires a supplied key.

### 2.4 Independently tested on ST25R3916?

**Yes.** Examples ship with the library and are hardware-validated per the README:
- `examples/SPI/ESP32_SPI_mf1_s70_read_write_test.ino`
- `examples/SPI/ESP32_SPI_mf1_s70_sector_range_dump.ino` (default Key A `FF FF FF FF FF FF`, authenticates per sector, reads data blocks skipping trailers, re-acquires card between sectors)
- `examples/I2C/ESP32_I2C_mf1_s70_read_write_test.ino`
- `examples/I2C/ESP32_I2C_mf1_s70_sector_range_dump.ino`

### 2.5 Licensing & dependencies

- License: SLA0052 Rev3 (Elechouse/ST). Not AGPL; compatible for in-tree reuse as a source component (review license terms for distribution).
- Depends on the sibling `ELECHOUSE NFC-RFAL for ESP32` (RFAL) — Bruce already uses an RFAL fork (`lewisxhe/NFC-RFAL-fork`), so the RFAL dependency is already present, though a *different fork*. Mixing two RFAL forks would be a concern.

### 2.6 Can it integrate into Bruce without replacing the NFC stack?

**Partially.** `RfalMf1Class` takes an `RfalRfST25R3916Class*` — Bruce already has `_hw` (`RfalRfST25R3916Class`). So an `RfalMf1Class` could be instantiated against Bruce's `_hw`. However:
- It is a **separate MIFARE Classic state machine** parallel to Bruce's existing `_readMifareClassic`/`_mifareAuth`/`_mifareReadBlock` (two Crypto1 implementations, two transceive paths).
- Per the task's reuse order, **fixing Bruce's existing implementation is preferred** over importing a second MIFARE Classic stack. Elechouse `rfal_mf1` is best used as a **reference/donor** for correct framing (e.g. CRC_TX_AUTO vs Bruce's CRC_TX_MANUAL for the first-auth command; reader-nonce seeding; 4-byte UID handling).

---

## 3. suut/rfal-mifare-classic

| Field | Value |
|-------|-------|
| URL | https://github.com/suut/rfal-mifare-classic |
| HEAD commit | `b2ac659` "Fix ST25R95 code" (2026-02-15) |
| Branch | `master` |
| License | No LICENSE file found in checkout |

### 3.1 Relevant source files

- `mf1/` — MIFARE Classic implementation over RFAL.
- `crapto1/` — Crypto1 implementation adapted from Proxmark3.
- `STM32L152RETX_FLASH.ld`, `mfc.ioc` — STM32CubeMX project for **STM32L152RE**.
- `Drivers/`, `Middlewares/`, `X-CUBE-NFC6/` — ST HAL + X-CUBE-NFC6 (RFAL STSW-ST25RFAL002 for ST25R3916/ST25R3916B).

### 3.2 Supported hardware & interfaces

- STM32L152RE (STM32 HAL), **not ESP32/Arduino**. ST25R3916 via ST RFAL (STSW-ST25RFAL002).
- Transport: SPI (RFAL ST25R3916 binding).

### 3.3 Working features vs README claims

README states: "Mifare Classic implementation using RFAL on a ST25R3916"; "The CRYPTO1 implementation is in `crapto1/` and was adapted from the version in the Proxmark3 repository."

- Provides MIFARE Classic auth/read over ST25R3916 RFAL.
- Documents a required RFAL driver change: **do not report `ERR_INCOMPLETE_BYTE` as an error when `PAR_RX_KEEP` is set** (incomplete byte = trailing parity bit, valid for MIFARE). Bruce already handles this via `_mfcRxOk()` in `ST25R3916.cpp` (accepts `ST_ERR_INCOMPLETE_BYTE .. ST_ERR_INCOMPLETE_BYTE_07`).
- Porting note: transceive flags and `encode_parity`/`decode_parity` must be adapted per reader IC (ST25R3916-style vs ST25R95-style parity framing).

### 3.4 Independently tested on ST25R3916?

Designed for ST25R3916/ST25R3916B via X-CUBE-NFC6, but on STM32 — not on ESP32-S3/Cardputer. No ESP32 hardware evidence in this checkout.

### 3.5 Licensing & dependencies

- No LICENSE found → reuse terms unclear; treat as reference only.
- Depends on STM32 HAL + X-CUBE-NFC6 RFAL — not portable to Bruce's Arduino-ESP32 RFAL fork without a port.

### 3.6 Integration value

**Reference only.** Not directly reusable on ESP32 (STM32 HAL). Its Crypto1 (Proxmark3-derived) and the incomplete-byte RFAL requirement are useful cross-checks for Bruce's `crypto1.cpp` and `_mfcRxOk`, both of which already exist and appear correct.

---

## 4. silasgubi/CardputerADV-NFC — Cardputer ADV-specific, NO MIFARE Classic auth/read

| Field | Value |
|-------|-------|
| URL | https://github.com/silasgubi/CardputerADV-NFC |
| HEAD commit | `1fd5a94` "Remove tag prices and clarify NFC module is official M5Stack unit" (2026-07-14) |
| Branch | `main` |
| License | MIT (2026 Silas Gubitoso) |

### 4.1 Relevant source files

- `src/nfc_reader.h` / `src/nfc_reader.cpp` — NFC reader using **M5UnitUnified + M5UnitUnifiedNFC** (M5Stack's official NFC unit library).
- `src/main.cpp`, `src/keyboard.{h,cpp}`, `src/card_store.{h,cpp}`, `src/card_store.h` — Cardputer ADV UI (scan/save/browse/emulate/NDEF write).
- `boards/m5stack-cardputer.json` — board definition named **"M5Stack Cardputer ADV"** (variant `m5stack_stamp_s3`, URL `docs.m5stack.com/en/core/Cardputer-Adv`).

### 4.2 Supported hardware & interfaces

- **M5Stack Cardputer ADV** specifically.
- Transport: **I²C**, M5 NFC Unit (ST25R3916B) at address `0x50` on Port A, via `m5::unit::wiring::addI2C(Units, unit, 0, NessoPort::PortA)`. Port A shared with TCA8418 keyboard (`0x34`) — no address conflict.
- Confirms Cardputer ADV NFC hardware: **ST25R3916B, I²C 0x50**.

### 4.3 Working features vs README claims

- NFC-A card scan (UID, ATQA, SAK, type name): YES.
- NDEF URI write to blank NTAG/Ultralight: YES.
- Card emulation (NFC-A): YES, but **only Ultralight/NTAG2xx** — the code explicitly rejects MIFARE Classic: `if (!(is_ntag2(type) || type == Type::MIFARE_Ultralight)) { _emuErr = "Classic nao emula (so Ultralight/NTAG)"; ... }`.
- **MIFARE Classic authentication / sector reading: NOT IMPLEMENTED.** No auth, no key dictionary, no block read. This repo is a scan/emulate/NDEF tool, not a MIFARE Classic reader.

### 4.4 Independently tested on ST25R3916?

Yes — it's a Cardputer ADV-specific app using the official M5 ST25R3916B unit, but only for ISO14443A scan / NDEF / Ultralight-NTAG emulation, not MIFARE Classic auth.

### 4.5 Licensing & dependencies

- License: MIT.
- Depends on `M5UnitUnified` / `M5UnitUnifiedNFC` (M5Stack official libraries) and `M5Cardputer.h` — **not** Bruce's RFAL fork. Introducing it would add a second, unrelated NFC stack.

### 4.6 Integration value

**Low for this task.** It confirms the Cardputer ADV ST25R3916B hardware (I²C 0x50, Port A) but contributes no MIFARE Classic auth/read code and would add a second NFC stack (M5UnitUnifiedNFC vs Bruce's RFAL). Reuse limited to: hardware pin/address reference (ST25R3916B @ 0x50, Port A) and UI patterns (scan/save/browse).

---

## 5. mtoolstec/CardputerZero-RFID

| Field | Value |
|-------|-------|
| URL | https://github.com/mtoolstec/CardputerZero-RFID |
| HEAD commit | `ac9071d` "docs(rfid): record validated 1.0.3 store release" (2026-10-21) |
| Branch | `main` |
| License | No LICENSE file found in checkout |

### 5.1 Relevant source files

- `main/nfc/` — `nfc_transport.hpp`, `nfc_protocol.hpp`, `nfc_spi_device.hpp`, `nfc_i2c_device.hpp`, `nfc_device_service.hpp`, `nfc_models.hpp`, `nfc_storage.hpp` — host-side NFC transport (Linux spidev `/dev/spidev*`, I²C `/dev/i2c-*`).
- `main/tools/mfkey/` — `mfkey32v2.c`, `mfkey64.c`, `nested_util.c`, `staticnested.c`, `crapto1/` — **MIFARE Classic key-recovery tools** (nested, static nested, mfkey32, mfkey64, crapto1).
- `config/defaults/mfc1k.json` — sample MIFARE Classic 1K dump (UID, ATQA, SAK, 64 blocks with trailer pattern `FFFFFFFFFFFFFF 078069 FFFFFFFFFFFF`).
- `main/ui/` — Cardputer UI (read/dump/save/emulate tabs).
- `FEATURE_MATRIX.md` — per-device capability matrix.
- `tests/` — host-side test fixtures (`test_mifare_standard.cpp`, `mfc_key_export_test.cpp`, ...).

### 5.2 Supported hardware & interfaces

Per `FEATURE_MATRIX.md`:

| Device | Transport | Scan/UID | Mifare Classic Dump |
|--------|-----------|----------|---------------------|
| M5 NFC Unit (ST25R3916B) | Grove I²C, 0x50 | ✓ | ✓ |
| M5 NFC CAP (ST25R3916) | SPI, spidev | ✓ | △ Gen1A path |
| PN532 / PN532Killer | USB/UART | ✓ | authenticated reads |
| UHF reader | USB | inventory | bank capture |

NFC Unit probe: `{0x50, "NFC Unit"}`; GroveNFC: `{0x48, "GroveNFC"}` (`nfc_transport.hpp:652`).

### 5.3 Working features vs README claims

README scope:
- M5 NFC CAP (SPI): Gen1A dump and saved writes; **encrypted MFC 1K emulation is experimental and disabled by default**.
- M5 NFC Unit / GroveNFC (I²C): reader, dump, writer, listener support depends on detected chip/protocol.
- PN532: authenticated reads.
- MIFARE Keys tool: manage key dictionary; staticnested recovers unknown keys using a successful auth key as seed — **key recovery**, explicitly out of scope for this task.

`FEATURE_MATRIX.md` (§78): "SPI 加密 MFC1K 模拟尚未通过完整重启认证回归，默认禁用，不能按稳定能力发布." (SPI encrypted MFC1K emulation has not passed full re-authentication regression, disabled by default, not a stable capability.)

### 5.4 Independently tested on ST25R3916?

Yes for the M5 NFC Unit (ST25R3916B I²C 0x50) Mifare Classic dump (✓ in FEATURE_MATRIX), but this is a **Linux host application** (spidev / /dev/i2c-*), not an Arduino/ESP32 sketch. Not directly portable to Bruce.

### 5.5 Licensing & dependencies

- No LICENSE found → terms unclear.
- Host-side Linux (spidev, i2c-dev) — not ESP32/Arduino.

### 5.6 Integration value

**Reference only.** Confirms ST25R3916B @ 0x50 Mifare Classic dump works on M5 hardware. Its key-recovery tools (nested/mfkey32/crapto1) are explicitly **excluded** by this task ("Do not add automated unknown-key recovery or access-credential cloning").

---

## 6. RSSeeker/chameleon-ultra-tab5

| Field | Value |
|-------|-------|
| URL | https://github.com/RSSeeker/chameleon-ultra-tab5 |
| HEAD commit | `da2bc70` "tools: refuse to run without the upstream checkout" (2026-09-16) |
| Branch | `main` |
| License | GNU GPL v3 |

### 6.1 Relevant source files

- `firmware/components/chameleon_crypto/` — `mfkey32.h`, `hardnested/` (bruteforce/core) — Crypto1/MIFARE key-recovery primitives.
- `firmware/components/chameleon/` — `chameleon_commands.{h,cpp}`, `chameleon_client.h`, `sniff_decoder.h` — client for Chameleon Ultra device.
- `firmware/main/pages_*.cpp` — LVLV UI pages (card, keys, tools, emulate).
- This is an **ESP-IDF** project (`idf.py build`), variant for **M5Stack Tab5** (ESP32-P4 + ESP32-C6).

### 6.2 Supported hardware & interfaces

- Host client for the **Chameleon Ultra** (a separate HF/LF RFID device) over **USB CDC** or Bluetooth (out of scope). **Not an ST25R3916 reader implementation.**
- M5Stack Tab5, not Cardputer ADV.

### 6.3 Working features vs README claims

- HF/LF scanning and cloning, emulation (LF IDs, Mifare Classic, MF0/NTAG), ISO14443-4/EMV/SEOS, sniffer trace decoding.
- **MIFARE Classic key recovery**: factory keys, darkside, nested, static nested, hardnested nonce acquisition, mfkey32 — all key **recovery/cracking**, explicitly out of scope for this task.
- README: "Real-card success paths are still untested"; "The Chameleon itself runs its own firmware; this repository is a host."

### 6.4 Independently tested on ST25R3916?

**No.** It talks to a Chameleon Ultra device over USB; no ST25R3916 reader code.

### 6.5 Licensing & dependencies

- GPL-3.0 (derives from GPL-3.0 upstream Chameleon Ultra code). Strong copyleft — not suitable for merging into Bruce (AGPL) without careful license review, and irrelevant anyway (different architecture, key-recovery focus).

### 6.6 Integration value

**None for this task.** Key recovery (excluded), host-client architecture (USB to Chameleon Ultra, not ST25R3916), wrong hardware (Tab5 ESP32-P4), ESP-IDF not Arduino.

---

## 7. Feature matrix

| Capability | Bruce (ST25R3916) | wilson-elechouse ST25R3916 (`rfal_mf1`) | suut/rfal-mifare-classic | silasgubi CardputerADV-NFC | mtoolstec CardputerZero-RFID | RSSeeker Chameleon-tab5 |
|---|---|---|---|---|---|---|
| Card detection (UID/ATQA/SAK) | ✓ (NFC-A scan) | ✓ (via RFAL discover) | ✓ (RFAL) | ✓ (NFC-A scan) | ✓ | ✓ (via Chameleon) |
| Identify MIFARE Classic 1K (SAK) | ✓ (`0x08`/`0x88`) | ✓ (ATQA/SAK check) | ✓ | — | ✓ | ✓ |
| Authentication with **supplied** keys | ✓ (builtin 15 + custom file) | ✓ (`authenticate`, Key A/B) | ✓ | — | ✓ | ✓ |
| Sector reading (all data blocks) | ✓ (`_readMifareClassic`) | ✓ (`readBlock` per block) | ✓ | — | ✓ | ✓ |
| Diagnostics: per-sector/block result | ✗ (only SUCCESS/FAILURE) | ✗ (per-call ReturnCode only) | ? | — | △ (status per bank) | — |
| Diagnostics: error classification (auth vs transport vs timeout) | ✗ (`FAILURE` = "Failed reading data blocks"; `TAG_AUTH_ERROR` defined but unused) | ✗ (raw `ReturnCode`) | ? | — | ✗ | — |
| Key dictionaries | ✓ (builtin 15 + persistent custom) | — (caller supplies key) | — | — | ✓ | — |
| Partial reads labeled partial | ✗ (`blocksOk>0` => SUCCESS) | ✗ (per-block ReturnCode, caller decides) | ? | — | ✓ (banks marked partial) | — |
| Key recovery / unknown keys | — | — | — | — | ✓ (nested, mfkey32) | ✓ (nested, hardnested, mfkey32) |
| Hardware: ST25R3916 | ✓ driver (RFAL fork) | ✓ (driver + examples) | ✓ (X-CUBE-NFC6, STM32) | ✓ (ST25R3916B @ 0x50 I²C) | ✓ (ST25R3916B @ 0x50 I²C) | — |
| Independently tested on ST25R3916 | △ (driver written for it; Cardputer ADV not wired) | **✓ (ESP32/ESP32-S3/ESP32-C3 SPI + I2C examples)** | ✓ (STM32 only) | ✓ (scan/NDEF only, not MFC auth) | ✓ (host spidev, not ESP32) | — |
| Reusable in Bruce without 2nd NFC stack | ✓ (already in-tree) | △ (standalone class vs Bruce `_hw`, but 2nd MFC state machine) | ✗ (STM32 HAL) | ✗ (M5UnitUnifiedNFC stack) | ✗ (host Linux) | ✗ (USB host client, GPL) |
| License | AGPL-3.0 | SLA0052 Rev3 | (none found) | MIT | (none found) | GPL-3.0 |

---

## 8. Recovery implementations on ST25R3916 — finding

**No existing recovery implementation works directly on the ST25R3916 in a way reusable here.**

- `mtoolstec/CardputerZero-RFID` has nested/static-nested/mfkey32 key-recovery, but it is a **Linux host application** (spidev / /dev/i2c-*) targeting the M5 NFC Unit — not portable to Bruce's Arduino-ESP32 stack.
- `RSSeeker/chameleon-ultra-tab5` has nested/hardnested/mfkey32 recovery, but it is a **USB host client for the Chameleon Ultra device** — not an ST25R3916 reader.
- `suut/rfal-mifare-classic` and `wilson-elechouse/ST25R3916` are **reader-side auth/read/write with supplied keys only** — no key recovery.
- Bruce itself has no key recovery (only a supplied-key dictionary).

**Documented finding:** Support for Crypto1 (authentication/encryption) does **not** automatically establish working recovery functionality. Recovery (nested attack, hardnested, mfkey32) requires nonces, parity/oracle behavior, and often many authentication sessions — none of which are present in the ST25R3916 reader implementations audited. Per the task, **no automated unknown-key recovery or access-credential cloning will be added** as part of this diagnostic milestone.

---

## 9. Conclusion — best existing implementation

**Best existing implementation to evaluate first: `wilson-elechouse/ST25R3916` → `ST25R3916_ELECHOUSE/src/rfal_mf1.{h,cpp}` (HEAD `16eb6c7`).**

Rationale:
- Complete, self-contained MIFARE Classic 1K/4K **authentication + block read/write** over ST25R3916 RFAL, with its own Crypto1.
- **Independently validated on ESP32 / ESP32-S3 / ESP32-C3** over SPI (and I2C examples) — the only reference with ESP32-S3 ST25R3916 MIFARE Classic hardware evidence.
- Standalone `RfalMf1Class(RfalRfST25R3916Class*)`; Bruce already owns an `RfalRfST25R3916Class` (`_hw`), so no new radio driver is needed.
- Reader-side only (supplied keys) — matches the task scope; no key recovery.

**However, per the task's reuse order, the preferred approach is to FIX Bruce's existing implementation first** (Phase 3/4), because Bruce's `ST25R3916` driver already contains MIFARE Classic (Milestone 5), Crypto1 (`crypto1.cpp`), the key dictionary, and the `RFIDInterface` abstraction — importing `rfal_mf1` would add a second MIFARE Classic state machine and a second RFAL fork. Elechouse `rfal_mf1` should be used as a **reference/donor** for correct framing details where Bruce's implementation is suspect (e.g. CRC_TX_AUTO vs CRC_TX_MANUAL on the first-auth command, reader-nonce seeding, 4-byte UID handling).

**Critical blocker identified in this audit:** Bruce does **not** configure ST25R3916 pins for the Cardputer/Cardputer ADV board (`ST25R_bus` is all `GPIO_NUM_NC`; `acquireSPIBus` returns `nullptr`; `ST25R3916::begin()` fails). The Cardputer ADV NFC hardware (per silasgubi/CardputerADV-NFC) is an ST25R3916B at I²C `0x50` on Port A. Before MIFARE Classic reading can work on Cardputer ADV, Bruce must wire the ST25R3916 I²C pins (and add a Cardputer ADV build env distinct from the original `m5stack-cardputer`). This is a prerequisite, not a conclusion about the MIFARE Classic logic itself.
