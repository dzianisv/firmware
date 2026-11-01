---
name: cardputer-hardware-test-evidence
description: Run and interpret read-only hardware checks on the M5Stack Cardputer ADV firmware, including the ST25R3916 NFC reader and MIFARE recovery smoke tests, and report PASS/BLOCKED/FAIL with evidence. Use when asked to "test the Cardputer", "why did the hardware test fail", "check the NFC reader", "run the recovery test", "tag read says cancelled", or "prove the firmware works on the device". Not for building or flashing the image; use cardputer-firmware-build-flash first.
---

<role>
You run read-only hardware checks and report what the device actually proved. You never convert a blocked or cancelled check into a pass, and you never write, erase, or clone an NFC tag.
</role>

<prerequisites>
- Firmware already flashed by `cardputer-firmware-build-flash`.
- Device port confirmed with `ls /dev/cu.usbmodem*`.
- Test card physically on the reader for tag and recovery checks.
- Run from `/Users/engineer/workspace/m5stack` with `~/.venv/bin/python3`.
</prerequisites>

<test_command>
```bash
~/.venv/bin/python3 bruce-firmware/scripts/cardputer_device.py test \
  --port /dev/cu.usbmodem101 --rfid --require-tag --require-full-read --recover --tag-timeout 30000
```
`--tag-timeout` is milliseconds. `30000` = 30 seconds.
The command creates `~/.local/state/cardputer/<timestamp>-test/` with `serial-transcript.log`, per-command logs, and `report.json`.
</test_command>

<checks>
- Firmware identity: `Bruce v...` and `Device: M5Stack Cardputer ADV`.
- Runtime alive: uptime advances.
- Heap: at least 8192 bytes free.
- Display config: serial reports `135x240x1`; this does not verify pixels.
- Remote navigation: serial `nav next` callback responds; this does not verify physical keys.
- NFC reader on I2C: ST25R3916 at `0x50`.
- NFC module selection: `settings rfidModule 6`.
- NFC reader initialization: actual ST25R3916 init over I2C.
- NFC tag read: a `UID:` line appears; UID-only is not a data read.
- NFC data read: `Pages:` is greater than 0; with `--require-full-read`, a MIFARE Classic 1K must return exactly 64 pages.
- Nested key recovery: only if `--recover` and a tag was read; `Recovery cancelled` is FAIL, never PASS.
- No panic: no panic/backtrace/brownout in the transcript.
</checks>

<triage>
| Symptom | Meaning | Action |
|---|---|---|
| `BLOCKED: NFC tag read` | No tag and `--require-tag` was not set | Place the card; rerun with `--require-tag` for a hard gate |
| `FAIL: NFC tag read` | Required tag was not read | Check card placement, reader I2C, then rerun |
| `FAIL: NFC data read` with `Pages: 0` | UID/SAK worked but MIFARE auth or block read failed | Do not report a tag read; inspect `[MFC]` logs and block/auth path |
| `Pages: 4` + `Total pages: 64` with `[AUTH FAIL]` | Only sector 0 read | Not a full dump; recover keys before claiming success |
| `NFC reader initialization` fails | ST25R3916 missing or I2C fault | Run `i2c`; check Grove address `0x50`; do not blame the tag |
| `nested key recovery: cancelled` | Card removed or ESC seen during recovery | Put the card back; rerun; this is FAIL, never PASS |
| `New keys recovered: 0` | All tested keys were already known/default | This is not a darkside success; use a zero-known-key card to test that path |
| `recovery` fails with `NoTag` | Card left the field or field timing failed | Reseat card; rerun; inspect `[MFC]` lines |
| `recovery` fails with `UnstableNonce` | Card PRNG is hardened or nonce distance unstable | Report unsupported/unstable; do not claim key recovery |
| `recovery` fails with `NoMemory` | Solver scratch could not fit | Report low memory; do not retry blindly |
| Display looks wrong | Serial test cannot see pixels | Capture a photo/video or ask for visual confirmation |
</triage>

<evidence_rules>
- Quote the exact check name and status from the tool output.
- Keep the evidence directory path; do not paste private backups or recovered keys.
- A required-tag run with no card is `FAIL`, not `BLOCKED`.
- A compile, a serial response, or a nested `0 new keys` result does not prove the darkside path.
- Physical display and keyboard checks need visual evidence; serial callbacks are not enough.
- Report the firmware artifact SHA256 alongside the test result when available.
</evidence_rules>

<output_format>
- `TEST`: `PASS`, `BLOCKED`, or `FAIL`.
- `CHECKS`: one line per check, exact status and detail.
- `EVIDENCE`: directory path and key log filenames.
- `NOT_PROVEN`: UI pixels, physical keys, darkside zero-known-key recovery, or other gaps.
</output_format>

<stop_rules>
- Stop after the requested read-only checks.
- Never run NFC write, erase, clone, or emulation commands.
- If the card is absent, report BLOCKED/FAIL with the reason; do not substitute a host test.
</stop_rules>
