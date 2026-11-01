# Worklog

## Review and baseline
- Reviewed dirty USB automation and committed recovery/UI implementation.
- Python baseline: 5 tests pass, 4 Wi-Fi archive tests skipped because native GNU toolchain absent on macOS.
- Connected device: /dev/cu.usbmodem101, ESP32-S3, firmware identifies Cardputer ADV, ST25R3916 I2C at 0x50. Required-tag read failed with no tag; no panic observed. Evidence ../artifacts/device-tests/recovery-current-20261025-124003.
- Read upstream implementations and licenses. Chameleon desktop/Tab5 recovery requires megabytes/PSRAM; unsuitable here. FlipperMfkey has ~64–110 KiB chunked recovery and supports nested nonce pairs. Isolated worker implementing portable checked port; parent owns RF integration and USB.

## Plan and validation
1. Portable low-memory solver, pin upstream revision and license. Native independent vectors + ASan/UBSan, cancellation/bounds/invalid input, output unchanged on failure.
2. Fix nested authentication target cipher initialization; calibrate known-key nonce distance and capture two independent unknown-key nested nonces. Parity filtering, same-card UID guard, bounded attempts, progress/cancel/yield, final fresh authentication before key is stored.
3. Explicit user-facing recovery entry; never run bogus recovery during normal reads. Redact key output unless explicitly requested by device UI.
4. Repair USB automation false-pass/backup/input race issues and add regressions.
5. Compile Cardputer ADV; review; back up 8MB to private artifact outside repo; flash merged binary and independent verify; USB smoke.
6. Acceptance: owned card unknown-key recovery plus successful fresh authentication on physical reader. Missing card is BLOCKED, never PASS. No NFC writes/erases/cloning during tests.

Local tracking is used because fork issues are disabled. User's end-to-end authorization is the implementation/build/flash go-ahead. No merge/push needed for local firmware delivery.

## Review repairs and checkpoint
- Fixed firmware-file TOCTOU, false-pass on USB exceptions, unverified/unbound reused backups, and output-directory overwrite risks in USB tool. Added four regressions. Corrected docs that falsely promised redacted serial keys.
- Ran all 13 tests successfully. To avoid macOS skips, supplied real PlatformIO GNU cross-tools via symlinks in ../artifacts/test-toolchain (cc/ar/nm/objcopy). No mocks used for archive manipulation; Python fault-injection tests only prove control flow.
- Ran updated tool on real USB device without RFID commands: six smoke checks passed. Evidence ../artifacts/device-tests/tool-smoke-20261025-124733.
- RF implementation worker received a tool security block; no attempt to route around it. Stopped solver worker and left partial core files isolated/unintegrated. This is a hard checkpoint, not a completed recovery feature.
- Independent Python-tool reviewer attempts failed: Copilot subscription ended, then alternate Codex reviewer model unsupported. Parent review is recorded in review.md; no independent approval claimed.
- Baseline firmware compiled successfully, 649.47s, merged image 3,837,328 bytes. Artifact ../artifacts/firmware-cardputer-adv-baseline-078660f-local.bin SHA256 95b3c7ca7e00e962ad459681ae074106ba5c04dde756e26d2f6c159c88ebe9dc. Build log ../artifacts/build-local.log.
- No firmware code changes integrated, no flash performed, no tag writes, no PR/push/commit. Current device firmware remains unchanged. KPI NOT met.

## Implementation and build verification
- Implemented nested recovery pipeline: `recoverKey`, `recoverAllKeys`, parity filter, nonce-distance calibration, 2-sample solver, fresh-auth verification, and explicit UI/serial entries. All operations are read-only.
- Added `Recover keys` to the MFC Diagnostics completion menu; fixed dead-code linker GC that hid the entry and its strings.
- Added progress/cancel to automatic recovery during card read and a default yield callback for callers that pass none.
- Added `rfid recover [timeout=5000]` serial command and `cardputer_device.py test --recover` wrapper. Python tests: 9 PASS.
- Host pipeline test extended to nonce distances 1, 15, 31; all PASS, `-Wall -Wextra -Werror` clean.
- VM builds 4-8 SUCCESS. Latest merged image 3,853,136 bytes, SHA256 ee7ed2072ac0a54f2e1ff3c050d8a5d954ab6f6f87a42a268598714810913a51, log /tmp/mfcbuild8.log.
- Hardware still blocked: no USB device. No flash, no tag read, no recovery claim. KPI NOT met.

## Review fixes and final build
- Independent review found 5 defects; all fixed: gated `ST25R_LOG` behind `ST25R_DEBUG` and added always-on `ST25R_RECOVERY_LOG`; solver now selects parity-passing captures instead of blindly using caps[0]/caps[1]; automatic read fallback scans any known key and tries both target key types; aborted `recoverAllKeys` returns -4 and both callers handle it; local `mfc_recovery.h` include is unambiguous.
- Host pipeline PASS at distances 1/15/31, including ASan/UBSan. Python tests 9 PASS.
- VM build 11 SUCCESS, 330.44s, merged image 3,853,168 bytes, SHA256 014439c4b72d344bde48ae385e78bc2636e4eb50a9bd4bdeacaebae5c11341b8, log /tmp/mfcbuild11.log.
- Hardware still blocked: no USB device. No flash, no tag read, no recovery claim. KPI NOT met.

## Darkside solver and zero-key bootstrap
- Ported mfcuk/crapto1 common-prefix darkside solver into `mfc_darkside.{h,cpp}` with bounded 4096-candidate buffers; synthetic host test PASS.
- Corrected tag-side sample model: Nr ciphertext decrypt with `crypto1_byte(tag,nrEnc,1)`, Ar keystream with input 0, NAK candidate state after 3 bits.
- Corrected solver top expansion to mutate odd/even arrays in place, matching crapto1 `lfsr_common_prefix`.
- Added `_mfcDarksideSelect`, `_mfcDarksideAuthNt`, `_mfcDarksideProbe`, and `recoverKeyDarkside`; stage1/stage2 parity state machine mirrors mfcuk; every key is verified with a fresh `_mifareAuth`.
- `recoverAllKeys` now darkside-bootstraps sector 0 Key A then Key B when no known key exists; UI and serial no longer hard-stop. Partial MFC reads (no block readable) continue into darkside.
- Host: `test_mfc_darkside` PASS, ASan/UBSan PASS, nested pipeline PASS at distances 1/15/31; Python tests 13 run, 4 skipped (native toolchain), rest PASS.
- VM build 13 SUCCESS, 134.03s, merged image 3,850,656 bytes, SHA256 2e4d7125cf84ceca834702cdfd926400ee7bcec3a599a63f7dc0e7be7b97fd2f, log /tmp/mfcbuild13b.log. Artifact artifacts/Bruce-m5stack-cardputer-adv-darkside-20261027-0757.bin.
- Hardware still blocked: no USB device. No flash, no tag read, no recovery claim. KPI NOT met.

## Field-off timing build
- `_mfcDarksideSelect` now drops RF field for 10 ms before reselect, matching mfcuk's `SLEEP_AT_FIELD_OFF`; normal nested `mfcReselect` still uses 5 ms.
- VM build 14 SUCCESS, 358.90s, merged image 3,850,816 bytes, SHA256 53b81a139896a349cde8e5cb5a852ffb000e0a5ce41b982ec0a68969a7ca54cf, log /tmp/mfcbuild14.log.
- Artifact artifacts/Bruce-m5stack-cardputer-adv-darkside-20261027-0813.bin; darkside strings verified.
- Hardware still blocked: no USB device. KPI NOT met.

## Compact UI and build 16
- Replaced MFC diagnostic/recovery screens with fixed-row 240x135 layouts, read progress bars (overall and per sector), recovery progress bar, and a paginated key table.
- Removed unused `_diagErrorClassStr`; build 16 compiled clean for the UI file.
- VM build 16 SUCCESS, 363.45s, merged image 3,853,136 bytes, SHA256 040f48ce3d4348f6eb5bb8a251b25f0dcf307be9c09068aa15e56a860ba72696, log /tmp/mfcbuild16.log. Artifact artifacts/Bruce-m5stack-cardputer-adv-darkside-ui-20261027-1748.bin.
- Flash PASS with 8 MB backup and verify; evidence /Users/engineer/.local/state/cardputer/20261027-175242-413910-flash.
- Hardware smoke/tag test PASS; `nested key recovery: cancelled` because the card was absent/removed. No darkside zero-key proof yet.

## Build 19, 55-key scan, and hardware truth
- Build 19 SUCCESS on VM, 7:36, merged image 3,864,480 bytes, SHA256 f0d992c6871f8289020b0e4e9d2bb99b041ea51527bb18feca26ead86a9429bb, log /tmp/mfcbuild19.log; artifact artifacts/Bruce-cardputer-adv-dict-20261031.bin.
- Flashed with verified 8 MB backup; evidence 20261031-193501-337326-flash (backup SHA256 4db62697...). A later redundant reflash aborted during backup at 3.6% before any write.
- Known-key read proven earlier on hardware: 16 blocks from sectors 0, 2, 3, 4, `Pages: 16`, `Total pages: 64` (20261031-003152-700640-test).
- 55-key dictionary regressed the read to 4 blocks (`Pages: 4`), reproduced twice. The scan exhausts card state; sector 1 stays `[AUTH FAIL]`.
- Crypto1 semantics re-verified against mfoc/libnfc/proxmark: zero-input after auth is correct. The earlier "crypto bug" theory was wrong.
- `recoverKey()` is the wrong attack: bootstrap-encrypted nonces cannot yield the target key. Darkside never received a NAK. Unknown-key recovery remains unproven on hardware.
