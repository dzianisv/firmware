# Local review

## Fixed in this session
- `scripts/cardputer_device.py`: exceptions after a successful first smoke check could leave `smoke_passed: true`. Exceptions and console-close failures now produce failed checks.
- `scripts/cardputer_device.py`: the input was reread after hashing and again after a lengthy backup, so a concurrent build could change the bytes flashed. Write/verify now use an exclusive staged copy of exactly the checked bytes.
- `scripts/cardputer_device.py`: an arbitrary 8 MB file was accepted as a reusable backup. Existing backups now require a matching MAC/hash/verified manifest; newly read backups are independently checked against device flash before writes are permitted.
- `scripts/cardputer_device.py`: reusing an output directory could overwrite evidence and rollback data. A fresh private directory outside the repo is now required.
- Documentation incorrectly promised serial-key redaction. The CLI emits stored tag data and keys; documentation now warns that logs are sensitive.

## Unresolved blockers for the requested firmware
- `src/modules/rfid/ST25R3916.cpp`: existing experimental fallback never derives an unknown Crypto1 key; it can only recheck the already-known bootstrap key. It must not be described as working unknown-key recovery.
- The existing nested authentication branch uses the previous cipher to decode the new nonce. Its target-key handling needs protocol review and physical tests; no fix integrated here.
- RF recovery worker was rejected by the tool security policy. It was not retried through an alternate route. The independent solver worker was stopped; its partial untracked files remain isolated in ../recovery-solver and are NOT in this firmware.
- Latest real reader test reported no detected tag. No card authentication/recovery success has been observed.

## Validation
- Python compilation: pass.
- 13 unit tests pass, including actual GNU archive operations using PlatformIO's cross-toolchain. USB fault tests are control-flow fixtures, not hardware verification.
- Actual USB smoke of current device: 6 checks pass; physical display pixels and key presses are not verified.
- Independent review unavailable: Copilot subscription ended; alternative reviewer model unsupported by the account. Findings above are the parent agent's review, not an independent approval.
- No new firmware has been flashed during this session. No tag writes were performed.
