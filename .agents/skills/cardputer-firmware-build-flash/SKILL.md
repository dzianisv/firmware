---
name: cardputer-firmware-build-flash
description: Build this local Bruce fork for M5Stack Cardputer ADV on the Contabo VM, retrieve the merged image, flash it from the laptop with a verified 8 MB backup, and prove the result. Use when asked to "build Cardputer firmware", "flash the Cardputer", "make a merged bin", "update the local fork firmware", "build on the VM and flash", or "sync the fork and build". Not for changing the MIFARE recovery algorithm itself.
---

<role>
You build and flash the local Bruce fork for M5Stack Cardputer ADV. You do not edit the recovery algorithm unless the user also asked for that. You never claim hardware success from a compile alone.
</role>

<facts>
- Local fork: `/Users/engineer/workspace/m5stack/recovery-rf`, branch `recovery-rf`, base commit `078660f0`.
- Build VM: `root@109.123.252.30`, key `/Users/engineer/.ssh/id_ed25519`.
- VM checkout: `/opt/bruce-builds/cardputer-adv`.
- Launcher: `/opt/bruce-builds/build-cardputer.sh` (runs PlatformIO env `m5stack-cardputer-adv`, uses `/opt/bruce-builds/pio-packages`).
- Merged output: `Bruce-m5stack-cardputer-adv.bin`, flash at `0x0`.
- App-only output: `.pio/build/m5stack-cardputer-adv/firmware.bin`, flash at `0x10000`; do not use it for USB flashing.
- USB device: `/dev/cu.usbmodem101` (confirm; may change).
- Flash/test tool: `bruce-firmware/scripts/cardputer_device.py`, run from `/Users/engineer/workspace/m5stack` with `~/.venv/bin/python3`.
- Evidence: `~/.local/state/cardputer/<timestamp>-flash|test/`.
</facts>

<workflow>
1. Preflight the local fork.
   - Run `git status --short`, `git diff --stat 078660f0`, and `git log -1 --oneline`.
   - Confirm the intended files are in the diff. Never build uncommitted changes you have not inspected.
   - Confirm the device exists: `ls /dev/cu.usbmodem*`. If absent, build only and report flash BLOCKED.

2. Send exactly the intended source to the VM.
   - From `recovery-rf`, include intent-to-add files, then generate a binary patch:
     ```bash
     git add -N src/modules/rfid src/core/serial_commands/rfid_commands.cpp tests
     git diff --binary 078660f0 -- src/modules/rfid src/core/serial_commands/rfid_commands.cpp tests > /tmp/cardputer.patch
     scp -i ~/.ssh/id_ed25519 /tmp/cardputer.patch root@109.123.252.30:/tmp/cardputer.patch
     ```
   - Reset the VM checkout to the base, then check and apply:
     ```bash
     ssh -i ~/.ssh/id_ed25519 root@109.123.252.30 \
       'cd /opt/bruce-builds/cardputer-adv && git checkout -- . && \
        git clean -fd src/modules/rfid src/core/serial_commands tests && \
        git apply --check /tmp/cardputer.patch && git apply /tmp/cardputer.patch'
     ```
   - `git clean` is destructive. Run it only after the patch contains every intended change. Preserve unrelated VM work elsewhere.

3. Build detached so an SSH reset does not kill the build.
   ```bash
   ssh -i ~/.ssh/id_ed25519 root@109.123.252.30 \
     'cd /opt/bruce-builds/cardputer-adv && rm -f /tmp/cardputer-build.done && \
      nohup bash -c "/opt/bruce-builds/build-cardputer.sh > /tmp/cardputer-build.log 2>&1; echo \$? > /tmp/cardputer-build.done" >/dev/null 2>&1 & echo STARTED'
   ```
   Poll, do not restart blindly:
   ```bash
   ssh -i ~/.ssh/id_ed25519 root@109.123.252.30 \
     'test -f /tmp/cardputer-build.done && echo DONE=$(cat /tmp/cardputer-build.done) || echo RUNNING; tail -3 /tmp/cardputer-build.log'
   ```
   A dropped SSH connection does not mean the build failed. Check the done file and log before retrying.

4. Enforce build gates.
   - `/tmp/cardputer-build.done` contains `0`.
   - Log contains `[SUCCESS]` and `[merge_bin] Success`.
   - Merged file is nonempty and about 3.8 MB.
   - Record SHA256.
   - If the build fails, fix the compile error and rebuild. Do not flash an older image as if it were the new one.

5. Retrieve and freeze the artifact.
   ```bash
   scp -i ~/.ssh/id_ed25519 root@109.123.252.30:/opt/bruce-builds/cardputer-adv/Bruce-m5stack-cardputer-adv.bin \
     artifacts/Bruce-m5stack-cardputer-adv-<tag>.bin
   shasum -a 256 artifacts/Bruce-m5stack-cardputer-adv-<tag>.bin
   ```
   Use a unique tag with date/time. Keep the VM log path in the final report.

6. Flash from the laptop, never from the VM.
   ```bash
   ~/.venv/bin/python3 bruce-firmware/scripts/cardputer_device.py flash \
     --port /dev/cu.usbmodem101 \
     --image artifacts/Bruce-m5stack-cardputer-adv-<tag>.bin
   ```
   Require `PASS: firmware written and independently verified against flash`.
   The tool backs up all 8 MB and verifies the backup before writing. Do not bypass that.

7. Prove the running image.
   ```bash
   ~/.venv/bin/python3 bruce-firmware/scripts/cardputer_device.py test \
     --port /dev/cu.usbmodem101 --rfid --require-tag --recover --tag-timeout 30000
   ```
   `--tag-timeout` is milliseconds. `30000` means 30 seconds, not 30 ms.
   A `FAIL` or `BLOCKED` check is not success. A `nested key recovery: cancelled` result means the card was removed or ESC was seen; rerun with the card present.
</workflow>

<success_gates>
- Build: exit `0`, `[SUCCESS]`, nonempty merged image, SHA256 recorded.
- Flash: tool prints `PASS`, backup and verify logs exist in the evidence directory.
- Hardware: firmware identity, runtime, heap, display config, I2C, NFC init, and required tag read all `PASS`; no panic.
- Report the exact artifact path, size, SHA256, VM log path, flash evidence directory, and test evidence directory.
- If any gate is missing, state the gate and do not call the firmware verified.
</success_gates>

<pitfalls>
- SSH reset during a build: the nohup build continues. Poll the done file.
- `--tag-timeout` is ms. A short value looks like “no tag”.
- `--recover` exercises nested recovery over serial; it does not prove the darkside zero-known-key path.
- `New keys recovered: 0` means the card’s keys were already known, not that darkside works.
- Serial tests do not verify physical pixels or key presses. UI layout needs human/visual evidence.
- The merged image goes at `0x0`; the app-only image is not a USB flash image.
- Do not print recovered keys, full backups, or private evidence paths in shared output.
- The VM checkout may contain unrelated work. Inspect before `git clean`.
</pitfalls>

<output_format>
Return exactly these fields:
- `BUILD`: `SUCCESS` or `FAIL`; image path, bytes, SHA256; VM log path.
- `FLASH`: `PASS` or `FAIL`; evidence directory; port and MAC.
- `TEST`: `PASS`, `BLOCKED`, or `FAIL`; one line per check; evidence directory.
- `CAVEAT`: what was not proven (for example, darkside on a zero-known-key card, or physical UI pixels).
</output_format>

<stop_rules>
- Stop and report BLOCKED if no USB device is present; do not fake a flash.
- Stop and fix compile errors before flashing.
- Stop after the requested build/flash/test scope; do not merge, deploy, or erase NFC cards.
- If a test fails, report the exact failing check and evidence. Do not relabel it as a pass.
</stop_rules>
