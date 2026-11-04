#!/usr/bin/env python3
"""Flash and test a real USB-connected Cardputer ADV; never write NFC tags.

Dependencies: python3 -m pip install esptool pyserial
Examples (run from the laptop, not the build VM):
  python3 scripts/cardputer_device.py probe --port /dev/cu.usbmodem101
  python3 scripts/cardputer_device.py flash --image /path/to/merged.bin
  python3 scripts/cardputer_device.py test --rfid

Outputs default to ~/.local/state/cardputer/<timestamp>-<action>/ (private files).
A merged image starts at 0x0; application-only images are rejected. Flashing the
merged image can reset NVS/configuration; a complete flash backup is required.
Test exit 0 means no failed smoke checks; inspect BLOCKED checks in the JSON.
Use --require-tag when a successful tag read is a required acceptance check.
"""

import argparse
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time

FLASH_SIZE = 8 * 1024 * 1024
PANIC = re.compile(r"Guru Meditation|Backtrace:|abort\(\) was called|Brownout detector")


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def choose_port(requested):
    if requested:
        return requested
    from serial.tools.list_ports import comports
    ports = [p.device for p in comports() if p.vid == 0x303A]
    if len(ports) != 1:
        raise RuntimeError(f"Specify --port; found Espressif ports: {ports}")
    return ports[0]


def save_json(path, data):
    path.write_text(json.dumps(data, indent=2) + "\n")


def esptool(args, output, label, *command):
    cmd = ["/Users/engineer/.venv/bin/esptool", "--chip", "esp32s3",
           "--port", args.port, "--baud", "460800", *map(str, command)]
    log = output / f"{label}.log"
    print(f"Running {label}; log: {log}", flush=True)
    with log.open("w") as stream:
        result = subprocess.run(cmd, stdout=stream, stderr=subprocess.STDOUT, timeout=300)
    text = log.read_text(errors="replace")
    if result.returncode:
        print(text[-6000:])
        raise RuntimeError(f"{label} failed with exit {result.returncode}; see {log}")
    return text


def probe(args, output):
    text = esptool(args, output, "flash-id", "flash-id")
    if "ESP32-S3" not in text or "Detected flash size: 8MB" not in text:
        raise RuntimeError("Expected an ESP32-S3 with 8 MB flash; refusing to flash")
    mac = re.search(r"MAC:\s*([0-9a-f:]+)", text, re.I)
    result = {"port": args.port, "chip": "ESP32-S3", "flash_bytes": FLASH_SIZE,
              "mac": mac.group(1) if mac else None}
    save_json(output / "device.json", result)
    print(json.dumps(result), flush=True)
    return result


def flash(args, output):
    image = args.image.resolve()
    data = image.read_bytes()
    if not (0x10018 <= len(data) <= FLASH_SIZE and data[0] == 0xE9
            and data[0x8000:0x8002] == b"\xaa\x50" and data[0x10000] == 0xE9):
        raise RuntimeError("Not a merged bootloader/partition/app image; refusing to flash at 0x0")
    digest = hashlib.sha256(data).hexdigest()
    if args.sha256 and digest.lower() != args.sha256.lower():
        raise RuntimeError("Firmware SHA256 mismatch")
    # Freeze exactly the bytes checked above: a build may replace the input
    # while the device backup is running. Never flash that later replacement.
    staged = output / "firmware-merged.bin"
    with staged.open("xb") as stream:
        stream.write(data)
    device = probe(args, output)
    if not device["mac"]:
        raise RuntimeError("Device MAC unavailable; cannot bind rollback backup to this device")
    backup = args.existing_backup.resolve() if args.existing_backup else output / "backup-8mb.bin"
    if args.existing_backup:
        if backup.stat().st_size != FLASH_SIZE:
            raise RuntimeError("Existing backup is not a complete 8 MB image")
        manifest = json.loads(backup.with_suffix(backup.suffix + ".json").read_text())
        if (manifest.get("mac") != device["mac"] or
                manifest.get("sha256") != sha256(backup) or
                manifest.get("verified") is not True):
            raise RuntimeError("Existing backup is not verified for THIS device; refusing to flash")
        print(f"Using explicitly supplied verified backup: {backup}", flush=True)
    else:
        esptool(args, output, "backup", "read-flash", "0x0", hex(FLASH_SIZE), backup)
        if backup.stat().st_size != FLASH_SIZE:
            raise RuntimeError("Incomplete backup; refusing to flash")
        esptool(args, output, "backup-verify", "verify-flash", "0x0", backup)
        save_json(backup.with_suffix(backup.suffix + ".json"),
                  {"mac": device["mac"], "sha256": sha256(backup), "verified": True})
    report = {"device": device, "image": str(image), "staged_image": str(staged), "image_sha256": digest,
              "backup": str(backup), "backup_sha256": sha256(backup), "verified": False}
    save_json(output / "flash-result.json", report)
    esptool(args, output, "write", "write-flash", "0x0", staged)
    esptool(args, output, "verify", "verify-flash", "0x0", staged)
    report["verified"] = True
    save_json(output / "flash-result.json", report)
    print("PASS: firmware written and independently verified against flash", flush=True)


class Console:
    def __init__(self, port, output):
        import serial
        self.output = output
        self.serial = serial.Serial(port=None, baudrate=115200, timeout=0.1, write_timeout=3)
        self.serial.dtr = False
        self.serial.rts = False
        self.serial.port = port
        self.serial.open()
        self.transcript = (output / "serial-transcript.log").open("ab")

    def close(self):
        self.serial.close()
        self.transcript.close()

    def receive(self, seconds, prompt=False):
        data = bytearray()
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            chunk = self.serial.read(max(1, min(self.serial.in_waiting, 8192)))
            if chunk:
                data.extend(chunk)
                self.transcript.write(chunk)
                self.transcript.flush()
                if prompt and data.rstrip(b"\r\n").endswith(b"# "):
                    break
        return data.decode("utf-8", errors="replace")

    def command(self, text, label, timeout=8):
        # Commands are fixed, read-only operations; callers cannot pass arbitrary
        # erase/clone/write/autotest-default commands through this tool.
        self.receive(0.15)
        self.transcript.write(("\n>>> " + text + "\n").encode())
        self.serial.write((text + "\n").encode())
        self.serial.flush()
        response = self.receive(timeout, prompt=True)
        (self.output / f"{label}.log").write_text(response)
        return response


def uptime_seconds(text):
    match = re.search(r"Uptime:\s*(\d+):(\d+):(\d+)", text)
    return sum(int(value) * scale for value, scale in zip(match.groups(), (3600, 60, 1))) if match else None


def test(args, output):
    console = Console(args.port, output)
    checks = []

    def record(name, passed, detail, blocked=False):
        status = "BLOCKED" if blocked else ("PASS" if passed else "FAIL")
        checks.append({"name": name, "status": status, "detail": detail})
        print(f"{status}: {name}: {detail}", flush=True)

    try:
        boot = console.receive(3)
        (output / "boot.log").write_text(boot)
        info = ""
        for attempt in range(4):
            info = console.command("info", f"info-{attempt + 1}", timeout=8)
            if "Bruce v" in info:
                break
        record("firmware identity", "Bruce v" in info and "Device: M5Stack Cardputer ADV" in info,
               "Expected Bruce / M5Stack Cardputer ADV serial response")
        if "Bruce v" not in info:
            return 1
        first = uptime_seconds(console.command("uptime", "uptime-1"))
        time.sleep(2)
        second = uptime_seconds(console.command("uptime", "uptime-2"))
        record("runtime alive", first is not None and second is not None and second > first,
               f"Uptime advanced: {first} -> {second} seconds")
        heap = console.command("free", "heap")
        match = re.search(r"Free heap:\s*(\d+)", heap)
        record("heap available", bool(match and int(match.group(1)) >= 8192),
               f"Free heap: {match.group(1) if match else 'no response'} bytes")
        display = console.command("display info", "display-info")
        record("display configuration", "135x240x1" in display,
               "Serial-reported panel configuration; physical pixels not visually verified")
        nav = console.command("nav next", "navigation")
        record("remote navigation", "Next Pressed" in nav,
               "Serial navigation callback responded; physical keyboard presses not tested")
        bus = console.command("i2c", "i2c", timeout=12)
        reader_present = bool(re.search(r"0x50\b", bus, re.I))
        if args.rfid:
            record("NFC reader on I2C", reader_present, "ST25R3916 expected at Grove address 0x50")
            if reader_present:
                selected = console.command("settings rfidModule 6", "rfid-module")
                record("NFC module selection", "rfidModule = 6" in selected,
                       "Select ST25R3916 I2C; does not write an NFC tag")
                console.command("rfid reset", "rfid-reset")
                if args.skip_read:
                    result = ""
                else:
                    result = console.command(f"rfid read {args.tag_timeout}", "rfid-read",
                                             timeout=args.read_timeout)
                if args.skip_read:
                    module_ok = True
                    has_tag = False
                    record("NFC reader initialization", False,
                           "skipped: --skip-read", blocked=True)
                    record("NFC tag read", False, "skipped: --skip-read", blocked=True)
                    record("NFC data read", False, "skipped: --skip-read", blocked=True)
                else:
                    module_ok = "RFID module not found" not in result and ("Waiting for tag" in result)
                    record("NFC reader initialization", module_ok,
                           "Actual ST25R3916 initialization over I2C")
                has_tag = bool(re.search(r"^UID:[ \t]*[0-9A-Fa-f]{2}(?:[ :]|$)", result, re.M))
                missing_tag = "Tag not found" in result
                if not args.skip_read:
                    record("NFC tag read", has_tag, "UID received" if has_tag else
                           "No successful tag read; see rfid-read.log",
                           blocked=module_ok and missing_tag and not args.require_tag)
                pages_match = re.search(r"^Pages:\s*(\d+)", result, re.M)
                pages = int(pages_match.group(1)) if pages_match else 0
                is_mfc = "MIFARE Classic" in result
                blocks = re.findall(r"^Block\s+(\d+):\s*((?:[0-9A-Fa-f]{2}(?:\s+|$)){16})", result, re.M)
                read_blocks = {int(block) for block, _ in blocks}
                data_ok = pages > 0
                if args.require_full_read:
                    data_ok = is_mfc and pages == 64 and read_blocks == set(range(64))
                if not args.skip_read:
                    record("NFC data read", data_ok,
                           f"MIFARE pages reported: {pages}; complete blocks: {len(read_blocks)}"
                           if is_mfc else "Tag data pages read: "
                           + (str(pages) if pages else "none"))
                for spec in args.rfid_command:
                    label = "cmd-" + re.sub(r"[^a-z0-9]+", "-", spec.lower()).strip("-")
                    out = console.command(spec, label, timeout=args.command_timeout)
                    ok = not re.search(r"\b(ERROR|FAIL|failed)\b", out)
                    if spec.strip().startswith("rfid mfckey"):
                        ok = bool(re.search(r": PASS", out))
                    elif spec.strip().startswith("rfid mfcdarkside"):
                        ok = bool(re.search(r"Darkside result: (Verified|AlreadyKnown)", out))
                    elif spec.strip().startswith("rfid mfcstatic"):
                        ok = bool(re.search(r"Static result: Verified", out))
                    elif spec.strip().startswith("rfid read"):
                        # A partial read is a success as long as blocks came back;
                        # [AUTH FAIL] on an unknown sector is not a read failure.
                        pages_match = re.search(r"^Pages:\s*(\d+)", out, re.M)
                        ok = bool(pages_match) and int(pages_match.group(1)) > 0
                    elif spec.strip().startswith("rfid recover"):
                        ok = bool(re.search(r"New keys recovered:\s*\d+", out))
                    first = next((l.strip() for l in reversed(out.splitlines()) if l.strip()), "")
                    record(f"serial: {spec}", ok, first[:200] or "no output")
                if args.recover and has_tag:
                    # Drain any pending serial input so the recovery callback doesn't cancel itself.
                    try:
                        console.serial.reset_input_buffer()
                    except Exception:
                        pass
                    time.sleep(0.2)
                    command = "rfid recover 5000"
                    if args.recover_sector is not None:
                        command += f" {args.recover_sector}"
                    recovery = console.command(command, "rfid-recover", timeout=args.recover_timeout)
                    count = re.search(r"New keys recovered:\s*(\d+)", recovery)
                    cancelled = "Recovery cancelled" in recovery
                    recovery_ok = count is not None and int(count.group(1)) >= 0 and not cancelled
                    record("nested key recovery", recovery_ok,
                           f"{command}: New keys recovered: {count.group(1) if count else 'cancelled'}")
                    reread = re.search(r"^Pages:\s*(\d+)", recovery, re.M)
                    reread_pages = int(reread.group(1)) if reread else 0
                    target = args.recover_sector
                    expected = 16 + 4 if target is not None and target < 16 else None
                    reread_ok = reread_pages > 0 and (expected is None or reread_pages >= expected)
                    record("re-read after recovery", reread_ok,
                           f"Pages after recovery: {reread_pages}"
                           + (f" (expected >= {expected})" if expected else ""))
            else:
                record("NFC tag read", False, "Reader is absent or not responding on Grove I2C", blocked=True)
        record("no observed panic", not PANIC.search((output / "serial-transcript.log").read_text(errors="replace")),
               "No panic/backtrace/brownout in captured serial output")
    except Exception as error:
        record("test execution", False, str(error))
    finally:
        try:
            console.close()
        except Exception as error:
            record("console shutdown", False, str(error))
        report = {"port": args.port, "checks": checks,
                  "limitations": ["Physical display pixels and key presses not verified",
                                  "UI recovery flow not exercised; --recover uses serial rfid recover"],
                  "passed": bool(checks) and all(c["status"] == "PASS" for c in checks),
                  "smoke_passed": bool(checks) and all(c["status"] != "FAIL" for c in checks),
                  "blocked_checks": sum(c["status"] == "BLOCKED" for c in checks)}
        save_json(output / "test-result.json", report)
    return 0 if report["smoke_passed"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("action", choices=("probe", "flash", "test"))
    parser.add_argument("--port", help="Auto-detect exactly one Espressif USB port when omitted")
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--image", type=Path, help="Merged .bin, not the application-only .pio firmware.bin")
    parser.add_argument("--sha256", help="Expected merged firmware SHA256")
    parser.add_argument("--existing-backup", type=Path,
                        help="Reuse this tool's verified backup with adjacent .bin.json device/hash manifest")
    parser.add_argument("--rfid", action="store_true", help="Probe ST25R3916 and attempt a read-only tag read")
    parser.add_argument("--require-tag", action="store_true", help="Fail, rather than block, if no tag is present")
    parser.add_argument("--require-full-read", action="store_true",
                        help="Fail unless a MIFARE Classic tag returns all 64 pages")
    parser.add_argument("--tag-timeout", type=int, default=3000)
    parser.add_argument("--read-timeout", type=int, default=300,
                        help="Seconds to wait for `rfid read` (default 300)")
    parser.add_argument("--skip-read", action="store_true",
                        help="Skip the standard `rfid read` sweep")
    parser.add_argument("--rfid-command", action="append", default=[],
                        metavar="CMD",
                        help="Extra read-only serial command to run and record; repeatable")
    parser.add_argument("--command-timeout", type=int, default=900,
                        help="Seconds to wait for each --rfid-command (default 900)")
    parser.add_argument("--recover-sector", type=int, default=None,
                        help="Limit `rfid recover` to this sector")
    parser.add_argument("--recover-timeout", type=int, default=900,
                        help="Seconds to wait for `rfid recover` (default 900)")
    parser.add_argument("--recover", action="store_true",
                        help="After a successful tag read, run read-only rfid recover over serial")
    args = parser.parse_args()
    if args.action == "flash" and not args.image:
        parser.error("flash requires --image")
    if not 1 <= args.tag_timeout <= 30000:
        parser.error("--tag-timeout must be between 1 and 30000 milliseconds")
    if args.require_tag or args.recover or args.require_full_read:
        args.rfid = True
    os.umask(0o077)
    args.port = choose_port(args.port)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    output = (args.output_dir or Path.home() / ".local" / "state" / "cardputer" / f"{stamp}-{args.action}").resolve()
    if output.is_relative_to(Path(__file__).resolve().parents[1]):
        parser.error("--output-dir must be outside the repository; backups and tag logs can contain secrets")
    # A fresh directory prevents stale reports and overwriting an earlier backup.
    output.mkdir(mode=0o700, parents=True, exist_ok=False)
    print(f"Evidence directory: {output}", flush=True)
    try:
        if args.action == "probe":
            probe(args, output)
        elif args.action == "flash":
            flash(args, output)
        else:
            return test(args, output)
    except Exception as error:
        save_json(output / "error.json", {"error": str(error), "port": args.port})
        print(f"ERROR: {error}; evidence: {output}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
