"""Safety/parser checks for the saved USB tool; no hardware is flashed here."""

import hashlib
import importlib.util
import json
from unittest.mock import patch
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest

SPEC = importlib.util.spec_from_file_location(
    "cardputer_device", Path(__file__).resolve().parents[1] / "scripts" / "cardputer_device.py"
)
DEVICE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEVICE)


class CardputerDeviceTest(unittest.TestCase):
    def test_rejects_application_only_before_contacting_device(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "application.bin"
            image.write_bytes(b"\xe9" + bytes(4095))
            with self.assertRaisesRegex(RuntimeError, "Not a merged"):
                DEVICE.flash(SimpleNamespace(image=image), root)

    def test_rejects_checksum_mismatch_before_contacting_device(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "merged.bin"
            contents = bytearray(0x10018)
            contents[0] = 0xE9
            contents[0x8000:0x8002] = b"\xaa\x50"
            contents[0x10000] = 0xE9
            image.write_bytes(contents)
            with self.assertRaisesRegex(RuntimeError, "SHA256 mismatch"):
                DEVICE.flash(SimpleNamespace(image=image, sha256="0" * 64), root)

    def test_serial_exception_cannot_produce_passing_report(self):
        # Control-flow regression only; live USB smoke remains separate.
        class BrokenConsole:
            def __init__(self, port, output):
                pass

            def receive(self, seconds):
                return ""

            def command(self, text, label, timeout=8):
                if text == "info":
                    return "Bruce vtest\nDevice: M5Stack Cardputer ADV"
                raise OSError("USB disconnected")

            def close(self):
                pass

        with tempfile.TemporaryDirectory() as directory, patch.object(DEVICE, "Console", BrokenConsole):
            root = Path(directory)
            self.assertEqual(DEVICE.test(SimpleNamespace(port="fixture"), root), 1)
            report = json.loads((root / "test-result.json").read_text())
            self.assertFalse(report["passed"])
            self.assertFalse(report["smoke_passed"])
            self.assertEqual(report["checks"][-1]["status"], "FAIL")

    def test_flash_uses_frozen_image_and_verifies_backup_before_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            output = root / "evidence"
            output.mkdir()
            image = root / "merged.bin"
            contents = bytearray(0x10018)
            contents[0] = contents[0x10000] = 0xE9
            contents[0x8000:0x8002] = b"\xaa\x50"
            image.write_bytes(contents)
            labels = []

            def tool(args, output, label, *command):
                labels.append(label)
                if label == "backup":
                    command[-1].write_bytes(bytes(DEVICE.FLASH_SIZE))
                    image.write_bytes(b"concurrent build replacement")
                if label in ("write", "verify"):
                    self.assertEqual(command[-1].read_bytes(), contents)

            args = SimpleNamespace(image=image, sha256=None, existing_backup=None)
            with patch.object(DEVICE, "probe", return_value={"mac": "test-device"}), patch.object(DEVICE, "esptool", tool):
                DEVICE.flash(args, output)
            self.assertEqual(labels, ["backup", "backup-verify", "write", "verify"])
            manifest = json.loads((output / "backup-8mb.bin.json").read_text())
            self.assertTrue(manifest["verified"])
            self.assertEqual(manifest["mac"], "test-device")

    def test_backup_for_other_device_is_rejected_before_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "merged.bin"
            contents = bytearray(0x10018)
            contents[0] = contents[0x10000] = 0xE9
            contents[0x8000:0x8002] = b"\xaa\x50"
            image.write_bytes(contents)
            backup = root / "backup.bin"
            backup.write_bytes(bytes(DEVICE.FLASH_SIZE))
            backup.with_suffix(".bin.json").write_text(json.dumps({
                "mac": "different-device", "sha256": DEVICE.sha256(backup), "verified": True,
            }))
            args = SimpleNamespace(image=image, sha256=None, existing_backup=backup)
            with patch.object(DEVICE, "probe", return_value={"mac": "connected-device"}), patch.object(DEVICE, "esptool") as tool:
                with self.assertRaisesRegex(RuntimeError, "THIS device"):
                    DEVICE.flash(args, root)
                tool.assert_not_called()

    def test_backup_verification_failure_prevents_write(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            image = root / "merged.bin"
            contents = bytearray(0x10018)
            contents[0] = contents[0x10000] = 0xE9
            contents[0x8000:0x8002] = b"\xaa\x50"
            image.write_bytes(contents)
            labels = []

            def tool(args, output, label, *command):
                labels.append(label)
                if label == "backup":
                    command[-1].write_bytes(bytes(DEVICE.FLASH_SIZE))
                if label == "backup-verify":
                    raise RuntimeError("backup mismatch")

            args = SimpleNamespace(image=image, sha256=None, existing_backup=None)
            with patch.object(DEVICE, "probe", return_value={"mac": "test-device"}), patch.object(DEVICE, "esptool", tool):
                with self.assertRaisesRegex(RuntimeError, "backup mismatch"):
                    DEVICE.flash(args, root)
            self.assertEqual(labels, ["backup", "backup-verify"])
            self.assertFalse((root / "backup-8mb.bin.json").exists())

    def test_uptime_parsing(self):
        self.assertEqual(DEVICE.uptime_seconds("COMMAND: uptime\nUptime: 02:03:04\n# "), 7384)
        self.assertIsNone(DEVICE.uptime_seconds("No response"))

    def test_explicit_port_requires_no_hardware_discovery(self):
        self.assertEqual(DEVICE.choose_port("/dev/cu.usbmodem101"), "/dev/cu.usbmodem101")

    def test_saved_file_checksum(self):
        with tempfile.TemporaryDirectory() as directory:
            image = Path(directory) / "image.bin"
            image.write_bytes(b"firmware fixture")
            self.assertEqual(DEVICE.sha256(image), hashlib.sha256(b"firmware fixture").hexdigest())

    # --- Scoring regressions: zero-evidence output must never score PASS. ---
    BASE_RESPONSES = {
        "info": "Bruce vtest\nDevice: M5Stack Cardputer ADV\n# ",
        "uptime": "Uptime: 00:00:01\n# ",
        "free": "Free heap: 100000\n# ",
        "display info": "135x240x1\n# ",
        "nav next": "Next Pressed\n# ",
        "i2c": "Found device at 0x50\n# ",
        "settings rfidModule 6": "rfidModule = 6\n# ",
        "rfid reset": "RFID reset\n# ",
        "rfid read 3000": "Waiting for tag\nUID: 01 02 03 04\nMIFARE Classic\nPages: 12\n# ",
    }

    def run_scripted_test(self, responses, **options):
        """Drive DEVICE.test with a scripted console and return {check name: status}."""
        merged = dict(self.BASE_RESPONSES)
        merged.update(responses)

        class ScriptedConsole:
            def __init__(self, port, output):
                self.output = output
                (output / "serial-transcript.log").write_text("scripted serial transcript\n")
                self.serial = SimpleNamespace(reset_input_buffer=lambda: None)

            def receive(self, seconds, prompt=False):
                return "Ready\n"

            def command(self, text, label, timeout=8):
                response = merged.get(text, "")
                (self.output / f"{label}.log").write_text(response)
                return response

            def close(self):
                pass

        args = SimpleNamespace(port="fixture", rfid=True, skip_read=False, tag_timeout=3000,
                               read_timeout=300, require_tag=False, require_full_read=False,
                               rfid_command=[], command_timeout=8, recover=False,
                               recover_sector=None, recover_timeout=8)
        for key, value in options.items():
            setattr(args, key, value)
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(DEVICE, "Console", ScriptedConsole), \
                patch.object(DEVICE.time, "sleep", lambda *_: None):
            root = Path(directory)
            DEVICE.test(args, root)
            report = json.loads((root / "test-result.json").read_text())
        return {check["name"]: check["status"] for check in report["checks"]}

    def test_zero_keys_recovered_is_a_failure(self):
        # Old matcher accepted "New keys recovered: 0" because it only looked for digits.
        statuses = self.run_scripted_test({"rfid recover 5000": "New keys recovered: 0\n# "},
                                          rfid_command=["rfid recover 5000"])
        self.assertEqual(statuses["serial: rfid recover 5000"], "FAIL")

    def test_one_key_recovered_is_a_pass(self):
        statuses = self.run_scripted_test({"rfid recover 5000": "New keys recovered: 1\n# "},
                                          rfid_command=["rfid recover 5000"])
        self.assertEqual(statuses["serial: rfid recover 5000"], "PASS")

    def test_cancelled_recovery_command_is_a_failure(self):
        statuses = self.run_scripted_test(
            {"rfid recover 5000": "Recovery cancelled\nNew keys recovered: 0\n# "},
            rfid_command=["rfid recover 5000"])
        self.assertEqual(statuses["serial: rfid recover 5000"], "FAIL")

    def test_nested_recovery_with_zero_keys_is_a_failure(self):
        statuses = self.run_scripted_test({"rfid recover 5000": "New keys recovered: 0\n# "},
                                          recover=True)
        self.assertEqual(statuses["nested key recovery"], "FAIL")

    def test_nested_recovery_with_keys_is_a_pass(self):
        statuses = self.run_scripted_test(
            {"rfid recover 5000": "New keys recovered: 1\nPages: 64\n# "}, recover=True)
        self.assertEqual(statuses["nested key recovery"], "PASS")

    def test_nested_recovery_cancelled_is_a_failure(self):
        # Keys reported but the operator cancelled: cancellation still fails the check.
        statuses = self.run_scripted_test(
            {"rfid recover 5000": "New keys recovered: 2\nRecovery cancelled\nPages: 64\n# "},
            recover=True)
        self.assertEqual(statuses["nested key recovery"], "FAIL")

    def test_rfid_read_with_zero_pages_is_a_failure(self):
        statuses = self.run_scripted_test({"rfid read 3000": "UID: 01 02 03 04\nPages: 0\n# "},
                                          rfid_command=["rfid read 3000"])
        self.assertEqual(statuses["serial: rfid read 3000"], "FAIL")
        self.assertEqual(statuses["NFC data read"], "FAIL")

    def test_rfid_read_with_pages_is_a_pass(self):
        statuses = self.run_scripted_test({}, rfid_command=["rfid read 3000"])
        self.assertEqual(statuses["serial: rfid read 3000"], "PASS")
        self.assertEqual(statuses["NFC data read"], "PASS")

    def test_rfid_command_without_output_is_a_failure(self):
        statuses = self.run_scripted_test({"rfid savelist": ""},
                                          rfid_command=["rfid savelist"])
        self.assertEqual(statuses["serial: rfid savelist"], "FAIL")

    def test_rfid_command_with_plain_output_is_a_pass(self):
        # Control: the fallback still accepts genuine non-empty evidence.
        statuses = self.run_scripted_test({"rfid savelist": "0 keys saved\n# "},
                                          rfid_command=["rfid savelist"])
        self.assertEqual(statuses["serial: rfid savelist"], "PASS")


if __name__ == "__main__":
    unittest.main()
