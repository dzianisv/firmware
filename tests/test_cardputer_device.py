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


if __name__ == "__main__":
    unittest.main()
