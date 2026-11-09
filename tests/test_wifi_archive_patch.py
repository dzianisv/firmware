"""Exercise patch.py's archive transaction with real GNU tools, without building firmware.

Run on Linux: python3 -m unittest discover -s tests -p 'test_wifi_archive_patch.py'
Only PlatformIO's metadata adapter is supplied here; compilation, objcopy and
archive inspection execute real commands against temporary files.
"""

import ast
import hashlib
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


class BuildEnvironment:
    def __init__(self, framework, toolchain):
        self.framework = framework
        self.toolchain = toolchain

    def PioPlatform(self):
        return self

    def get_package_dir(self, package):
        if package == "framework-arduinoespressif32-libs":
            return str(self.framework)
        if package == "toolchain-xtensa-esp-elf":
            return str(self.toolchain)
        raise AssertionError("Unexpected package: " + package)

    def BoardConfig(self):
        return {"build.mcu": "esp32s3"}

    def Execute(self, command):
        return subprocess.run(command, shell=True, capture_output=True).returncode


@unittest.skipUnless(
    all(shutil.which(tool) for tool in ("cc", "ar", "objcopy", "nm", "false")),
    "requires a C compiler and GNU binutils",
)
class WifiArchivePatchTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        source = Path(__file__).resolve().parents[1] / "patch.py"
        module = ast.parse(source.read_text())
        # Run the actual pre-script through its archive-patching section, not
        # the unrelated web-resource generation which follows hash_file().
        prefix = []
        for node in module.body:
            if isinstance(node, ast.FunctionDef) and node.name == "hash_file":
                break
            if isinstance(node, ast.Import) and any(n.name == "requests" for n in node.names):
                continue
            prefix.append(node)
        cls.script = compile(ast.Module(body=prefix, type_ignores=[]), str(source), "exec")

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        root = Path(self.tmp.name)
        self.framework = root / "framework"
        lib = self.framework / "esp32s3" / "lib"
        lib.mkdir(parents=True)
        self.archive = lib / "libnet80211.a"
        self.backup = lib / "libnet80211.a.old"
        self.marker = lib / ".patched"
        self.toolchain = root / "toolchain"
        (self.toolchain / "bin").mkdir(parents=True)
        self.objcopy = self.toolchain / "bin" / "xtensa-esp-elf-objcopy"
        self.objcopy.symlink_to(shutil.which("objcopy"))
        source = root / "fixture.c"
        source.write_text("int ieee80211_raw_frame_sanity_check(void) { return 42; }\n")
        obj = root / "fixture.o"
        subprocess.run(["cc", "-c", str(source), "-o", str(obj)], check=True)
        subprocess.run(["ar", "rcs", str(self.archive), str(obj)], check=True)
        self.original = self.archive.read_bytes()

    def run_patch(self):
        exec(self.script, {"env": BuildEnvironment(self.framework, self.toolchain), "Import": lambda _: None})

    def test_success_and_idempotence(self):
        self.run_patch()
        self.assertTrue(self.marker.is_file())
        self.assertEqual(self.backup.read_bytes(), self.original)
        symbols = subprocess.check_output(["nm", "-g", str(self.archive)], text=True)
        self.assertRegex(symbols, r"\bW ieee80211_raw_frame_sanity_check\b")
        patched_hash = hashlib.sha256(self.archive.read_bytes()).digest()
        # A subsequent build must not invoke even a deliberately failing tool.
        self.objcopy.unlink()
        self.objcopy.symlink_to(shutil.which("false"))
        self.run_patch()
        self.assertEqual(hashlib.sha256(self.archive.read_bytes()).digest(), patched_hash)

    def test_failure_preserves_original_without_success_marker(self):
        self.objcopy.unlink()
        self.objcopy.symlink_to(shutil.which("false"))
        Path(str(self.archive) + ".patched").write_bytes(b"stale partial output")
        with self.assertRaisesRegex(RuntimeError, "original left intact"):
            self.run_patch()
        self.assertEqual(self.archive.read_bytes(), self.original)
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.backup.exists())

    def test_repairs_old_missing_archive_and_stale_marker(self):
        self.archive.rename(self.backup)
        self.marker.touch()
        self.run_patch()
        self.assertTrue(self.archive.is_file())
        self.assertEqual(self.backup.read_bytes(), self.original)
        self.assertEqual(self.marker.read_text(), "objcopy patch completed\n")

    def test_missing_archive_fails_clearly(self):
        self.archive.unlink()
        with self.assertRaisesRegex(RuntimeError, "Wi-Fi archive missing"):
            self.run_patch()


if __name__ == "__main__":
    unittest.main()
