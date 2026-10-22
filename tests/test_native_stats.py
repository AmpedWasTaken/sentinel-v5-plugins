"""Compile C from source and exercise the actual isolated Python/C plugin."""
from __future__ import annotations

import ctypes
import importlib.util
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SDK = REPO / "sdk" / "python"
PLUGIN = REPO / "plugins" / "native-stats"


def checksum(data: bytes) -> int:
    value = 14695981039346656037
    for byte in data:
        value = ((value ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return value


class NativeStatsIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform == "win32":
            if not any(shutil.which(name) for name in ("cl", "gcc", "clang")):
                raise unittest.SkipTest("C compiler unavailable")
        elif not any(shutil.which(name) for name in ("cc", "gcc", "clang")):
            raise unittest.SkipTest("C compiler unavailable")
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.plugin = cls.root / "plugins" / "native-stats"
        cls.native = cls.plugin / "native"
        cls.native.mkdir(parents=True)
        sdk_dir = cls.root / "sdk" / "python"
        sdk_dir.mkdir(parents=True)
        for name in ("sentinel_sdk.py", "sentinel_native.py"):
            shutil.copy2(SDK / name, sdk_dir / name)
        for name in ("main.py", "build_native.py"):
            shutil.copy2(PLUGIN / name, cls.plugin / name)
        for name in ("stats.c", "stats.h"):
            shutil.copy2(PLUGIN / "native" / name, cls.native / name)
        result = subprocess.run(
            [sys.executable, "-I", str(cls.plugin / "build_native.py")],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            check=False,
            timeout=25,
        )
        if result.returncode:
            cls.temp.cleanup()
            raise AssertionError(
                "native C compile failed:\n" + result.stderr.decode("utf-8", "replace")
            )

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    @classmethod
    def request(cls, command: str, **args: str) -> dict:
        payload = json.dumps({
            "version": 1, "command": command,
            "actor": "tester", "role": "admin", "args": args,
        }).encode("utf-8")
        result = subprocess.run(
            [sys.executable, "-I", str(cls.plugin / "main.py")],
            input=payload,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            check=False,
        )
        if result.returncode:
            raise AssertionError(result.stderr.decode("utf-8", "replace"))
        return json.loads(result.stdout)

    def test_native_c_abi_info(self):
        result = self.request("info")
        self.assertNotIn("error", result)
        self.assertEqual(result["result"]["view"], "info")
        self.assertEqual(result["result"]["values"]["abi"], "1")

    def test_compiled_c_byte_statistics(self):
        for text, letters, digits, spaces in (
            ("Hello 123", 5, 3, 1),
            ("SentinelV5", 9, 1, 0),
            ("hé2", 1, 1, 0),
        ):
            with self.subTest(text=text):
                result = self.request("analyze", text=text)
                self.assertNotIn("error", result)
                self.assertEqual(result["result"]["view"], "analysis")
                values = result["result"]["values"]
                self.assertEqual(int(values["bytes"]), len(text.encode("utf-8")))
                self.assertEqual(int(values["letters"]), letters)
                self.assertEqual(int(values["digits"]), digits)
                self.assertEqual(int(values["spaces"]), spaces)
                self.assertEqual(values["fnv64"], f"{checksum(text.encode('utf-8')):016x}")

    def test_command_validation(self):
        self.assertIn("error", self.request("analyze"))
        self.assertIn("error", self.request("info", unexpected="x"))
        self.assertIn("error", self.request("unknown"))

    def test_native_loader_rejects_unsafe_library_names(self):
        spec = importlib.util.spec_from_file_location(
            "sentinel_native_integration", self.root / "sdk" / "python" / "sentinel_native.py"
        )
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        for bad in ("../escape", "/tmp/foo", "evil.dll", "bad-name", "", "a" * 34):
            with self.subTest(name=bad):
                with self.assertRaises(ValueError):
                    module.library_filename(bad)

    def test_missing_compiled_library_fails_closed(self):
        suffix = ".dll" if sys.platform == "win32" else (".dylib" if sys.platform == "darwin" else ".so")
        filename = "sentinelstats" + suffix if sys.platform == "win32" else "libsentinelstats" + suffix
        compiled = self.native / filename
        temp_name = self.native / ("hidden-" + filename)
        compiled.rename(temp_name)
        try:
            result = self.request("info")
            self.assertIn("error", result)
            self.assertIn("compiled native library", result["error"])
        finally:
            temp_name.rename(compiled)


if __name__ == "__main__":
    unittest.main()
