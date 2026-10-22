"""End-to-end PacketLens tests: compile C, use Python -I, parse synthetic PCAP."""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
SOURCE = REPO / "plugins" / "packetlens"
SDK = REPO / "sdk" / "python"


class PacketLensTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if sys.platform == "win32":
            if not any(shutil.which(x) for x in ("cl", "gcc", "clang")):
                raise unittest.SkipTest("C compiler not available")
        elif not any(shutil.which(x) for x in ("cc", "gcc", "clang")):
            raise unittest.SkipTest("C compiler not available")
        cls.temp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.temp.name)
        cls.plugin = cls.root / "plugins" / "packetlens"
        (cls.plugin / "native").mkdir(parents=True)
        (cls.plugin / "captures").mkdir()
        (cls.root / "sdk" / "python").mkdir(parents=True)
        for name in ("main.py", "build_native.py", "generate_sample.py"):
            shutil.copy2(SOURCE / name, cls.plugin / name)
        for name in ("packetlens.h", "packetlens.c"):
            shutil.copy2(SOURCE / "native" / name, cls.plugin / "native" / name)
        for name in ("sentinel_sdk.py", "sentinel_native.py"):
            shutil.copy2(SDK / name, cls.root / "sdk" / "python" / name)

        compile_result = subprocess.run(
            [sys.executable, "-I", str(cls.plugin / "build_native.py")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25, check=False,
        )
        if compile_result.returncode:
            cls.temp.cleanup()
            raise AssertionError(
                "PacketLens C compile failed: " +
                compile_result.stderr.decode("utf-8", "replace")
            )
        sample_result = subprocess.run(
            [sys.executable, "-I", str(cls.plugin / "generate_sample.py")],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10, check=False,
        )
        if sample_result.returncode:
            cls.temp.cleanup()
            raise AssertionError(sample_result.stderr.decode("utf-8", "replace"))

        spec = importlib.util.spec_from_file_location(
            "packetlens_fixture", cls.plugin / "generate_sample.py"
        )
        assert spec is not None and spec.loader is not None
        cls.fixture = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.fixture)

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "temp"):
            cls.temp.cleanup()

    @classmethod
    def command(cls, name: str, **args: str) -> dict:
        payload = json.dumps({
            "version": 1, "command": name, "actor": "analyst",
            "role": "admin", "args": args,
        }).encode()
        process = subprocess.run(
            [sys.executable, "-I", str(cls.plugin / "main.py")],
            input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=10, check=False,
        )
        if process.returncode:
            raise AssertionError(process.stderr.decode("utf-8", "replace"))
        return json.loads(process.stdout)

    def test_real_native_parser_on_synthetic_traffic(self):
        result = self.command("analyze", capture="sample")
        self.assertNotIn("error", result)
        self.assertEqual(result["result"]["view"], "analysis")
        values = result["result"]["values"]
        expected = {
            "frames": "10",
            "ipv4": "7",
            "ipv6": "1",
            "arp": "1",
            "tcp": "6",
            "udp": "2",
            "malformed": "1",
            "syn": "3",
            "rst": "1",
            "dns": "1",
            "http": "1",
            "tls": "4",
        }
        for key, expected_value in expected.items():
            with self.subTest(key=key):
                self.assertEqual(values[key], expected_value)
        sources = json.loads(values["sources"])
        self.assertEqual(sources[0]["ip"], "192.0.2.5")
        self.assertEqual(sources[0]["packets"], "3")
        ports = json.loads(values["ports"])
        self.assertTrue(any(p["port"] == "443" and p["proto"] == "TCP" and p["packets"] == "3" for p in ports))
        self.assertIn("Malformed", values["signal"])

    def test_big_endian_pcap(self):
        (self.plugin / "captures" / "big.pcap").write_bytes(
            self.fixture.build(big_endian=True)
        )
        values = self.command("analyze", capture="big")["result"]["values"]
        self.assertEqual(values["frames"], "10")
        self.assertEqual(values["tcp"], "6")

    def test_list_and_info(self):
        listed = self.command("list")["result"]
        self.assertEqual(listed["view"], "captures")
        self.assertTrue(any(x["name"] == "sample" for x in json.loads(listed["values"]["files"])))
        info = self.command("info")["result"]
        self.assertEqual(info["values"]["abi"], "1")
        self.assertEqual(info["values"]["max_size"], "8 MiB")

    def test_rejects_path_traversal_and_unknown_args(self):
        for args in ({"capture": "../sample"}, {"capture": "sample.pcap"},
                     {"capture": "/etc/passwd"}, {"capture": "sample", "target": "1.2.3.4"}):
            with self.subTest(args=args):
                self.assertIn("error", self.command("analyze", **args))
        self.assertIn("error", self.command("list", unexpected="value"))

    def test_rejects_bad_pcap_and_unsupported_linktype(self):
        capture = self.plugin / "captures" / "bad.pcap"
        for data in (
            b"\x00" * 24,
            self.fixture.build()[:29],
            self.fixture.build()[:40],
        ):
            with self.subTest(size=len(data)):
                capture.write_bytes(data)
                self.assertIn("error", self.command("analyze", capture="bad"))
        data = bytearray(self.fixture.build())
        data[20:24] = (101).to_bytes(4, "little")
        capture.write_bytes(bytes(data))
        self.assertIn("only classic Ethernet", self.command("analyze", capture="bad")["error"])

    def test_refuses_symlinked_capture(self):
        alias = self.plugin / "captures" / "linked.pcap"
        try:
            alias.symlink_to(self.plugin / "captures" / "sample.pcap")
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not permitted by environment")
        self.assertIn("symlinked", self.command("analyze", capture="linked")["error"])

    def test_rejects_oversized_capture(self):
        large = self.plugin / "captures" / "large.pcap"
        with open(large, "wb") as handle:
            handle.truncate(8 * 1024 * 1024 + 1)
        self.assertIn("8 MiB", self.command("analyze", capture="large")["error"])


if __name__ == "__main__":
    unittest.main()
