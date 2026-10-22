#!/usr/bin/env python3
"""Run safe real protocol smoke tests against reviewed Linux/amd64 plugin binaries.

No network calls or host administration. The release process fails if a
compiled binary can't handle its declared command using Sentinel's JSON v1.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import subprocess

ROOT = Path("build-plugins/linux-amd64")
FIXTURES = (
    ("hashkit", "digest", {"data": "SentinelV5"}),
    ("jsonfix", "format", {"data": '{"ready":true}'}),
    ("hookbin", "inspect", {"data": '{"hello":"world"}'}),
)


def smoke() -> None:
    for plugin, command, args in FIXTURES:
        exe = ROOT / plugin
        request = json.dumps({
            "version": 1,
            "command": command,
            "actor": "release-ci",
            "role": "admin",
            "args": args,
        }).encode("utf-8")
        result = subprocess.run(
            [str(exe.resolve(strict=True))],
            input=request,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=4,
            check=False,
        )
        if result.returncode or len(result.stdout) > 32768:
            raise ValueError(f"{plugin}: failed, crashed or oversized response")
        decoded = json.loads(result.stdout)
        if decoded.get("version") != 1 or decoded.get("error") or not isinstance(decoded.get("result"), dict):
            raise ValueError(f"{plugin}: invalid JSON protocol response")
        output = decoded["result"].get("text")
        if not isinstance(output, str):
            raise ValueError(f"{plugin}: missing plain text response")
        if plugin == "hashkit":
            expected = hashlib.sha256(b"SentinelV5").hexdigest()
            if output != "SHA256 " + expected:
                raise ValueError("hashkit produced an incorrect SHA-256 result")
        elif plugin == "jsonfix":
            if json.loads(output) != {"ready": True}:
                raise ValueError("jsonfix produced incorrect JSON")
        elif plugin == "hookbin":
            if json.loads(output) != {"hello": "world"}:
                raise ValueError("hookbin produced incorrect JSON")
        print(plugin, "JSON protocol smoke test OK")


if __name__ == "__main__":
    smoke()
