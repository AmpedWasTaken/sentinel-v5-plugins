#!/usr/bin/env python3
"""Fail closed on mismatched or incomplete curated v0.2 signed artifacts."""
from __future__ import annotations

import base64
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT = Path("release-plugins")
TAG = "plugins-v0.2.0"
IDS = ("hashkit", "jsonfix", "hookbin")
TARGETS = (("linux","amd64"),("linux","arm64"))
PREFIX = f"https://github.com/AmpedWasTaken/sentinel-v5-plugins/releases/download/{TAG}/"


def verify() -> None:
    catalog = json.loads((ROOT / "catalog.json").read_text(encoding="utf-8"))
    trust = json.loads((ROOT / "trusted-publishers.json").read_text(encoding="utf-8"))
    if trust.get("version") != catalog.get("version") or trust["version"] != 1:
        raise ValueError("catalog/trust protocol mismatch")
    publishers = trust.get("publishers")
    if len(publishers) != 1 or publishers[0]["id"] != "sentinel-community-v2":
        raise ValueError("unexpected publisher")
    if len(base64.b64decode(publishers[0]["public_key"],validate=True)) != 32:
        raise ValueError("invalid public key")
    plugins = catalog.get("plugins")
    if [p["id"] for p in plugins] != list(IDS):
        raise ValueError("curated plugin set mismatch")
    expected_files = {"catalog.json", "trusted-publishers.json"}
    for plugin in plugins:
        if plugin["version"] != "0.2.0" or plugin["publisher"] != publishers[0]["id"]:
            raise ValueError("plugin signing identity mismatch")
        if [(a["os"],a["arch"]) for a in plugin["artifacts"]] != list(TARGETS):
            raise ValueError("unexpected platform selection")
        for artifact in plugin["artifacts"]:
            name = f"{plugin['id']}-{artifact['os']}-{artifact['arch']}.zip"
            expected_files.add(name)
            if artifact["url"] != PREFIX + name or not re.fullmatch(r"[a-f0-9]{64}",artifact["sha256"]):
                raise ValueError("unexpected artifact URL or digest")
            if len(base64.b64decode(artifact["signature"],validate=True)) != 64:
                raise ValueError("missing Ed25519 signature")
            path = ROOT / name
            raw = path.read_bytes()
            if not 0 < len(raw) < 16 * 1024 * 1024:
                raise ValueError("oversized release ZIP")
            if hashlib.sha256(raw).hexdigest() != artifact["sha256"]:
                raise ValueError("SHA-256 mismatch")
            with zipfile.ZipFile(path) as archive:
                if archive.namelist() != ["plugin.yaml",f"bin/{plugin['id']}"]:
                    raise ValueError("installer-incompatible ZIP member list")
                if not 0 < archive.getinfo(f"bin/{plugin['id']}").file_size < 12 * 1024 * 1024:
                    raise ValueError("invalid executable size")
                if archive.getinfo(f"bin/{plugin['id']}").external_attr >> 16 & 0o111 == 0:
                    raise ValueError("Linux binary lacks executable mode")
                content = archive.read("plugin.yaml").decode("utf-8")
                if f"id: {plugin['id']}\n" not in content or "enabled: false\n" not in content:
                    raise ValueError("plugin manifest mismatch")
    if set(p.name for p in ROOT.iterdir()) != expected_files:
        raise ValueError("unexpected/stale release files present")
    # The Go signer cryptographically verifies every signature immediately
    # after signing; this script verifies metadata and archive integrity.
    checksum_lines = [
        f"{hashlib.sha256((ROOT / name).read_bytes()).hexdigest()}  {name}"
        for name in sorted(expected_files)
    ]
    (ROOT / "SHA256SUMS").write_text("\n".join(checksum_lines) + "\n",encoding="utf-8")
    print("Verified 6 signed-metadata, checksum-pinned ZIPs and immutable catalog.")


if __name__ == "__main__":
    verify()
