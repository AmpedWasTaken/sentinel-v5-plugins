#!/usr/bin/env python3
"""Package reviewed beta plugins for MANUAL installation, never marketplace install.

The current Sentinel marketplace installer accepts only plugin.yaml + one executable
and enforces signed Linux isolation. These richer packages are intentionally NOT
marketplace catalog entries and must never be presented as signed or sandboxed.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import stat
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "manual-release"
TAG = "plugins-manual-v0.1.0"
TARGETS = (("linux", "amd64"), ("linux", "arm64"), ("windows", "amd64"))
BINARIES = {
    "c2-relay": ("plugin.yml", "config.yml"),
    "webserver": ("plugin.yml", "config.yml", "public/index.html", "views/web-status.sml"),
    "hello-go": ("plugin.yaml", "views/greeting.sml"),
    "netwatch": ("plugin.yaml", "views/interfaces.sml", "views/traffic.sml"),
}
SCRIPTS = {"hello-python": ("plugin.yaml", "main.py", "views/greeting.sml")}
SDK = (
    "sdk/python/sentinel_sdk.py",
    "sdk/python/sentinel_native.py",
    "sdk/php/Sentinel.php",
)
SAFE_NAME = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
GUIDE = """# Sentinel V5 manual beta plugin

This package is for administrator-reviewed MANUAL installations only.
It is not a signed marketplace artifact and does not work with 'plugins install'.

Extract all files into assets/plugins/<plugin-id>/, preserving bin/, views/
and config.yml. Keep enabled: false until you inspect the files.

Locally installed native/Python plugins require explicit host trusted-code opt-in.
These run with the Sentinel OS account's privileges, WITHOUT the marketplace
isolation guarantees. Run under a low-privilege account and review endpoints,
config, code provenance and platform compatibility before enabling.

The Sentinel portable distribution already includes assets/sdk/python and
assets/sdk/php. The Python example needs a trusted Python 3.10+ interpreter.
This package does not copy or overwrite host SDK files.

C2 Relay in this release displays method/provider metadata and performs ONLY
opt-in read-only HTTPS health/status requests. It never dispatches attack API
requests. Webserver defaults to 127.0.0.1:8088.
"""

def read_regular(path: Path, max_bytes: int = 12 * 1024 * 1024) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing or unsafe release member: {path}")
    if not 0 < path.stat().st_size < max_bytes:
        raise ValueError(f"oversized or empty release member: {path}")
    return path.read_bytes()

def emit(name: str, files: list[tuple[str, bytes, bool]]) -> tuple[str, str]:
    if not re.fullmatch(r"[a-z0-9-]+(?:-linux-(?:amd64|arm64)|-windows-amd64|-any)\.zip", name):
        raise ValueError("invalid release artifact name")
    output = OUT / name
    seen = set()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for relative, contents, executable in files:
            path = Path(relative)
            if (path.is_absolute() or ".." in path.parts or relative in seen
                    or "\\" in relative or not contents):
                raise ValueError(f"unsafe duplicate or empty archive member: {relative}")
            seen.add(relative)
            info = zipfile.ZipInfo(relative)
            info.create_system = 3
            info.external_attr = (0o100755 if executable else 0o100644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, contents)
    if output.stat().st_size >= 16 * 1024 * 1024:
        raise ValueError(f"archive too large: {name}")
    return name, hashlib.sha256(output.read_bytes()).hexdigest()

def main() -> None:
    if OUT.exists() and any(OUT.iterdir()):
        raise ValueError("manual-release must be empty; refusing mixed artifacts")
    OUT.mkdir(exist_ok=True)
    artifacts = []
    for plugin, members in BINARIES.items():
        if not SAFE_NAME.fullmatch(plugin):
            raise ValueError("invalid plugin ID")
        base = ROOT / "plugins" / plugin
        data = [(part, read_regular(base / part), False) for part in members]
        manifest = data[0][1]
        if b"enabled: false" not in manifest or f"id: {plugin}\n".encode() not in manifest:
            raise ValueError(f"invalid disabled manifest for {plugin}")
        for operating_system, arch in TARGETS:
            if plugin == "netwatch" and operating_system != "linux":
                continue
            ext = ".exe" if operating_system == "windows" else ""
            binary = ROOT / "build-plugins" / f"{operating_system}-{arch}" / f"{plugin}{ext}"
            data_with_bin = data + [(f"bin/{plugin}{ext}", read_regular(binary), True),
                                   ("MANUAL-INSTALL.md", GUIDE.replace("<plugin-id>", plugin).encode(), False)]
            filename, digest = emit(f"{plugin}-{operating_system}-{arch}.zip", data_with_bin)
            artifacts.append({"file": filename, "sha256": digest, "plugin": plugin,
                              "os": operating_system, "arch": arch})
    for plugin, members in SCRIPTS.items():
        base = ROOT / "plugins" / plugin
        data = [(part, read_regular(base / part), False) for part in members]
        if b"enabled: false" not in data[0][1]:
            raise ValueError(f"invalid disabled manifest: {plugin}")
        data.append(("MANUAL-INSTALL.md", GUIDE.replace("<plugin-id>", plugin).encode(), False))
        filename, digest = emit(f"{plugin}-any.zip", data)
        artifacts.append({"file": filename, "sha256": digest, "plugin": plugin, "os": "any", "arch": "any"})
    sdk_members = [(p, read_regular(ROOT / p), False) for p in SDK]
    sdk_members.append(("README.txt", b"Developer examples only. Sentinel portable builds already include their own host SDK under assets/sdk/.\n", False))
    # This SDK ZIP is a separate development asset, not an installable plugin.
    with zipfile.ZipFile(OUT / "sdk-examples.zip", "w", zipfile.ZIP_DEFLATED) as archive:
        for relative, contents, _ in sdk_members:
            archive.writestr(relative, contents)
    artifacts.append({"file": "sdk-examples.zip",
                      "sha256": hashlib.sha256((OUT / "sdk-examples.zip").read_bytes()).hexdigest(),
                      "plugin": "developer-sdk", "os": "any", "arch": "any"})
    (OUT / "manifest.json").write_text(json.dumps({"version": 1, "tag": TAG,
        "marketplace_installable": False, "signed": False, "artifacts": artifacts}, indent=2) + "\n")
    sums = [(filename.name, hashlib.sha256(filename.read_bytes()).hexdigest())
            for filename in sorted(OUT.iterdir()) if filename.is_file()]
    (OUT / "SHA256SUMS").write_text("".join(f"{digest}  {name}\n" for name, digest in sums))
    print(f"Packaged {len(artifacts)} manual beta archives. Marketplace catalog unchanged.")

if __name__ == "__main__":
    main()
