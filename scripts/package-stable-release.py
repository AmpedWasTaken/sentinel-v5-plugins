#!/usr/bin/env python3
"""Package reviewed Sentinel V5 v1.0.0 manual-install distributions.

These are production-tagged distributions of the EXISTING host-trusted plugin
runtime. The current signed two-file SSH installer cannot install the richer
webserver/relay layouts. Do not misrepresent these as managed/sandboxed builds.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "stable-release"
TAG = "plugins-stable-v1.0.0"
BASE = f"https://github.com/AmpedWasTaken/sentinel-v5-plugins/releases/download/{TAG}/"

BINARIES = {
    "c2-relay": ("plugin.yml", "config.yml"),
    "webserver": ("plugin.yml", "config.yml", "public/index.html", "views/web-status.sml"),
    "netwatch": ("plugin.yaml", "views/interfaces.sml", "views/traffic.sml"),
    "hello-go": ("plugin.yaml", "views/greeting.sml"),
}
SCRIPTS = {"hello-python": ("plugin.yaml", "main.py", "views/greeting.sml")}
LINUX = (("linux", "amd64"), ("linux", "arm64"))
PLATFORMS = LINUX + (("windows", "amd64"),)
MANUAL_GUIDE = """# Sentinel V5 stable plugin v1.0.0

This is a full GitHub release for administrator-reviewed manual installation.
It is NOT a signed SSH marketplace artifact and does not work with
'plugins install'. Do not enable before reviewing its manifest and permissions.

Extract all files into assets/plugins/<id>/, preserving config.yml, bin/,
views/ and public/. Enable host trusted-code opt-in explicitly and run Sentinel
as a least-privileged service account. Do not assume host filesystem or
network access is sandboxed for manually provisioned plugins.

C2 Relay exposes provider/method metadata and read-only HTTPS health checks.
It does NOT issue attack or traffic-dispatch requests.
Webserver defaults to 127.0.0.1 and requires separate TLS/security review
before being configured for public interfaces.
NetWatch reads /proc/net/dev on Linux.
Python example requires Python 3.10+ and the installed Sentinel host SDK.
"""

def source_bytes(path: Path, cap: int = 12 * 1024 * 1024) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"missing or unsafe source: {path}")
    size = path.stat().st_size
    if not 0 < size < cap:
        raise ValueError(f"empty or oversized source: {path}")
    return path.read_bytes()

def package(filename: str, members: list[tuple[str, bytes, bool]]) -> dict:
    if not re.fullmatch(r"[a-z0-9-]+(?:-linux-(?:amd64|arm64)|-windows-amd64|-any)\.zip", filename):
        raise ValueError("unexpected archive name")
    names = [name for name, _, _ in members]
    if len(names) != len(set(names)) or not names:
        raise ValueError("duplicate or empty archive layout")
    target = OUTPUT / filename
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for name, payload, executable in members:
            path = Path(name)
            if path.is_absolute() or ".." in path.parts or "\\" in name or not payload:
                raise ValueError(f"unsafe release member {name}")
            info = zipfile.ZipInfo(name)
            info.create_system = 3
            info.external_attr = (0o100755 if executable else 0o100644) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, payload)
    raw = source_bytes(target, 16 * 1024 * 1024)
    return {"file": filename, "size": len(raw),
            "sha256": hashlib.sha256(raw).hexdigest(), "url": BASE + filename}

def main() -> None:
    OUTPUT.mkdir(exist_ok=True)
    if any(OUTPUT.iterdir()):
        raise ValueError("refusing to mix previous and current release artifacts")
    published = []
    for plugin, required in BINARIES.items():
        root = ROOT / "plugins" / plugin
        files = [(name, source_bytes(root / name), False) for name in required]
        manifest = files[0][1]
        if b"enabled: false" not in manifest or f"id: {plugin}\n".encode() not in manifest:
            raise ValueError(f"{plugin} must start disabled with its expected plugin ID")
        targets = LINUX if plugin == "netwatch" else PLATFORMS
        artifacts = []
        for os_name, arch in targets:
            executable = plugin + (".exe" if os_name == "windows" else "")
            binary = ROOT / "build-plugins" / f"{os_name}-{arch}" / executable
            extras = [
                (f"bin/{executable}", source_bytes(binary), True),
                ("MANUAL-INSTALL.md", MANUAL_GUIDE.replace("<id>", plugin).encode(), False),
            ]
            file = f"{plugin}-{os_name}-{arch}.zip"
            artifacts.append({"os": os_name, "arch": arch, **package(file, files + extras)})
        published.append({"id": plugin, "version": "1.0.0", "artifacts": artifacts})
    for plugin, required in SCRIPTS.items():
        root = ROOT / "plugins" / plugin
        files = [(name, source_bytes(root / name), False) for name in required]
        if b"enabled: false" not in files[0][1] or f"id: {plugin}\n".encode() not in files[0][1]:
            raise ValueError(f"invalid manifest: {plugin}")
        files.append(("MANUAL-INSTALL.md", MANUAL_GUIDE.replace("<id>", plugin).encode(), False))
        artifact = package(f"{plugin}-any.zip", files)
        published.append({"id": plugin, "version": "1.0.0",
                          "artifacts": [{"os": "any", "arch": "any", **artifact}]})
    if [p["id"] for p in published] != ["c2-relay", "webserver", "netwatch", "hello-go", "hello-python"]:
        raise ValueError("unexpected publisher allowlist")
    manifest = {
        "version": 1, "tag": TAG, "release_channel": "stable",
        "marketplace_installable": False, "signed": False,
        "requires_admin_review": True, "plugins": published,
    }
    (OUTPUT / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    files = sorted(p for p in OUTPUT.iterdir() if p.is_file())
    (OUTPUT / "SHA256SUMS").write_text(
        "".join(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}\n" for f in files),
        encoding="ascii",
    )
    print(f"Packaged {len(published)} stable manual-install plugins with 12 platform archives.")

if __name__ == "__main__":
    main()
