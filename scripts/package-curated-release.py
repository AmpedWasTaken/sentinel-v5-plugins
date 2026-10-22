#!/usr/bin/env python3
"""Build a minimal, approved signed-marketplace release from compiled Go binaries.

The manifest is a maintainer-reviewed release allowlist; this does not scan
source contributions or approve arbitrary plugin code.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

import yaml

SAFE = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
RELEASE = re.compile(r"^plugins-v[0-9]+\.[0-9]+\.[0-9]+$")
TARGETS = {("linux", "amd64"), ("linux", "arm64")}
PUBLIC_REPO = "https://github.com/AmpedWasTaken/sentinel-v5-plugins/releases/download"


def _manifest(path: Path) -> dict:
    config = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(config, dict) or not RELEASE.fullmatch(config.get("tag", "")):
        raise ValueError("invalid immutable release tag")
    if config.get("version") != config["tag"].removeprefix("plugins-v"):
        raise ValueError("tag/version mismatch")
    if config.get("publisher") != "sentinel-community-v2":
        raise ValueError("unexpected trusted publisher")
    names = config.get("plugins")
    if not isinstance(names, list) or not names or any(not isinstance(n, str) or not SAFE.fullmatch(n) for n in names):
        raise ValueError("invalid plugin release allowlist")
    if names != ["hashkit", "jsonfix", "hookbin"] or len(names) != len(set(names)):
        raise ValueError("curated release contains unreviewed plugin IDs")
    targets = config.get("targets")
    if not isinstance(targets, list) or len(targets) != len(TARGETS) or {tuple(t) for t in targets} != TARGETS:
        raise ValueError("unsupported platform targets")
    return config


def package(root: Path, manifest: Path, out: Path) -> None:
    config = _manifest(manifest)
    out.mkdir(parents=True, exist_ok=True)
    if any(out.iterdir()):
        raise ValueError("release directory must be empty; refusing stale or mixed artifacts")
    entries = []
    for name in config["plugins"]:
        source = root / "plugins" / name / "plugin.yaml"
        if not source.is_file() or source.is_symlink():
            raise ValueError(f"missing trusted manifest: {name}")
        raw = source.read_bytes()
        declaration = yaml.safe_load(raw)
        runtime = declaration.get("runtime", {}) if isinstance(declaration, dict) else {}
        commands = declaration.get("commands", []) if isinstance(declaration, dict) else []
        if (declaration.get("id") != name or declaration.get("version") != 1 or
                declaration.get("enabled") is not False or
                runtime.get("kind") != "exec" or runtime.get("binary") != name or
                declaration.get("dynamic_commands") or
                not commands or any(c.get("capability") != "code.invoke" for c in commands)):
            raise ValueError(f"manifest not compatible with two-file native installer: {name}")
        artifacts = []
        for os_name, arch in config["targets"]:
            # This lane is Linux-only, deliberately excluding Windows where
            # marketplace native execution is not yet sandboxed/supported.
            binary = root / "build-plugins" / f"{os_name}-{arch}" / name
            if not binary.is_file() or binary.is_symlink() or not 0 < binary.stat().st_size < 12 * 1024 * 1024:
                raise ValueError(f"missing, unsafe or oversized binary {binary}")
            filename = f"{name}-{os_name}-{arch}.zip"
            with zipfile.ZipFile(out / filename, "w", zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
                for path, content, mode in (
                    ("plugin.yaml", raw, 0o100644),
                    (f"bin/{name}", binary.read_bytes(), 0o100755),
                ):
                    info = zipfile.ZipInfo(path)
                    info.create_system = 3
                    info.external_attr = mode << 16
                    info.compress_type = zipfile.ZIP_DEFLATED
                    archive.writestr(info, content)
            digest = hashlib.sha256((out / filename).read_bytes()).hexdigest()
            artifacts.append({
                "os": os_name, "arch": arch,
                "url": f"{PUBLIC_REPO}/{config['tag']}/{filename}",
                "sha256": digest
            })
        entries.append({
            "id": name, "version": config["version"],
            "publisher": config["publisher"], "artifacts": artifacts
        })
    (out / "catalog.json").write_text(
        json.dumps({"version": 1, "plugins": entries}, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Packaged {len(entries)} vetted plugins for {len(TARGETS)} Linux platforms")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", type=Path, default=Path("release-manifests/plugins-v0.2.0.json"))
    parser.add_argument("--dist", type=Path, default=Path("release-plugins"))
    args = parser.parse_args()
    package(Path("."), args.manifest, args.dist)
