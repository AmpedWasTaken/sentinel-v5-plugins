#!/usr/bin/env python3
"""Offline validation for the generated marketplace release (no GitHub API calls)."""
import argparse
import hashlib
import json
import pathlib
import re
import sys
import zipfile

IDENT = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
HASH = re.compile(r"^[0-9a-f]{64}$")
TARGETS = {("linux", "amd64"), ("linux", "arm64"), ("windows", "amd64")}


def verify(directory: pathlib.Path) -> int:
    catalog_path = directory / "catalog.json"
    index = json.loads(catalog_path.read_text())
    if index.get("version") != 1 or not isinstance(index.get("plugins"), list) or not index["plugins"]:
        raise ValueError("Missing release plugins")
    ids = set()
    count = 0
    for plugin in index["plugins"]:
        identifier = plugin["id"]
        if not IDENT.fullmatch(identifier) or identifier in ids:
            raise ValueError("Invalid or duplicate plugin ID")
        ids.add(identifier)
        platforms = set()
        for entry in plugin["artifacts"]:
            target = (entry["os"], entry["arch"])
            if target not in TARGETS or target in platforms:
                raise ValueError("Invalid or duplicate OS/architecture target")
            platforms.add(target)
            name = f"{identifier}-{entry['os']}-{entry['arch']}.zip"
            archive = directory / name
            if not HASH.fullmatch(entry["sha256"]):
                raise ValueError(f"Missing checksum: {name}")
            digest = hashlib.sha256(archive.read_bytes()).hexdigest()
            if digest != entry["sha256"]:
                raise ValueError(f"Checksum mismatch: {name}")
            if not entry["url"].endswith("/" + name):
                raise ValueError(f"Unexpected download URL for {name}")
            with zipfile.ZipFile(archive) as z:
                members = z.namelist()
                binary = "bin/" + identifier + (".exe" if entry["os"] == "windows" else "")
                if set(members) != {"plugin.yaml", binary}:
                    raise ValueError(f"Unexpected files in {name}: {members}")
                manifest = z.read("plugin.yaml").decode("utf-8")
                if not re.search(r"(?m)^enabled:\s*false\s*$", manifest):
                    raise ValueError(f"Plugin not disabled by default: {name}")
                if not re.search(r"(?m)^id:\s*" + re.escape(identifier) + r"\s*$", manifest):
                    raise ValueError(f"Manifest mismatch: {name}")
                if len(z.read(binary)) == 0:
                    raise ValueError(f"Empty executable: {name}")
            count += 1
        if platforms != TARGETS:
            raise ValueError(f"Missing platforms for {identifier}: {TARGETS - platforms}")
    print(f"Verified {count} release archives for {len(ids)} plugins.")
    return count


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("directory", type=pathlib.Path, nargs="?", default=pathlib.Path("release-plugins"))
    args = parser.parse_args()
    try:
        verify(args.directory)
    except (ValueError, OSError, KeyError, zipfile.BadZipFile) as exc:
        print(f"Release validation failed: {exc}", file=sys.stderr)
        sys.exit(1)
