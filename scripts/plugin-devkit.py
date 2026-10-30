#!/usr/bin/env python3
"""Sentinel community plugin starter and source packager.

This is developer convenience tooling, not a malware scanner, signature
issuer or substitute for Sentinel host-side approval.
"""
from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
import zipfile
from pathlib import Path

PLUGIN_ID = re.compile(r"^[a-z][a-z0-9-]{0,23}$")
SAFE_FILE = re.compile(
    r"^(plugin\.yaml|providers\.yaml|config\.json|config\.ya?ml|README\.md|"
    r"(?:views|components)/[a-z][a-z0-9_-]{0,47}\.sml|"
    r"art/[a-z][a-z0-9_-]{0,47}\.txt|"
    r"media/[A-Za-z0-9_-]{1,45}\.(?:png|jpe?g|gif)|"
    r"[a-z][a-z0-9_-]{0,47}\.php|"
    r"bin/[a-z][a-z0-9_-]{0,47}(?:\.exe)?|"
    r"src/[a-z][a-z0-9_-]{0,47}\.go)$"
)
MAX_FILES = 48
MAX_TOTAL = 2 * 1024 * 1024


def init_plugin(destination: Path, plugin_id: str) -> None:
    if not PLUGIN_ID.fullmatch(plugin_id):
        raise ValueError("Plugin ID must be a lowercase slug of at most 24 characters")
    if destination.exists():
        raise ValueError(f"Destination already exists: {destination}")
    (destination / "views").mkdir(parents=True)
    (destination / "plugin.yaml").write_text(
        "version: 1\n"
        f"id: {plugin_id}\n"
        f"name: {plugin_id.replace('-', ' ').title()}\n"
        "description: A community-made SML plugin\n"
        "enabled: false\n"
        "roles: [admin, operator, viewer]\n"
        "experience:\n"
        "  commands:\n"
        f"    - name: {plugin_id}\n"
        "      description: Show the starter plugin screen\n"
        "      type: screen\n"
        "      screen: starter\n",
        encoding="utf-8",
    )
    (destination / "views" / "starter.sml").write_text(
        '<screen name="starter"><column><panel title="Community starter">'
        '<text>Welcome to your Sentinel SML plugin.</text>'
        '</panel></column></screen>\n',
        encoding="utf-8",
    )
    (destination / "README.md").write_text(
        f"# {plugin_id}\n\nCommunity-made SML example. Review the source before running.\n"
        "\nThis source-only package is not approved or signed for SSH installation.\n",
        encoding="utf-8",
    )


def checked_files(root: Path) -> list[tuple[str, bytes]]:
    if not root.is_dir():
        raise ValueError("Plugin folder not found")
    entries: list[tuple[str, bytes]] = []
    total = 0
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise ValueError(f"Symlinks are not allowed: {path}")
        if not path.is_file():
            continue
        rel = path.relative_to(root).as_posix()
        if not SAFE_FILE.fullmatch(rel):
            raise ValueError(f"Unsupported plugin path: {rel}")
        size = path.stat().st_size
        total += size
        if total > MAX_TOTAL or size > MAX_TOTAL:
            raise ValueError("Package exceeds the 2 MiB source limit")
        data = path.read_bytes()
        if rel.endswith(".sml"):
            if len(data) > 65536 or b"<!DOCTYPE" in data.upper() or b"<!ENTITY" in data.upper():
                raise ValueError(f"Unsafe SML file: {rel}")
            tree = ET.fromstring(data)
            if tree.tag not in ("screen", "component") or tree.attrib.get("name") != path.stem:
                raise ValueError(f"SML root must match file name: {rel}")
        if rel.endswith((".yaml", ".json", ".php", ".go", ".md", ".txt", ".sml")):
            data.decode("utf-8")
        entries.append((rel, data))
    if not entries or len(entries) > MAX_FILES or not any(name == "plugin.yaml" for name, _ in entries):
        raise ValueError("Plugin needs plugin.yaml and at most 48 supported files")
    manifest = (root / "plugin.yaml").read_text(encoding="utf-8")
    if not re.search(r"(?m)^enabled:\s*false\s*$", manifest):
        raise ValueError("Community uploads must be disabled by default")
    if not re.search(r"(?m)^version:\s*1\s*$", manifest):
        raise ValueError("Expected manifest version 1")
    match = re.search(r"(?m)^id:\s*([a-z0-9-]+)\s*$", manifest)
    if not match or not PLUGIN_ID.fullmatch(match.group(1)):
        raise ValueError("Invalid manifest plugin ID")
    # Final canonical YAML, capability and runtime checks are enforced by
    # the Sentinel website and local host. Do not call this a security audit.
    return entries


def package(root: Path, output: Path) -> None:
    entries = checked_files(root)
    if output.resolve().is_relative_to(root.resolve()):
        raise ValueError("Output ZIP must be outside the plugin source directory")
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for name, data in entries:
            info = zipfile.ZipInfo(name, date_time=(2020, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            archive.writestr(info, data)
    if output.stat().st_size > MAX_TOTAL:
        output.unlink(missing_ok=True)
        raise ValueError("Compressed ZIP exceeds the 2 MiB upload limit")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    init = commands.add_parser("init", help="Generate a minimal SML starter plugin")
    init.add_argument("id")
    init.add_argument("directory", type=Path)
    check = commands.add_parser("check", help="Check folder layout and basic source safety")
    check.add_argument("directory", type=Path)
    pack = commands.add_parser("pack", help="Create a reproducible source ZIP")
    pack.add_argument("directory", type=Path)
    pack.add_argument("output", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "init":
            init_plugin(args.directory, args.id)
            print(f"Created {args.directory}")
        elif args.action == "check":
            entries = checked_files(args.directory)
            print(f"Basic checks passed for {len(entries)} files; not a security audit")
        else:
            package(args.directory, args.output)
            print(f"Created {args.output} — source-only, unsigned")
        return 0
    except (ValueError, OSError, ET.ParseError, UnicodeError) as error:
        print(f"Plugin devkit: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
