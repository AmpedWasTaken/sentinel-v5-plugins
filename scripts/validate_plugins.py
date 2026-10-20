#!/usr/bin/env python3
"""Static, no-execution checks for source submissions to the Sentinel community.

This validator is intentionally conservative and does not attest to security.
Requires PyYAML; it never imports or runs contributed plugin code.
"""
from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET

import yaml

ID = re.compile(r"^[a-z][a-z0-9-]{0,47}$")
COMMAND = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
SAFE_CAP = re.compile(r"^[a-z][a-z0-9_.-]{0,63}$")
ALLOWED_ROLES = {"admin", "operator", "viewer"}
ALLOWED_RUNTIME = {"php", "exec", "exec-rpc"}
BAD_SUFFIXES = {".exe", ".dll", ".so", ".dylib", ".zip", ".tar", ".gz",
                ".7z", ".rar", ".class", ".jar", ".pyc", ".wasm",
                ".pem", ".p12", ".pfx", ".key"}
MAX_FILE_BYTES = 128 * 1024
MAX_FILES = 256
MAX_TOTAL_BYTES = 2 * 1024 * 1024


class UniqueSafeLoader(yaml.SafeLoader):
    """Safe YAML loader that rejects silently overwritten keys."""


def unique_mapping(loader: UniqueSafeLoader, node: yaml.MappingNode) -> dict:
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=True)
        if not isinstance(key, (str, int, float, bool, tuple)) or key in mapping:
            raise yaml.constructor.ConstructorError(
                "while reading mapping", node.start_mark,
                "duplicate or invalid YAML key", key_node.start_mark
            )
        mapping[key] = loader.construct_object(value_node, deep=True)
    return mapping


UniqueSafeLoader.add_constructor(
    yaml.resolver.BaseResolver.DEFAULT_MAPPING_TAG, unique_mapping
)


def read_yaml(path: Path, errors: list[str]) -> dict | None:
    try:
        raw = path.read_bytes()
        if len(raw) > MAX_FILE_BYTES:
            errors.append(f"{path}: YAML exceeds the file size limit")
            return None
        parsed = yaml.load(raw, Loader=UniqueSafeLoader)
        if not isinstance(parsed, dict):
            errors.append(f"{path}: YAML must contain a mapping")
            return None
        return parsed
    except (OSError, ValueError, yaml.YAMLError) as exc:
        errors.append(f"{path}: cannot read safe YAML: {exc}")
        return None


def slug(value: object, pattern: re.Pattern[str] = ID) -> bool:
    return isinstance(value, str) and pattern.fullmatch(value) is not None


def validate_files(folder: Path, errors: list[str]) -> None:
    count = size = 0
    for path in folder.rglob("*"):
        if path.is_symlink():
            errors.append(f"{path}: symlinks are not allowed")
            continue
        if path.is_dir():
            continue
        if not path.is_file():
            errors.append(f"{path}: unexpected non-regular file")
            continue
        count += 1
        if path.suffix.lower() in BAD_SUFFIXES or path.name in {".env", ".env.local"}:
            errors.append(f"{path}: binary, archive or secret file is not allowed")
        if path.name.startswith(".") and path.name != ".gitkeep":
            errors.append(f"{path}: hidden files are not allowed in plugin source")
        file_bytes = path.stat().st_size
        size += file_bytes
        if file_bytes > MAX_FILE_BYTES:
            errors.append(f"{path}: individual file exceeds {MAX_FILE_BYTES} bytes")
    if count > MAX_FILES or size > MAX_TOTAL_BYTES:
        errors.append(f"{folder}: exceeds source file count or size limit")


def validate_views(folder: Path, errors: list[str]) -> None:
    views = folder / "views"
    if not views.exists():
        return
    if not views.is_dir() or views.is_symlink():
        errors.append(f"{views}: views must be a directory")
        return
    for path in views.rglob("*.sml"):
        if path.is_symlink():
            continue
        try:
            contents = path.read_bytes()
            if len(contents) > 64 * 1024:
                errors.append(f"{path}: exceeds Sentinel's 64 KiB SML file limit")
                continue
            if b"<!DOCTYPE" in contents.upper() or b"<!ENTITY" in contents.upper():
                errors.append(f"{path}: DTD/entity declarations are not permitted")
                continue
            root = ET.fromstring(contents)
            if root.tag != "screen" or root.get("name") != path.stem:
                errors.append(f"{path}: expected screen root with matching name")
            if root.get("version", "") not in {"", "1", "2", "3"}:
                errors.append(f"{path}: unsupported SML version")
            if sum(1 for _ in root.iter()) > 800:
                errors.append(f"{path}: too many SML nodes")
        except (OSError, ET.ParseError, UnicodeError) as exc:
            errors.append(f"{path}: invalid SML XML: {exc}")


def validate_plugin(folder: Path, errors: list[str]) -> None:
    if folder.is_symlink() or not folder.is_dir():
        errors.append(f"{folder}: plugin must be an ordinary directory")
        return
    if not slug(folder.name):
        errors.append(f"{folder}: plugin directory must be a lowercase slug")
    validate_files(folder, errors)
    if not (folder / "README.md").is_file():
        errors.append(f"{folder}: missing plugin README.md")
    manifest_path = folder / "plugin.yaml"
    if not manifest_path.is_file() or manifest_path.is_symlink():
        errors.append(f"{folder}: missing regular plugin.yaml")
        return
    manifest = read_yaml(manifest_path, errors)
    if manifest is None:
        return
    if type(manifest.get("version")) is not int or manifest["version"] != 1:
        errors.append(f"{manifest_path}: version must be integer 1")
    if manifest.get("id") != folder.name or not slug(manifest.get("id")):
        errors.append(f"{manifest_path}: id must match lowercase directory name")
    for key in ("name", "description"):
        val = manifest.get(key)
        if not isinstance(val, str) or not val.strip() or len(val) > 240:
            errors.append(f"{manifest_path}: {key} must be nonempty text (max 240 chars)")
    if manifest.get("enabled") is not False:
        errors.append(f"{manifest_path}: community plugins must have enabled: false")

    roles = manifest.get("roles")
    if (not isinstance(roles, list) or not roles
            or len(roles) != len(set(map(str, roles)))
            or any(not isinstance(x, str) or x not in ALLOWED_ROLES for x in roles)):
        errors.append(f"{manifest_path}: invalid roles (admin/operator/viewer)")

    runtime = manifest.get("runtime")
    if runtime is not None:
        if not isinstance(runtime, dict) or runtime.get("kind") not in ALLOWED_RUNTIME:
            errors.append(f"{manifest_path}: runtime.kind must be php, exec or exec-rpc")
        else:
            kind = runtime["kind"]
            entry = runtime.get("entry") if kind == "php" else runtime.get("binary")
            if not slug(entry) and not (kind == "php" and entry == "main.php"):
                errors.append(f"{manifest_path}: invalid runtime entry/binary name")
            if kind == "php" and (not isinstance(entry, str) or not (folder / entry).is_file()):
                errors.append(f"{manifest_path}: PHP source entry is missing")
            timeout = runtime.get("timeout_ms")
            if timeout is not None and (type(timeout) is not int or not 100 <= timeout <= 8000):
                errors.append(f"{manifest_path}: timeout_ms must be between 100 and 8000")
            caps = runtime.get("capabilities", [])
            if not isinstance(caps, list) or any(not slug(c, SAFE_CAP) for c in caps):
                errors.append(f"{manifest_path}: invalid runtime capabilities")

    commands = manifest.get("commands")
    if not isinstance(commands, list) or not 1 <= len(commands) <= 32:
        errors.append(f"{manifest_path}: provide 1..32 commands")
        commands = []
    seen = set()
    provider_names = set()
    for cmd in commands:
        if not isinstance(cmd, dict):
            errors.append(f"{manifest_path}: command must be a mapping")
            continue
        name = cmd.get("name")
        if not slug(name, COMMAND) or name in seen:
            errors.append(f"{manifest_path}: command names must be unique safe slugs")
        seen.add(name)
        if not isinstance(cmd.get("description"), str) or not cmd["description"].strip():
            errors.append(f"{manifest_path}: each command needs a description")
        provider, capability = cmd.get("provider"), cmd.get("capability")
        if bool(provider) == bool(capability):
            errors.append(f"{manifest_path}: command {name!r} needs one provider or capability")
        if provider:
            if runtime is not None or not slug(provider):
                errors.append(f"{manifest_path}: provider command {name!r} is malformed")
            provider_names.add(provider)
        if capability:
            if runtime is None or capability != "code.invoke":
                errors.append(f"{manifest_path}: executable command {name!r} needs code.invoke and runtime")

    provider_path = folder / "providers.yaml"
    if provider_names or provider_path.exists():
        if not provider_path.is_file():
            errors.append(f"{folder}: provider commands require providers.yaml")
        else:
            data = read_yaml(provider_path, errors)
            if data is not None:
                providers = data.get("providers")
                if data.get("version") != 1 or not isinstance(providers, dict):
                    errors.append(f"{provider_path}: needs version: 1 and providers mapping")
                else:
                    for name in provider_names:
                        if name not in providers:
                            errors.append(f"{provider_path}: missing provider {name!r}")
                    for name, provider in providers.items():
                        if not slug(name) or not isinstance(provider, dict):
                            errors.append(f"{provider_path}: invalid provider entry {name!r}")
                            continue
                        request = provider.get("request", {})
                        if not isinstance(request, dict) or request.get("method") != "GET":
                            errors.append(f"{provider_path}: provider {name} needs read-only GET")
                            continue
                        url = request.get("url")
                        if not isinstance(url, str):
                            errors.append(f"{provider_path}: provider {name} needs HTTPS URL")
                        else:
                            split = urlsplit(url)
                            if split.scheme != "https" or not split.hostname or split.username:
                                errors.append(f"{provider_path}: provider {name} needs HTTPS without embedded credentials")

    validate_views(folder, errors)


def validate_repo(root: Path) -> list[str]:
    errors: list[str] = []
    seen = set()
    for dirname in ("plugins", "examples"):
        base = root / dirname
        if not base.exists():
            if dirname == "plugins":
                errors.append(f"{base}: missing plugins directory")
            continue
        if base.is_symlink() or not base.is_dir():
            errors.append(f"{base}: must be an ordinary directory")
            continue
        for entry in sorted(base.iterdir()):
            if entry.name == ".gitkeep":
                continue
            if entry.is_dir():
                if entry.name in seen:
                    errors.append(f"{entry}: plugin id already exists in the other source directory")
                seen.add(entry.name)
                validate_plugin(entry, errors)
            else:
                errors.append(f"{entry}: unexpected file in plugin collection root")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parents[1])
    args = parser.parse_args()
    errors = validate_repo(args.root)
    if errors:
        for error in errors:
            print(f"ERROR: {error}", file=sys.stderr)
        print(f"Validation failed: {len(errors)} issue(s).", file=sys.stderr)
        return 1
    print("Static plugin manifest, layout and SML XML checks passed.")
    print("No submitted code was executed; human security review remains required.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
