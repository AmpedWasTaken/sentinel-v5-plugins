#!/usr/bin/env python3
"""Package already-built plugin binaries and generate a checksum-pinned catalog.
Usage: python3 scripts/package-plugin-releases.py --tag plugins-v1.0.0 --dist release-plugins
Build step must have placed files at build-plugins/<os>-<arch>/<id>[.exe].
"""
import argparse, hashlib, json, pathlib, shutil, zipfile
from urllib.parse import quote

PLUGINS = """netcatty pktpeek portfox sysmon reqr dnsdig certcheck logtail latency socktop filewatch docktop sshwatch hookbin ioclookup httpxray whoiz jwtpeek gitty servectl termfiles authguard jsonfix hashkit uptimez""".split()
TARGETS = [("linux", "amd64"), ("linux", "arm64"), ("windows", "amd64")]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--tag", required=True)
    parser.add_argument("--dist", default="release-plugins")
    parser.add_argument("--base-url", required=True, help="Public HTTPS artifact directory ending at the release version")
    args = parser.parse_args()
    if not args.tag.startswith("plugins-v") or not all(c.isalnum() or c in ".-_" for c in args.tag):
        parser.error("tag must be a valid plugins-v* release tag")
    if not args.base_url.startswith("https://") or "github.com/AmpedWasTaken/Sentinel-V5/releases" in args.base_url:
        parser.error("a public HTTPS artifact host is required (not private repository release URLs)")
    base_url = args.base_url.rstrip("/")
    out = pathlib.Path(args.dist)
    out.mkdir(parents=True, exist_ok=True)
    entries = []
    for plugin in PLUGINS:
        manifest = pathlib.Path("plugins") / plugin / "plugin.yaml"
        if not manifest.is_file():
            raise SystemExit(f"Missing manifest: {manifest}")
        entry = {"id": plugin, "version": args.tag.removeprefix("plugins-v"), "artifacts": []}
        for os_name, arch in TARGETS:
            binary_name = plugin + (".exe" if os_name == "windows" else "")
            binary = pathlib.Path("build-plugins") / f"{os_name}-{arch}" / binary_name
            if not binary.is_file() or binary.stat().st_size == 0:
                raise SystemExit(f"Missing built plugin: {binary}")
            package_name = f"{plugin}-{os_name}-{arch}.zip"
            target = out / package_name
            with zipfile.ZipFile(target, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
                z.write(manifest, "plugin.yaml")
                data = binary.read_bytes()
                info = zipfile.ZipInfo("bin/" + binary_name)
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = ((0o100755 if os_name != "windows" else 0o100644) << 16)
                z.writestr(info, data)
            digest = hashlib.sha256(target.read_bytes()).hexdigest()
            entry["artifacts"].append({
                "os": os_name, "arch": arch,
                "url": f"{base_url}/{quote(package_name)}",
                "sha256": digest
            })
        entries.append(entry)
    (out / "catalog.json").write_text(json.dumps({"version": 1, "plugins": entries}, indent=2) + "\n")
    print(f"Packaged {len(entries)} plugins across {len(TARGETS)} targets: {len(entries)*len(TARGETS)} archives")

if __name__ == "__main__":
    main()
