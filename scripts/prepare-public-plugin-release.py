#!/usr/bin/env python3
"""Prepare an immutable static release directory for upload to a PUBLIC HTTPS host.
Run after package-plugin-releases.py and verify-plugin-releases.py.
Does not upload or imply the remote files exist.
"""
import argparse
import hashlib
import pathlib
import shutil
import tempfile
import subprocess
import sys

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument("--source",default="release-plugins")
    parser.add_argument("--destination",required=True)
    args=parser.parse_args()
    source=pathlib.Path(args.source).resolve()
    target=pathlib.Path(args.destination).resolve()
    if target.exists():raise SystemExit("Destination already exists; immutable releases cannot be overwritten")
    if not source.is_dir() or not (source/"catalog.json").is_file():raise SystemExit("Missing prepared release directory")
    subprocess.run([sys.executable, str(pathlib.Path(__file__).with_name('verify-plugin-releases.py')), str(source)], check=True)
    target.parent.mkdir(parents=True,exist_ok=True)
    staging=pathlib.Path(tempfile.mkdtemp(prefix=".plugin-release-",dir=target.parent))
    try:
        for f in source.iterdir():
            if f.name=="catalog.json" or f.suffix==".zip":
                shutil.copyfile(f,staging/f.name)
        checksums=sorted(f"{hashlib.sha256(f.read_bytes()).hexdigest()}  {f.name}" for f in staging.iterdir() if f.is_file())
        (staging/"SHA256SUMS").write_text("\n".join(checksums)+"\n")
        staging.rename(target)
    finally:
        if staging.exists():shutil.rmtree(staging)
    print(f"Prepared {target}. Upload files to the exact public HTTPS URL prefix in catalog.json and verify downloads before distributing catalog.json.")
if __name__=="__main__":main()
