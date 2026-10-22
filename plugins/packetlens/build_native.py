"""Compile PacketLens's locally reviewed C library for the current host."""
from __future__ import annotations
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NATIVE = ROOT / "native"
SOURCE = NATIVE / "packetlens.c"


def build() -> Path:
    if sys.platform == "win32":
        target = NATIVE / "packetlens.dll"
        if shutil.which("cl"):
            command = ["cl", "/nologo", "/W4", "/O2", "/LD",
                       str(SOURCE), "/Fe:" + str(target)]
        else:
            cc = shutil.which("gcc") or shutil.which("clang")
            if not cc:
                raise RuntimeError("install MSVC Build Tools or MinGW GCC / clang")
            command = [cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-shared",
                       "-o", str(target), str(SOURCE)]
    else:
        cc = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
        if not cc:
            raise RuntimeError("install a C compiler (cc / clang / gcc)")
        if sys.platform.startswith("linux"):
            target = NATIVE / "libpacketlens.so"
            extra = ["-fPIC", "-shared"]
        elif sys.platform == "darwin":
            target = NATIVE / "libpacketlens.dylib"
            extra = ["-dynamiclib"]
        else:
            raise RuntimeError("unsupported platform")
        command = [cc, "-std=c11", "-O2", "-Wall", "-Wextra", "-Werror",
                   *extra, "-o", str(target), str(SOURCE)]
    subprocess.run(command, check=True, cwd=NATIVE)
    if not target.is_file():
        raise RuntimeError("C compiler did not create a native library")
    return target


if __name__ == "__main__":
    try:
        print("Built:", build())
    except (OSError, RuntimeError, subprocess.CalledProcessError) as exc:
        print(f"PacketLens build failed: {exc}", file=sys.stderr)
        sys.exit(1)
