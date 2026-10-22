"""Build the local platform C ABI library; no binary is checked into Git."""
from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
NATIVE = ROOT / "native"
SOURCE = NATIVE / "stats.c"


def build() -> Path:
    if sys.platform == "win32":
        output = NATIVE / "sentinelstats.dll"
        if shutil.which("cl"):
            command = ["cl", "/nologo", "/W4", "/O2", "/LD",
                       str(SOURCE), "/Fe:" + str(output)]
        else:
            compiler = shutil.which("gcc") or shutil.which("clang")
            if not compiler:
                raise RuntimeError("install MSVC Build Tools or MinGW/clang")
            command = [compiler, "-std=c11", "-O2", "-Wall", "-Wextra",
                       "-shared", "-o", str(output), str(SOURCE)]
    else:
        compiler = shutil.which("cc") or shutil.which("clang") or shutil.which("gcc")
        if not compiler:
            raise RuntimeError("install a C compiler (cc, clang or gcc)")
        if sys.platform == "darwin":
            output = NATIVE / "libsentinelstats.dylib"
            options = ["-dynamiclib"]
        elif sys.platform.startswith("linux"):
            output = NATIVE / "libsentinelstats.so"
            options = ["-fPIC", "-shared"]
        else:
            raise RuntimeError("unsupported platform")
        command = [compiler, "-std=c11", "-O2", "-Wall", "-Wextra",
                   "-Werror", *options, "-o", str(output), str(SOURCE)]
    subprocess.run(command, cwd=NATIVE, check=True)
    if not output.is_file():
        raise RuntimeError("compiler produced no native library")
    return output


if __name__ == "__main__":
    try:
        print("Built:", build())
    except (OSError, subprocess.CalledProcessError, RuntimeError) as exc:
        print(f"Native build failed: {exc}", file=sys.stderr)
        sys.exit(1)
