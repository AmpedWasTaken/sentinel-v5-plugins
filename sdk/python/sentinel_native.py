"""Native C ABI interoperability for administrator-trusted Python plugins.

This loader does not sandbox native code. Shared libraries execute with the
Sentinel process account's OS privileges, inside the trusted Python subprocess.
Only load locally reviewed binaries built for the active platform.
"""
from __future__ import annotations

import ctypes
import re
import sys
from pathlib import Path

_LIBRARY_NAME = re.compile(r"^[a-z][a-z0-9_]{0,31}$")


def library_filename(name: str) -> str:
    """Return the platform's conventional filename for a cdecl C ABI library."""
    if not isinstance(name, str) or not _LIBRARY_NAME.fullmatch(name):
        raise ValueError("invalid native library name")
    if sys.platform == "win32":
        return name + ".dll"
    if sys.platform == "darwin":
        return "lib" + name + ".dylib"
    if sys.platform.startswith("linux"):
        return "lib" + name + ".so"
    raise OSError("native library loading is unsupported on this platform")


def load_c_library(plugin_file: str, name: str) -> ctypes.CDLL:
    """Load a prebuilt C ABI library from <plugin>/native/ by absolute path.

    Python -I mode is fully supported. This function does not compile source,
    consult search paths, or accept caller-supplied arbitrary library paths.
    Configure ctypes argtypes/restype for *each* called function.
    """
    filename = library_filename(name)
    entry = Path(plugin_file)
    if entry.is_symlink() or not entry.is_file():
        raise ValueError("plugin entry point must be an ordinary file")
    plugin_dir = entry.resolve(strict=True).parent
    native_dir = plugin_dir / "native"
    candidate = native_dir / filename
    if native_dir.is_symlink() or not native_dir.is_dir():
        raise FileNotFoundError("plugin native directory is missing or symlinked")
    if candidate.is_symlink() or not candidate.is_file():
        raise FileNotFoundError(
            "compiled native library is missing; build the plugin for this host"
        )
    return ctypes.CDLL(str(candidate.resolve(strict=True)))
