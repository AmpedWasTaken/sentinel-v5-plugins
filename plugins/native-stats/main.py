"""Sentinel V5 one-shot Python plugin using a native C library."""
from __future__ import annotations

import ctypes
import sys
from pathlib import Path

# Sentinel invokes Python with -I: import its trusted SDK by absolute path.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))

from sentinel_native import load_c_library  # noqa: E402
from sentinel_sdk import Plugin, Request, Result  # noqa: E402


class NativeStats(ctypes.Structure):
    _fields_ = [
        ("bytes", ctypes.c_uint64),
        ("ascii_letters", ctypes.c_uint64),
        ("digits", ctypes.c_uint64),
        ("spaces", ctypes.c_uint64),
        ("fnv1a64", ctypes.c_uint64),
    ]


def open_stats_library():
    library = load_c_library(__file__, "sentinelstats")
    library.sentinel_stats_abi_version.argtypes = []
    library.sentinel_stats_abi_version.restype = ctypes.c_uint32
    if library.sentinel_stats_abi_version() != 1:
        raise RuntimeError("unsupported native C ABI version")
    library.sentinel_stats_analyze.argtypes = [
        ctypes.c_void_p,
        ctypes.c_size_t,
        ctypes.POINTER(NativeStats),
    ]
    library.sentinel_stats_analyze.restype = ctypes.c_int
    return library


app = Plugin()


@app.command("analyze")
def analyze(request: Request) -> Result:
    text = request.args.get("text")
    if not text:
        raise ValueError("usage: native-stats analyze text=SentinelV5")
    data = text.encode("utf-8")
    if len(data) > 1024:
        raise ValueError("input exceeds the native analysis limit")
    stats = NativeStats()
    buffer = ctypes.create_string_buffer(data)
    library = open_stats_library()
    code = library.sentinel_stats_analyze(
        ctypes.cast(buffer, ctypes.c_void_p),
        len(data),
        ctypes.byref(stats),
    )
    if code != 0:
        raise RuntimeError("native C analyzer rejected input")
    return Result(
        view="analysis",
        values={
            "bytes": str(stats.bytes),
            "letters": str(stats.ascii_letters),
            "digits": str(stats.digits),
            "spaces": str(stats.spaces),
            "fnv64": f"{stats.fnv1a64:016x}",
            "engine": "Python / ctypes / C ABI v1",
        },
    )


@app.command("info")
def info(request: Request) -> Result:
    if request.args:
        raise ValueError("info does not accept arguments")
    library = open_stats_library()
    return Result(
        view="info",
        values={
            "abi": str(library.sentinel_stats_abi_version()),
            "runtime": "Python + native C",
            "platform": sys.platform,
        },
    )


if __name__ == "__main__":
    app.serve()
