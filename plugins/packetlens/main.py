"""PacketLens: offline, bounded native-C PCAP inspection in Sentinel's Python runtime."""
from __future__ import annotations

import ctypes
import json
import os
import re
import stat
import sys
from pathlib import Path

# -I mode disables path and PYTHONPATH imports; load Sentinel's reviewed SDK explicitly.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))
from sentinel_sdk import Plugin, Request, Result  # noqa: E402
from sentinel_native import load_c_library  # noqa: E402

MAX_PCAP = 8 * 1024 * 1024
MAX_TOP = 6
CAPTURE_NAME = re.compile(r"^[a-z][a-z0-9_-]{0,31}$")
ROOT = Path(__file__).resolve().parent


class TopSource(ctypes.Structure):
    _fields_ = [
        ("address", ctypes.c_char * 48),
        ("packets", ctypes.c_uint64),
        ("bytes", ctypes.c_uint64),
    ]


class TopPort(ctypes.Structure):
    _fields_ = [
        ("port", ctypes.c_uint16),
        ("protocol", ctypes.c_uint16),
        ("packets", ctypes.c_uint64),
    ]


class CaptureReport(ctypes.Structure):
    _fields_ = [
        (name, ctypes.c_uint64) for name in (
            "frames", "wire_bytes", "captured_bytes", "ipv4", "ipv6", "arp",
            "tcp", "udp", "icmp", "other", "malformed", "tcp_syn", "tcp_rst",
            "dns", "http", "tls", "untracked_source_packets",
            "untracked_port_packets",
        )
    ] + [
        ("source_count", ctypes.c_uint32),
        ("port_count", ctypes.c_uint32),
        ("sources", TopSource * MAX_TOP),
        ("ports", TopPort * MAX_TOP),
    ]


def engine():
    lib = load_c_library(__file__, "packetlens")
    lib.packetlens_abi_version.argtypes = []
    lib.packetlens_abi_version.restype = ctypes.c_uint32
    if lib.packetlens_abi_version() != 1:
        raise RuntimeError("PacketLens native ABI mismatch")
    lib.packetlens_analyze.argtypes = [
        ctypes.c_void_p, ctypes.c_size_t, ctypes.POINTER(CaptureReport),
    ]
    lib.packetlens_analyze.restype = ctypes.c_int
    return lib


def capture_folder() -> Path:
    folder = ROOT / "captures"
    if folder.is_symlink() or not folder.is_dir():
        raise ValueError("captures directory is missing or symlinked")
    return folder


def capture_path(name: str) -> Path:
    if not CAPTURE_NAME.fullmatch(name):
        raise ValueError("capture must be a simple local name such as sample")
    return capture_folder() / (name + ".pcap")


def read_capture(name: str) -> bytes:
    path = capture_path(name)
    if path.is_symlink():
        raise ValueError("symlinked PCAP files are forbidden")
    # O_NOFOLLOW prevents a symlink swap at open on supporting platforms.
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        metadata = os.fstat(fd)
        if not stat.S_ISREG(metadata.st_mode) or not 24 <= metadata.st_size <= MAX_PCAP:
            raise ValueError("PCAP must be a regular file between 24 bytes and 8 MiB")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_PCAP + 1)
        if len(data) != metadata.st_size:
            raise ValueError("PCAP changed during reading")
        return data
    finally:
        os.close(fd)


def analyze_capture(name: str) -> CaptureReport:
    data = read_capture(name)
    buffer = ctypes.create_string_buffer(data)
    report = CaptureReport()
    result = engine().packetlens_analyze(
        ctypes.cast(buffer, ctypes.c_void_p),
        len(data),
        ctypes.byref(report),
    )
    if result == -2:
        raise ValueError("malformed or unsupported classic PCAP structure")
    if result == -3:
        raise ValueError("only classic Ethernet PCAP is supported (not PCAPNG)")
    if result != 0:
        raise ValueError("native packet parser rejected the capture")
    return report


def signal(report: CaptureReport) -> str:
    if report.malformed:
        return "Malformed or truncated packets observed"
    if report.tcp >= 10 and report.tcp_syn >= 10 and report.tcp_syn * 100 >= 60 * report.tcp:
        return "SYN-heavy traffic sample (not an attack verdict)"
    if report.tcp >= 10 and report.tcp_rst * 100 >= 50 * report.tcp:
        return "High TCP reset ratio (investigate context)"
    return "No simple heuristic triggered; not a security verdict"


app = Plugin()


@app.command("analyze")
def analyze(request: Request) -> Result:
    if set(request.args) - {"capture"}:
        raise ValueError("only capture=name is supported")
    name = request.args.get("capture", "sample")
    report = analyze_capture(name)
    sources = [
        {"ip": report.sources[i].address.decode("ascii"), 
         "packets": str(report.sources[i].packets), 
         "bytes": str(report.sources[i].bytes)}
        for i in range(report.source_count)
    ]
    ports = [
        {"proto": "TCP" if report.ports[i].protocol == 6 else "UDP",
         "port": str(report.ports[i].port),
         "packets": str(report.ports[i].packets)}
        for i in range(report.port_count)
    ]
    return Result(view="analysis", values={
        "capture": name,
        "frames": str(report.frames),
        "wire_bytes": str(report.wire_bytes),
        "captured_bytes": str(report.captured_bytes),
        "ipv4": str(report.ipv4),
        "ipv6": str(report.ipv6),
        "arp": str(report.arp),
        "tcp": str(report.tcp),
        "udp": str(report.udp),
        "icmp": str(report.icmp),
        "other": str(report.other),
        "malformed": str(report.malformed),
        "syn": str(report.tcp_syn),
        "rst": str(report.tcp_rst),
        "dns": str(report.dns),
        "http": str(report.http),
        "tls": str(report.tls),
        "untracked_sources": str(report.untracked_source_packets),
        "untracked_ports": str(report.untracked_port_packets),
        "sources": json.dumps(sources, separators=(",", ":")),
        "ports": json.dumps(ports, separators=(",", ":")),
        "signal": signal(report),
        "note": "Port counters are heuristics; payloads are not inspected.",
    })


@app.command("list")
def list_captures(request: Request) -> Result:
    if request.args:
        raise ValueError("list does not accept arguments")
    files = []
    for item in sorted(capture_folder().iterdir(), key=lambda p: p.name):
        if len(files) >= 20:
            break
        if not item.name.endswith(".pcap") or not CAPTURE_NAME.fullmatch(item.stem):
            continue
        if item.is_symlink() or not item.is_file():
            continue
        size = item.stat().st_size
        if 24 <= size <= MAX_PCAP:
            files.append({"name": item.stem, "bytes": str(size)})
    return Result(view="captures", values={
        "count": str(len(files)),
        "files": json.dumps(files, separators=(",", ":")),
    })


@app.command("info")
def info(request: Request) -> Result:
    if request.args:
        raise ValueError("info does not accept arguments")
    library = engine()
    return Result(view="info", values={
        "abi": str(library.packetlens_abi_version()),
        "max_size": "8 MiB",
        "runtime": "Python / ctypes / native C",
        "format": "Classic Ethernet PCAP",
    })


if __name__ == "__main__":
    app.serve()
