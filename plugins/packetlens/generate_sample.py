"""Produce a deterministic synthetic Ethernet PCAP for PacketLens tests/demo.

This script opens no sockets and reads no network interfaces.
"""
from __future__ import annotations

import ipaddress
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent


def eth(ethertype: int) -> bytes:
    return b"\xaa\xbb\xcc\xdd\xee\xff" + b"\x00\x11\x22\x33\x44\x55" + struct.pack("!H", ethertype)


def tcp(source_port: int, dest_port: int, flags: int) -> bytes:
    return struct.pack("!HHIIHHHH", source_port, dest_port, 0, 0,
                       (5 << 12) | flags, 1024, 0, 0)


def udp(source_port: int, dest_port: int) -> bytes:
    return struct.pack("!HHHH", source_port, dest_port, 8, 0)


def ipv4(source: str, protocol: int, payload: bytes) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64,
        protocol, 0, ipaddress.IPv4Address(source).packed,
        ipaddress.IPv4Address("198.51.100.10").packed,
    )
    return header + payload


def ipv6(source: str, protocol: int, payload: bytes) -> bytes:
    header = struct.pack(
        "!IHBB16s16s", 0x60000000, len(payload), protocol, 64,
        ipaddress.IPv6Address(source).packed,
        ipaddress.IPv6Address("2001:db8::2").packed,
    )
    return header + payload


def packets() -> list[bytes]:
    frames = [eth(0x0800) + ipv4("192.0.2.5", 6, tcp(43000 + i, 443, 0x02))
              for i in range(3)]
    frames += [
        eth(0x0800) + ipv4("192.0.2.6", 6, tcp(44000, 80, 0x04)),
        eth(0x0800) + ipv4("192.0.2.7", 17, udp(50100, 53)),
        eth(0x0800) + ipv4("192.0.2.7", 17, udp(50101, 443)),
        eth(0x86DD) + ipv6("2001:db8::1", 6, tcp(55000, 8080, 0x10)),
        eth(0x0806) + b"\x00" * 28,
        eth(0x8100) + b"\x00\x01\x08\x00" + ipv4("192.0.2.8", 6, tcp(55001, 22, 0x10)),
        b"\x00" * 9,  # Deliberately truncated Ethernet frame.
    ]
    return frames


def build(*, big_endian: bool = False) -> bytes:
    endian = ">" if big_endian else "<"
    header = struct.pack(endian + "IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    records = [
        struct.pack(endian + "IIII", i, 0, len(frame), len(frame)) + frame
        for i, frame in enumerate(packets())
    ]
    return header + b"".join(records)


if __name__ == "__main__":
    directory = ROOT / "captures"
    directory.mkdir(exist_ok=True)
    result = directory / "sample.pcap"
    if result.is_symlink():
        raise RuntimeError("refusing to replace a symlinked capture")
    result.write_bytes(build())
    print("Generated synthetic PCAP:", result)
