# PacketLens — native C offline PCAP analyzer for Sentinel V5

**An advanced real-world Python + C plugin.** Instead of a hello-world or checksum demo, PacketLens uses a compiled native C parser to inspect *existing local* network capture files and renders a multi-panel SML dashboard in Sentinel's SSH terminal.

## Architecture

```text
Authenticated Sentinel SSH command
      |
Sentinel role and code.invoke checks
      |
Python 3.10+ runtime -I (one-shot, up to 4.5 seconds)
      |
Python SDK: sentinel_sdk.Plugin + sentinel_native.load_c_library()
      |
Native C ABI: packetlens_analyze(bytes, length, *report)
      |
Bounded protocol counters + top source addresses + destination ports
      |
SML metrics + 2 tables + diagnostic observations
```

## Capabilities

- Parses **classic PCAP v2.4** with Ethernet link type 1, both endian formats and micro/nanosecond magic variants.
- Decodes Ethernet, up to two VLAN tags, IPv4, IPv6, ARP, TCP, UDP, ICMP and other protocols.
- Tallies captured frames, declared wire size, captured bytes, TCP SYN-only and RST flags.
- Reports top IPv4/IPv6 source addresses and TCP/UDP destination ports.
- Port-based indicators for DNS (53), HTTP (80) and TLS/QUIC (443) — **not deep payload identification**.
- Emits simple heuristic observations, clearly **not** a proof of attack or attribution.
- Requires a **named local capture**, never accepts an arbitrary filesystem path or network target.
- Reads a maximum of **8 MiB**; only aggregates counts and addresses, never exposes packet payloads in SML.
- Creates a **deterministic synthetic capture** for demonstration with no live network access.

**Not included:** PCAPNG, radiotap/Wi-Fi captures, IPv6 extension-header decoding, IP reassembly, TCP stream assembly, application payload dissection, full traffic forensics, continuous packet capture, or live interface monitoring. Source and port rankings are bounded to the first 256 distinct entries; if over capacity, the dashboard reports untracked packet counts.

## Installing on your Sentinel host

Requirements: Sentinel V5 with merged Python runtime (core PR #179), reviewed one-shot Python SDK from the [community Python PR #8](https://github.com/AmpedWasTaken/sentinel-v5-plugins/pull/8), Python 3.10+, and a local compiler (MSVC/GCC/Clang).

1. Copy `plugins/packetlens/` to `assets/plugins/packetlens/`; ensure the Python SDK files `assets/sdk/python/sentinel_sdk.py` and `assets/sdk/python/sentinel_native.py` exist.
2. Generate a harmless synthetic sample in the installed plugin directory:

   ```powershell
   python assets/plugins/packetlens/generate_sample.py
   ```

3. Build the platform-specific native C library:

   ```powershell
   python assets/plugins/packetlens/build_native.py
   ```

   Linux/macOS: replace `python` with `python3`. No third-party Python packages required.

4. Enable the host-level `plugins.trusted_code=true` setting (or `SENTINEL_TRUSTED_CODE_PLUGINS=enabled`), restart Sentinel and use an administrator SSH session:

   ```text
   plugins validate
   plugins enable packetlens
   packetlens info
   packetlens list
   packetlens analyze capture=sample
   plugins disable packetlens
   ```

5. To analyze an existing authorized capture, place a regular **Ethernet classic-PCAP** file named `office.pcap` under the plugin's `captures/` directory and run `packetlens analyze capture=office`. The user argument is a simple slug, not a path; files and the directory must not be symlinks.

## Layout

```text
packetlens/
  plugin.yaml
  main.py
  build_native.py
  generate_sample.py
  native/
    packetlens.h
    packetlens.c
    libpacketlens.so    # built on Linux, ignored by git
    packetlens.dll      # built on Windows, ignored by git
  captures/
    .gitkeep
    sample.pcap         # generated locally; do not commit actual captures
  views/
    analysis.sml
    captures.sml
    info.sml
```

## Security boundaries

- The executable is manually installed, administrator-trusted code. Python isolated mode `-I` **is not an OS sandbox**, and the C library runs with the host account's privileges.
- Untrusted capture files still pass through native parsing code, so parser correctness must be reviewed and fuzz-tested before sensitive deployment. The parser rejects inconsistent PCAP headers/record sizes and bounds all reads, but it is **not security-certified**.
- The C plugin does not open network sockets, capture interfaces or launch other programs.
- Keep real PCAP files private: even source IP metadata can be sensitive. Never store sensitive captures in a public web/static assets location; the example capture directory is intended for locally controlled development installations.
- The current signed marketplace installer packages platform-native executables, not Python+C source libraries.

## Tests

```sh
python3 -m unittest discover -s tests -p test_packetlens.py -v
python3 scripts/validate_plugins.py
```

The integration tests compile the native library inside a temporary installation tree, create synthetic PCAP samples, run the plugin under `python -I`, check exact C counters, and reject malformed/symlinked captures. No live network is involved.
