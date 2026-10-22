# Native Stats — Python plugin with a real C runtime

This source-only example demonstrates **Python + C in the same Sentinel V5 plugin**:

- Sentinel dispatches an authorized `runtime.kind: python` command.
- Python loads `assets/sdk/python/sentinel_sdk.py` and `sentinel_native.py` in `-I` isolated mode.
- The SDK's `load_c_library()` loads a prebuilt native C library from this plugin's `native/` directory using an absolute path.
- Python declares the exact `ctypes` C function signatures and structures, calls the C engine, and sends structured SML bindings back to Sentinel.

This is **not a separate `runtime.kind: c`**. Standalone compiled C/C++ executables can instead implement the existing `runtime.kind: exec` JSON protocol. `ctypes` calls C ABI functions; C++ requires an `extern "C"` wrapper.

## Source layout

```text
assets/
  sdk/python/
    sentinel_sdk.py
    sentinel_native.py
  plugins/native-stats/
    plugin.yaml
    main.py
    build_native.py
    native/
      stats.h
      stats.c
      libsentinelstats.so         # build locally on Linux, not committed
      libsentinelstats.dylib      # build locally on macOS, not committed
      sentinelstats.dll          # build locally on Windows, not committed
    views/
      analysis.sml
      info.sml
```

## Build and install

Requires a host with **Python 3.10+**, a C compiler, and the Sentinel V5 Python runtime/SDK PRs installed.

1. Copy `plugins/native-stats/` into your host's `assets/plugins/native-stats/`.
2. Ensure `assets/sdk/python/sentinel_sdk.py` and `sentinel_native.py` exist; updated core/portable builds provide both.
3. Build the native library in the **installed plugin directory**:

```powershell
# Windows PowerShell — requires MSVC Build Tools, MinGW GCC, or clang
python assets/plugins/native-stats/build_native.py
```

```sh
# Linux / macOS
python3 assets/plugins/native-stats/build_native.py
```

This generates exactly one platform-native library beside the C source. Do not commit it to the community source repo. It must match your Python process architecture.

4. Configure `plugins.trusted_code=true` (or `SENTINEL_TRUSTED_CODE_PLUGINS=enabled`) on your own host and restart Sentinel. As admin:

```text
plugins validate
plugins enable native-stats
native-stats info
native-stats analyze text=SentinelV5
plugins run native-stats analyze text=Hello123
plugins disable native-stats
```

Use `SENTINEL_PYTHON_BIN` on the host if your trusted Python interpreter is not found as `python3` / `python`.

## What the actual C code does

`sentinel_stats_analyze()` counts UTF-8 **bytes** and ASCII letters, digits, and whitespace, and computes a 64-bit FNV-1a checksum. It processes bounded input entirely in C with explicit `uint8_t*`, `size_t`, and a versioned `ctypes.Structure`. Its character classification is ASCII-only; it does not treat multi-byte Unicode code points as single characters.

Python uses `ctypes.c_void_p`, `ctypes.c_size_t`, explicit `argtypes` / `restype`, and a `ctypes.Structure` matching the C header. The C function never owns the Python memory buffer.

## Security and portability

**Native libraries are arbitrary executable code and run in the Python subprocess's OS security context.** Python `-I` does **not** sandbox C, isolate the filesystem/network or validate native code. This plugin is for manually reviewed, administrator-trusted source only, not automatic untrusted marketplace installation.

The C library is loaded only from a fixed `native/` directory and a safe library basename. The SDK rejects symlinked library files and unsafe names, but binary provenance, dependencies, memory safety, ABI compatibility, compiler trust and library authenticity still need developer review. Marketplace-managed native releases currently use a different signed installer and isolation policy; they do not automatically support Python+C source packages.

Tests compile this plugin into a temporary directory (not your real Sentinel installation):

```sh
python3 -m unittest discover -s tests -p 'test_native_stats.py' -v
```
