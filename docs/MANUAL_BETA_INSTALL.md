# Sentinel V5 manual-install plugin beta

This beta release provides **platform-specific plugin folders**, separate from
the strict signed two-file marketplace installer.

Release: https://github.com/AmpedWasTaken/sentinel-v5-plugins/releases/tag/plugins-manual-v0.1.0

## Included

| Plugin | Targets | Files/behavior |
| --- | --- | --- |
| c2-relay | Linux AMD64/ARM64, Windows AMD64 | Executable, plugin.yml, config.yml; read-only health requests and method/provider metadata, **no attack dispatch** |
| webserver | Linux AMD64/ARM64, Windows AMD64 | Persistent HTTP/HTTPS worker, plugin.yml, config.yml, web-status.sml, static public example; loopback by default |
| netwatch | Linux AMD64/ARM64 | Read-only host NIC statistics and SML views; Linux /proc required |
| hello-go | Linux AMD64/ARM64, Windows AMD64 | Minimal Go executable SDK example and greeting SML view |
| hello-python | Python 3.10+ on supported hosts | Minimal Python SDK script and greeting SML view |
| sdk-examples | Developer-only | Python/PHP SDK example files; the Sentinel portable build already ships its own runtime SDK |

These downloads are **NOT** Ed25519-signed marketplace packages. Their SHA-256
files detect accidental corruption against a trusted recorded digest, but do not
authenticate a publisher. They cannot be installed with `plugins install`.

## Manual install

1. Choose the ZIP matching the host platform from the GitHub Release and independently review its code/provenance and checksum.
2. Extract *the contents* of the chosen ZIP into `assets/plugins/<plugin-id>/` in the Sentinel installation; preserve `bin/`, `views/`, `config.yml` and the manifest. Never extract into `assets/marketplace/`.
3. Check `assets/sdk/python/sentinel_sdk.py`, `sentinel_native.py` and `assets/sdk/php/Sentinel.php` exist in the **Sentinel portable build** for interpreted plugin support. The included SDK archive is for development reference, not a blind replacement for a host SDK.
4. Configure the manifest and network access deliberately. Keep `enabled: false` until reviewed.
5. Run Sentinel as a dedicated unprivileged OS user. The administrator must opt into locally trusted code via `plugins.trusted_code=true` in the host's settings and restart Sentinel.
6. Connect as admin and use `plugins validate`, `plugins info <plugin-id>`, `plugins enable <plugin-id>`. For example:

   ```text
   plugins info webserver
   plugins enable webserver
   webserver status
   webserver routes
   ```

Only install one build per plugin ID, and do not overwrite an existing installed
plugin without first stopping it, backing up its configuration and reviewing
compatibility.

## Security and compatibility

- `c2-relay` has no implementation of provider attack dispatch. The
  `/testnetwork` and `/attack` URLs in its example YAML are nonexecuting
  method **metadata**. Only explicitly enabled fixed `GET /health` or
  `GET /status` probes can make real network calls.
- `webserver` binds to `127.0.0.1:8088` and does not listen publicly unless
  an administrator changes its config. Avoid exposing it directly before
  independently reviewing TLS, proxy trust and rate limits.
- `netwatch` needs Linux host network interface stats.
- On Windows, local trusted executable plugins are **not** the same as
  managed-marketplace plugins. Do not disable or bypass the managed sandbox to
  force one-click marketplace installation.
- The `plugins-manual-v0.1.0` release is immutable; subsequent changes require
  a new version and independent verification.

The separate **signed marketplace** release requires a persistent independently
trusted Ed25519 publisher key, reviewed compatible binaries, and Linux
bubblewrap isolation. The manual beta does not waive those requirements.
