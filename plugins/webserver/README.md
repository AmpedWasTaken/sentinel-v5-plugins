# Sentinel V5 · Web Server

A real, managed HTTP/HTTPS server built as a Sentinel V5 persistent Go plugin. Inspired by [FileGoneIsBack/Golang-HTTPS-Handler](https://github.com/FileGoneIsBack/Golang-HTTPS-Handler), but with its own security-focused implementation using the Go standard library. No upstream code is vendored.

## Features

- Native Go `net/http` listener controlled by Sentinel's persistent `exec-rpc` worker lifecycle.
- Local HTTP default; opt-in TLS 1.2+ with a pre-existing certificate/key, including Cloudflare Origin certificates.
- Strict YAML validation, IP-only listeners, explicit public/TLS gate, up to 16 virtual hosts, no directory listings.
- Safe static file serving, optional per-site SPA fallback, up to 32 exact GET/HEAD routes returning JSON/text.
- Per-remote-IP bounded token-bucket rate limiting (does not trust spoofable proxy headers).
- HTTP timeouts and secure response headers.
- In-memory traffic summaries and the latest 128 requests; no query strings, request bodies or cookies collected.
- Live route/rate-limit hot reload; stop/start to change listener or TLS configuration.
- SML status dashboard and terminal tables.
- No new Sentinel core dependencies and no host RPC capabilities required.

## Build and install (locally trusted plugin ONLY)

From the `sentinel-v5-plugins` source root:

```sh
go build -trimpath -o plugins/webserver/bin/webserver ./plugins/webserver
```

Copy `plugins/webserver/` into your Sentinel installation's `assets/plugins/webserver/`. On Windows build `bin/webserver.exe`. Review the source and binary, then enable Sentinel's host-wide trusted-code opt-in and enable the plugin:

```text
plugins enable webserver
plugins run webserver status
plugins run webserver routes
plugins run webserver traffic limit=10
plugins run webserver reload
plugins run webserver stop
plugins run webserver start
```

Only the `admin` role can start/stop/reload. Both `admin` and `operator` can inspect status/routes/traffic. The server is started on worker initialization and stopped when the worker exits or is disabled (subject to ordinary OS process lifecycle). All web traffic stays separate from Sentinel SSH sessions.

**Important:** Current marketplace-managed executables are sandboxed without networking. This server requires a manually installed, administrator-reviewed binary with OS network permissions. It is not a claim of arbitrary marketplace plugin compatibility, and enabling trusted-code execution carries OS privilege risk. Run Sentinel under an unprivileged account.

## Configuration

`config.yml` starts with a safe local example:

```yaml
version: 1
listen: "127.0.0.1:8088"
allow_public: false
tls:
  enabled: false
  cert_file: ""
  key_file: ""
rate_limit:
  requests_per_minute: 120
  burst: 30
sites:
  - host: "*"
    root: "./public"
    spa_fallback: false
routes:
  - path: /api/version
    kind: json
    status: 200
    body: '{"service":"sentinel-webserver","healthy":true}'
```

The local example responds at `http://127.0.0.1:8088/`. For direct public binding, specify a **numeric non-loopback IP**, turn on `allow_public: true`, set `tls.enabled: true`, provide certificate and private-key file paths, and configure exact non-wildcard virtual hostnames. A public listener **cannot** use plain HTTP.

Do not commit certificate files, keys or credentials to this repository. Store them outside the plugin source directory under restrictive filesystem permissions. Cloudflare Origin certificates require traffic to pass through Cloudflare; use **Full (strict)** rather than insecure Full. Alternatively keep the plugin on loopback behind your own HTTPS reverse proxy.

### Reload behavior

`reload` validates the replacement YAML first and atomically swaps sites/routes/limits without closing the current listener. Listener IP/port, TLS mode/paths, and public exposure changes require `stop` followed by `start`. Certificate material changed at the same path also requires stop/start. A failed reload retains the old live config.

### Security limitations

- The public `/_sentinel/health` route returns only `{"status":"ok"}`. Operator metrics and logs are **not** HTTP endpoints.
- Requests are keyed by actual socket remote IP; forwarded client-IP headers are deliberately ignored. When used behind a reverse proxy, rate limits therefore apply to the proxy IP, not individual clients. Use proxy-side rate limiting for per-client enforcement.
- Static roots must be inside the plugin folder. Keep static content admin-owned and unmodifiable by untrusted processes, to avoid symlink races.
- This plugin is a basic web host, **not** a reverse proxy, WAF, or DDoS protection appliance. Its in-memory limiter is not a replacement for upstream protection.
- RPC worker shutdown can be abrupt; the OS will reclaim listening sockets even if Go's graceful shutdown cannot finish.
- Avoid placing private user data in served static files or exposing this service before configuring TLS and access controls.
