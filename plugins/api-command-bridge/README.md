# Simple C2 — API Bridge (Sentinel V5)

This is a **globally enabled, administrator-managed HTTPS diagnostics plugin** built on the existing Sentinel Go code-plugin SDK. It does not run attacks, dispatch bot agents, or start network floods. It intentionally keeps the API host fixed and verified, with read-only requests and scoped access.

## Install

Build from the repository root:

```sh
go build -o plugins/api-command-bridge/bin/api-command-bridge ./plugins/api-command-bridge
```

On Windows build to `plugins/api-command-bridge/bin/api-command-bridge.exe`. Set `SENTINEL_TRUSTED_CODE_PLUGINS=enabled` in the host environment or configure `plugins.trusted_code=true` and restart the Sentinel host. This opt-in is mandatory because separate executables are **not** OS-sandboxed.

Within Sentinel:

```text
plugins validate
plugins enable api-command-bridge
plugins run api-command-bridge lookup target=example.com category=inventory
plugins disable api-command-bridge
```

Global enablement makes the command available to all users with allowed roles (admin/operator) including active sessions. Sentinel's current SDK requires the `plugins run` prefix; a bare `lookup` alias is not supported.

## Template mapping

Edit `plugins/api-command-bridge/config.json` as administrator. Example:

```json
{
  "endpoint": "https://api.example.com/v1/reports",
  "allowed_host": "api.example.com",
  "timeout_ms": 2500,
  "query": {
    "target": "<<$target>>",
    "category": "<<$category>>"
  }
}
```

For `target=example.com category=inventory`, the request is an URL-encoded HTTPS GET with `?target=example.com&category=inventory`. Administrators may rename *query parameter keys*, but only the explicit `<<$target>>` and `<<$category>>` values are supported. The endpoint does not accept templated hosts or paths.

The upstream API must respond with JSON such as `{"success":true,"message":"Completed","data":{"service":"Inventory","records":24}}`. Sentinel renders it through `views/bridge-result.sml`.

## Security and limits

The endpoint must be an HTTPS URL on port 443 matching `allowed_host`. Outbound DNS is resolved on each request and all resolved addresses must be public IPv4, to prevent internal-network access. Proxies and redirects are disabled. Timeout is restricted to 500–3000 ms, max response is 16 KiB, and requests are GET only. No credentials are stored in this plugin.

`api.example.com` is illustrative and does not provide a functional service. Set a real approved diagnostics API before running a command.

## Attack-command dry-run simulator

This plugin also registers an `attack` command that mirrors a testing console's argument structure **without performing any attack**:

```text
plugins run api-command-bridge attack target=127.0.0.3 method=TCP port=8080 time=60
```

It performs real argument parsing, validation, request-ID generation and SML rendering in the compiled Go plugin. Accepted method labels are TCP, UDP and HTTP; the duration range is 1–3600 seconds. The `attack` handler deliberately performs **no network requests** and does not trigger the separate HTTPS lookup integration. Its returned status is always `SIMULATED`. The `time` argument is a declared scenario duration, not a sleep or running background task.

This intentionally does not emulate real bot agents, remote dispatch, traffic floods or attack-provider API triggers. The existing `lookup` handler remains a separate, administrator-approved HTTPS diagnostics integration.
