# Local Load Test plugin

This is an **authorized, loopback-only** diagnostics example built for the V5 PHP plugin SDK. It does **not** connect to external DDoS APIs and cannot dispatch attacks to arbitrary hosts.

The host must independently enable trusted code plugins with `SENTINEL_TRUSTED_CODE_PLUGINS=enabled` and have PHP CLI with the cURL extension installed. Code plugins execute with the Sentinel operating-system user's privileges. Inspect the plugin before enabling it.

Start your own development HTTP service on `127.0.0.1:8080`, implementing `GET /health` and/or `GET /api/status`.

From an admin SSH session:

```text
plugins enable local-loadtest
plugins run local-loadtest loadtestinfo
plugins run local-loadtest loadtest profile=health count=2 case=smoke
```

The report renders via `loadtest-report.sml`. URL, host, port, and path cannot be changed by invoking users. Queries carry a strictly validated `case` parameter. Each invocation permits 1–3 sequential GET samples with no redirects or proxy, no concurrency, and 2-second request deadlines. Results are ephemeral and do not create a persistent background job.

The built-in `attack` command is intentionally not overridden: Sentinel reserves that name for its offline synthetic lab. This plugin registers its own `loadtest` handler under the `plugins run` namespace.

For broader authorized performance testing, implement a separately reviewed and permission-brokered host runner with proof-of-control for each registered target, explicit rate limits, auditing, and cancellation.
