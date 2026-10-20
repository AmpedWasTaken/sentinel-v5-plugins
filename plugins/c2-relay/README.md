# C2 Relay — Sentinel V5 plugin

**Standalone Go plugin with a readable YAML configuration, offline diagnostic previews and a narrowly scoped, read-only HTTPS health API check.**

C2 Relay takes inspiration from the *configuration and administration* parts of the older Sentinel-CNC API module, but it is not an attack dispatcher. It supports legacy `<<$target>>` URL placeholders **as a local dry-run preview**, but never calls the resulting `/attack` URL. It does not support packet floods, Qbot/Mirai, traffic generation, remote attack callbacks or SSH-selected outbound targets.

## Features

- Editable `config.yaml`: command display prefix, key-value display prefix, timeout/unit, user agent, optional callback-preview flag, groups and duration/concurrency limits.
- Read-only `check`: actual HTTPS GET to fixed, pre-approved `/health` or `/status` endpoints (disabled by default).
- Up to three approved endpoints and configurable minimum successful responses (HTTP 200/204).
- Safe-by-default outbound behavior: HTTPS port 443 only, no user-supplied target/url, no query strings, no redirects, no proxies and no private/loopback DNS results.
- Local `info`, `methods`, and `preview` commands with SML v3 terminal output.
- A `template` command for previewing an encoded legacy `/attack` URL with static `<<$target>>`, `<<$port>>`, `<<$duration>>` and `<<$method>>` placeholders; **no dispatch**.
- Bounded parser/protocol input; Go unit tests for configuration and command handling.

## Configuration

Edit `config.yaml`:

```yaml
version: 1
relay:
  command_prefix: "!"
  kv_prefix: "-"
  timeout_unit: second
  timeout_seconds: 15
  default_duration_seconds: 60
  user_agent: ""
  callback_preview: false

  groups:
    - name: user
      max_duration_seconds: 600
      max_concurrent: 15

  dns:
    enabled: true
    resolvers: ["1.1.1.1", "8.8.8.8"]

  health_api:
    enabled: false
    minimum_success: 1
    endpoints:
      - name: primary
        url: "https://example.com/health"

  # URL templating is dry-run only; the rendered URL is never requested.
  attack_template:
    enabled: true
    mode: preview_only
    url: "https://api.example.com/attack?target=<<$target>>&port=<<$port>>&duration=<<$duration>>&method=<<$method>>"

  scenarios:
    api-health:
      enabled: true
      description: "Preview the health check configuration"
```

**The example endpoint is only a placeholder.** To use the real health check, replace it with a service you operate or are authorized to query, ensure it provides a harmless `/health` or `/status` GET endpoint on HTTPS/443, then set `health_api.enabled: true`.

The `timeout_seconds: 15` setting remains a **display-only legacy-compatible field** for offline preview scenarios. A real health check enforces **1.2 seconds per endpoint**, maximum three endpoints, and the Sentinel manifest additionally limits the whole plugin process to 5 seconds. The `user_agent` is used for fixed health GET requests when enabled.

The display prefixes do not install a new SSH command parser: Sentinel accepts its regular `plugin-id command key=value` syntax. DNS resolver entries and configured concurrency limits are validated and displayed, but neither changes the host resolver nor launches connections. `callback_preview` is only metadata, and no callbacks are sent.

## Source

```text
plugins/c2-relay/
  plugin.yaml
  config.yaml
  README.md
  go.mod
  go.sum
  main.go
  health.go
  template.go
  main_test.go
  health_test.go
  template_test.go
  views/c2-relay-report.sml
```

This Go program implements Sentinel's one-shot JSON plugin protocol without importing the private core SDK. Its sole external dependency is the YAML parser `gopkg.in/yaml.v3`. It has no privileged host-service capabilities.

## Build and test

With Go 1.23+:

```sh
cd plugins/c2-relay
go test ./...
go build -trimpath -o c2-relay .
```

On Windows, build as `c2-relay.exe`. Place the reviewed binary in the installed plugin's `bin/` folder alongside the source's YAML, manifest and views:

```text
assets/plugins/c2-relay/
  plugin.yaml
  config.yaml
  views/c2-relay-report.sml
  bin/c2-relay        # Linux/macOS
  bin/c2-relay.exe    # Windows
```

The plugin is disabled by default. It requires a Sentinel administrator to review and trust the executable and explicitly enable trusted-code plugins at host level. **Process isolation is not an OS sandbox.**

## SSH commands

```text
plugins enable c2-relay
c2-relay info
c2-relay methods
c2-relay preview scenario=api-health group=user duration=30
c2-relay check
c2-relay template target=example.org port=443 duration=30 method=tcp group=user
```

`check` accepts **no arguments** and uses only the fixed health endpoints in `config.yaml`. It reports how many endpoints answered successfully, without rendering their response bodies or sending user-provided parameters.

## What was retained from Sentinel-CNC?

The former `core/attack` code had a configurable command prefix, parsed flags, method registry, groups/limits, HTTP timeouts and callback state. The legacy URL placeholder syntax can now also be parsed and **displayed without sending a request**. This plugin only adapts the **benign control/configuration concepts**:

| Legacy concept | C2 Relay |
| --- | --- |
| Prefix, key-value prefix | YAML metadata, visible in `info` |
| Attack methods | Named **offline previews**; no attack implementation |
| Groups, durations, concurrency | Validated UI configuration; no connections generated |
| API URL list, minimum success | Up to 3 fixed **read-only health** endpoints; minimum healthy responses |
| HTTP user agent and timeout | Fixed outbound health GET user agent; 1.2s endpoint limit |
| URL placeholders `<<$target>>` etc. | Display-only substitution with query-value encoding; **never sent** |
| Attack callbacks and remote dispatch | **Not supported** |

For observability integrations requiring richer authenticated JSON fields, use Sentinel's existing read-only provider system rather than extending this executable to arbitrary HTTP request templates.

## Legacy /attack URL template (dry-run only)

The `attack_template` YAML key accepts a fixed HTTPS URL ending in `/attack`. Configure `mode: preview_only` and include all four tokens in static query values:

```yaml
attack_template:
  enabled: true
  mode: preview_only
  url: "https://api.example.com/attack?target=<<$target>>&port=<<$port>>&duration=<<$duration>>&method=<<$method>>"
```

```text
c2-relay template target=example.org port=443 duration=30 method=tcp group=user
```

This produces a **text preview**, not an outbound HTTP call. The plugin validates the arguments and the group duration, substitutes URL-encoded values into the query, rejects unsupported tokens and refuses other modes such as `dispatch`. This command does not accept cookies, headers, callbacks or arbitrary URL overrides. It does not change Sentinel's SSH parser: the documented command still uses `key=value` arguments.

## Security and compatibility

Only source code is contributed to the public community repository. The automatic static PR workflow verifies source layout, YAML manifests, and SML XML; it intentionally does not run arbitrary submitted Go executables. A human must still review the binary, test in an isolated host, and approve any distribution separately. There is no automatic marketplace release or one-command install claim.
