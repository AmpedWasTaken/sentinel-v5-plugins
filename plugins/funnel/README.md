# Funnel

**Go plugin for Sentinel V5: YAML-configured network-test scenario previews.**

Funnel provides a familiar command/configuration interface for defining named test scenarios, user groups, DNS resolver labels, timeout settings and SML output.

**Safety boundary:** Funnel is **simulation-only**. It does not send TCP/UDP/HTTP requests, query DNS, call attack APIs, launch background jobs or control real network load. Configured concurrency and time values are validated and displayed, not executed.

## Configuration

Edit `config.yaml` in the installed Funnel plugin directory:

```yaml
version: 1
funnel:
  command_prefix: "!"
  kv_prefix: "-"
  timeout_unit: second
  timeout_seconds: 15
  default_duration_seconds: 60
  user_agent: ""
  callback_preview: true

  groups:
    - name: user
      max_duration_seconds: 600
      max_concurrent: 15

  dns:
    enabled: true
    resolvers: ["1.1.1.1", "8.8.8.8"]

  scenarios:
    tcp:
      enabled: true
      description: "TCP capacity-test simulation"
    dns:
      enabled: true
      description: "DNS diagnostics simulation"
```

### What the fields mean

| YAML key | Purpose |
| --- | --- |
| `command_prefix` | Single character for a future custom front end; **does not change Sentinel's SSH parser** |
| `kv_prefix` | `-` or `--` metadata for front ends, not the Sentinel argument syntax |
| `timeout_unit` | `second` |
| `timeout_seconds` | Validated range 1–60, **no actual task timer** |
| `default_duration_seconds` | Default preview duration 1–600 |
| `user_agent` | Optional display-only metadata; **never attached to requests** |
| `callback_preview` | Optional display-only flag; **never sends callbacks** |
| `groups[].max_duration_seconds` | Limits duration accepted by the preview command |
| `groups[].max_concurrent` | Simulated concurrency value 1–15; **no sockets opened** |
| `dns.resolvers` | Up to four validated public IP labels; **no DNS queries performed** |
| `scenarios` | Named preview profiles, not executable attack methods |

Configuration is decoded strictly: unknown YAML keys, invalid ranges, duplicate group names, unsafe resolver labels and a second YAML document are rejected.

## Source layout

```text
plugins/funnel/
  plugin.yaml
  config.yaml
  go.mod
  go.sum
  main.go
  main_test.go
  views/funnel-report.sml
  README.md
```

The executable implements Sentinel's existing one-shot JSON plugin protocol directly. This project is a standalone Go module and does not require access to the private Sentinel-V5 Go module to compile. It requires Go 1.23+.

## Build for local development

From `plugins/funnel/`:

```sh
go test ./...
go build -trimpath -o funnel .
```

On Windows:

```powershell
go test ./...
go build -trimpath -o funnel.exe .
```

Place the built executable in the installed plugin's `bin/` directory:

```text
assets/plugins/funnel/
  plugin.yaml
  config.yaml
  views/funnel-report.sml
  bin/funnel            # Linux/macOS
  bin/funnel.exe        # Windows
```

The Sentinel host must allow **trusted-code plugins**, and an administrator must review the source/binary and explicitly enable the plugin. Trusted-code execution is not a security sandbox. Follow Sentinel's [code-plugin documentation](https://github.com/AmpedWasTaken/Sentinel-V5/blob/main/docs/code-plugin-sdk.md) for host setup.

## Use over SSH

Once approved and enabled, use Sentinel's **real** command syntax (`key=value`, not the display-only `!`/`-` prefix):

```text
plugins enable funnel
funnel info
funnel methods
funnel preview scenario=tcp group=user duration=30
funnel preview scenario=dns group=operator duration=60
```

The terminal renders a report showing simulated scenario, group, duration, maximum configured concurrency and an explicit **no traffic sent** notice.

**No target is accepted and nothing is sent to a remote host.** The plugin is suitable for UI prototyping, permission design and dry-run configuration review, not network performance testing or traffic generation.

## Permissions

- Sentinel roles: `admin`, `operator`
- Required capability: `code.invoke` (the host executes a trusted one-shot plugin process)
- Runtime permissions: Go code reads only its local `config.yaml`; it has no network, subprocess or platform-specific dependencies
- Data storage: none; no callbacks or requests
- OS support: source is portable Go; released binaries must be built and independently reviewed per platform
- Secrets: none. Do not store API tokens or credentials in `config.yaml`.

## Security review / publication

This is a **source contribution**, not an automatically verified marketplace package. A maintainer must independently review builds and decide whether/how to release it. The existing community CI validates manifests and SML but deliberately does not execute untrusted plugin source submitted by contributors.
