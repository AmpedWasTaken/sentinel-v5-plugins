# Sentinel NetWatch

Read-only network interface monitoring plugin using **actual Linux kernel** byte counters from `/proc/net/dev`. It measures a one-second interval and produces an SML dashboard with RX/TX throughput and total counters.

## Build

From the repo root on Linux:

```sh
go build -o plugins/netwatch/bin/netwatch ./plugins/netwatch
go test ./plugins/netwatch
```

Sentinel must be started with explicit trusted code plugin opt-in (`plugins.trusted_code=true` or `SENTINEL_TRUSTED_CODE_PLUGINS=enabled`) because the current code-plugin process is not sandboxed.

In an authenticated Sentinel terminal:

```text
plugins validate
plugins enable netwatch
netwatch interfaces
netwatch
netwatch interface=all
netwatch watch interface=eth0
```

Available to allowed admin/operator accounts while globally enabled.

## Limitations

- Linux host only. The Windows plugin binary can compile, but sampling deliberately fails with a clear message because Windows interface sampling is not implemented.
- The present code SDK launches a short-lived plugin executable for each invocation (maximum 5-second timeout), so this is a **real on-demand one-second measurement**, not continuous streaming. No background worker, web push, historical charts or connection-level inspection is claimed.
- The default `interface=all` aggregates all non-loopback adapters visible at the beginning and end of the one-second sample; you may select an interface explicitly. The SML view also displays packet rates per second.
- Displays host counters; does not perform remote scans, inspect packet contents or generate traffic.

## Extended monitoring

The `interfaces` command reads real interface RX/TX totals and error counters, including loopback, without waiting for a sample. `watch` also shows packet totals and RX/TX errors in its SML display. Measurements are kernel counters, not generated or mock values. The plugin still uses on-demand snapshots; continuous streaming and persistent historical charts are not yet implemented.

## Interface DataTable (V5)

`netwatch interfaces` now renders real Linux interface counters using `views/interfaces.sml` and the SML DataTable engine, including RX/TX totals and errors. The plugin **must be rebuilt** after updating `plugins/netwatch/main.go`; updating assets alone does not replace the compiled executable. Only the first 48 interfaces are displayed in the bounded table.
