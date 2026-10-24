# ServerWatch — read-only Linux health snapshots

Reads the *visible* kernel procfs counters and returns load averages, memory
usage and uptime. No privileged shell, network requests, changes, or daemon.

```text
serverwatch snapshot
```

The command accepts no arguments and reads only three fixed paths:
`/proc/loadavg`, `/proc/uptime`, and `/proc/meminfo`.

**Scope matters:** a sandbox may expose its own process namespace, memory,
or view of the host rather than the actual physical server. This plugin does
not claim container-independent CPU or memory statistics. For precise
multi-server telemetry, Sentinel will need a scoped, consented metrics broker
or an enrolled read-only monitoring agent.

Only run this on a Linux Sentinel instance with explicitly approved
plugin permissions and compatible isolation. Source is not an approved
SSH-marketplace release until reviewed, signed and smoke-tested.
