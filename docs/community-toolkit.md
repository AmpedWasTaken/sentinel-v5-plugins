# Community toolkit plugins (initial implementations)

15 independently switchable Go plugins using the Sentinel V5 plugin SDK. They are authored in this repository; **do not attribute them to fictitious community authors**. They are **not** currently uploaded into a running marketplace service.

## Build

From repository root, on the target host (or cross-compile for its OS/architecture):

```sh
sh scripts/build-community-plugins.sh
```

Plugin binaries must reside in their corresponding `plugins/<id>/` directories alongside `plugin.yaml`. Your Sentinel deployment must allow administrator-reviewed trusted code plugins. A plugin is disabled by default.

## Plugins and direct SSH commands

| Plugin | Command | Notes |
|---|---|---|
| netcatty | `netcatty connect host=127.0.0.1 port=80 data=hello` | Bounded TCP/UDP client; `scan` checks one port |
| pktpeek | `pktpeek capture interface=eth0 timeout=3` | Requires Linux, tcpdump, and capture permissions |
| portfox | `portfox check host=127.0.0.1 port=22` | One TCP port per invocation |
| sysmon | `sysmon stats` | Host memory counters (Linux) and runtime statistics |
| reqr | `reqr request url=https://example.org method=GET` | No redirects, 3 KiB response preview |
| dnsdig | `dnsdig lookup host=example.org type=MX` | A, AAAA, MX, TXT, NS, CNAME |
| certcheck | `certcheck inspect host=example.org port=443` | TLS verification enabled |
| logtail | `logtail read source=auth` | /var/log/auth.log, /var/log/secure, or syslog |
| latency | `latency probe host=127.0.0.1 port=443` | TCP connect latency, not ICMP ping |
| socktop | `socktop connections` | Read-only Linux kernel socket tables |
| filewatch | `filewatch hash file=auth` | Curated /var/log files; no arbitrary path access |
| docktop | `docktop ps` | Requires installed Docker + permission |
| sshwatch | `sshwatch sessions` | Uses host `who` binary |
| hookbin | `hookbin inspect data={"hello":"world"}` | Local JSON inspection, not a public webhook receiver |
| ioclookup | `ioclookup resolve host=example.org` | DNS resolution only; no reputation scoring |

Enable individually as an administrator, e.g. `plugins enable dnsdig`, then use the commands above over SSH without `plugins run`.

## Boundaries and limitations

- The functions run on the Sentinel host and access its own network namespace and service privileges.
- No shell execution through client input, arbitrary command parameters, persistent proxy, remote shells or port forwarding.
- These are baseline implementations: they do not yet implement the proposed interactive SML dashboards, persistent workers, upload/verification marketplace flow, full scan ranges, realtime packet graphs, or historical storage.
- `reqr` performs HTTP requests on the server's behalf: enforce destination egress allowlists / SSRF protection in deployment before exposing to untrusted operators.
- Logs and session information may be sensitive. Limit roles to appropriate trusted operators.
- Per-command 9s plugin timeout, request timeouts capped at 7s; one-shot captures.
- Compile and runtime integration tests are still required before merging into production.
