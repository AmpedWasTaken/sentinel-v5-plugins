# SNet — Netcat-inspired Sentinel V5 plugin

A small, bounded networking diagnostics plugin built using the **real Go SDK**. It runs on the **Sentinel server**, not the SSH client's machine.

## Build

From the repository root:

```sh
go build -o plugins/snet/snet ./plugins/snet
```

On Windows build Linux binary with `GOOS=linux GOARCH=amd64` in the target environment. Compile for the same OS/architecture as the Sentinel host. The executable must be available at the relative runtime binary path defined in `plugin.yaml`. Enable trusted code plugins according to your Sentinel deployment policy, then from the SSH terminal (admin):

```text
plugins enable snet
```

## Commands (SSH, no plugin run prefix)

```text
snet connect host=127.0.0.1 port=8080 data=hello
snet connect host=127.0.0.1 port=80 data="GET / HTTP/1.0" crlf=true
snet scan host=127.0.0.1 ports=22,80,443 timeout=1
snet banner host=127.0.0.1 port=22 timeout=2
snet udp host=127.0.0.1 port=9999 data=ping
snet listen port=9999 timeout=8
```

Sentinel argument parsing governs quoting. In the current command transport, data is limited to simple UTF-8 text; raw binary and stdin streaming are not provided. All operations are synchronous. The listener accepts **one** connection on **127.0.0.1** and terminates; it cannot bind a public interface. Results are capped to 2048 bytes, payloads to 1024 bytes, and timeouts to 8 seconds. Scans accept up to 32 explicit TCP ports (no ranges) and may be cut short by the plugin's overall 12-second runtime timeout.

**Security:** operator/admin only; use on authorized systems. This plugin does not execute local/remote commands, provide reverse or bind shells, proxy, or stream files. The plugin process itself is trusted code and is not a sandbox; administrators should restrict egress at the host/container firewall as appropriate.
