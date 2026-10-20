# Community Multitool Pack

Ten independently enabled code plugins, extending Sentinel beyond a CNC/network terminal into development, operations and website checks.

## Building

```sh
sh scripts/build-community-extras.sh
```

Binaries are generated in `plugins/<name>/<name>`. Cross-compile for the Sentinel host if necessary. All manifests are disabled by default; enabling requires admin review and trust policy.

## Direct SSH commands

| Plugin | Example | Actual scope |
|---|---|---|
| httpxray | `httpxray inspect url=https://example.org` | HTTP response security header presence |
| whoiz | `whoiz lookup domain=example.org` | System WHOIS binary lookup |
| jwtpeek | `jwtpeek decode token=<JWT>` | Local decode only: signature NOT verified; avoid placing live tokens in shell history |
| gitty | `gitty status` | Git status, requires SENTINEL_GITTY_ROOT environment |
| servectl | `servectl list` | Read-only systemd service list |
| termfiles | `termfiles list` | Directory listing, requires SENTINEL_TERMFILES_ROOT |
| authguard | `authguard summary` | Bounded authentication log text counts, not realtime |
| jsonfix | `jsonfix format data={"ok":true}` | JSON validation / pretty print |
| hashkit | `hashkit digest data=hello` | SHA-256 digest |
| uptimez | `uptimez check url=https://example.org` | One HTTP response check with elapsed time |

### Future categories worth supporting

- **Developer workspace:** JSON/YAML validation, Git status, build logs, database schema browsing, local API fixtures.
- **System operations:** process/service observability, backup verification, disk hygiene, containers, incident triage.
- **Web monitoring:** HTTPS checks, certificate expiration, redirects, accessibility audits, scheduled uptime with history.
- **Home lab / IoT:** MQTT inspection, read-only device status, network discovery and metrics.
- **Team collaboration:** incident notes, runbooks, handoffs, audit trails, secure webhooks.
- **Data utilities:** CSV inspection, log aggregation, SQL explain plans, transformations.
- **Automation:** scheduled plugin jobs, capability-limited workflows, event triggers and read-only report generation.

### Production limitations

This PR adds small, real command handlers, NOT full interactive SML apps, background monitors or a live marketplace publishing pipeline. Dependencies (whois, systemctl, git) must be available on the Sentinel host. External HTTP requests deny private/reserved destination IPs, disable redirects and proxies, and pin requests to validated DNS results, but operators should still enforce egress policy. Plugins execute trusted code: process isolation is not equivalent to an OS sandbox. The command transport has practical limits for JSON quoting and large JWTs.

Before public use: run `go test ./...`, compile every plugin, validate plugin discovery and SSH invocation, and review role access for host logs and remote requests.
