# Community security, monitoring and AI plugins — release review

Status: **SOURCE REVIEW CANDIDATES**. Neither merging nor compiling a plugin grants it
marketplace approval. The existing SSH website only lists independently signed,
release-compatible binaries. Do not advertise `plugins install` for these IDs
until the operator-trusted catalog actually includes them.

## New plugins

| Plugin | Commands | Security model | SSH release readiness |
| --- | --- | --- | --- |
| TrafficGuard | `analyze`, `block-plan` | Offline access-log summary and IPv4/IPv6 single-IP *plan*, no shell, no packet capture, no iptables mutation | **Candidate** for a Linux isolated signed release after tests, review and packaging |
| ServerWatch | `snapshot` | Read-only `/proc` from the visible Linux process namespace | **Blocked** for reliable host monitoring until host-vs-sandbox metrics scope is explicit |
| Sentinel AI | `ask`, `explain` | Explicit-text local model inference, no tools, no remote LLM URLs, no automatic context | **Blocked** by restricted managed-plugin network namespace; needs scoped model broker |

## Existing plugins worth promoting (do not duplicate)

- **Webserver** already supports HTTP/HTTPS, static sites, virtual hosts,
  bounded rate limiting, traffic summaries and hot reload. It runs as a
  persistent worker and requires network/filesystem access forbidden by
  marketplace isolation; its older release was approved only for manual beta.
- **NetWatch** already samples actual Linux interface counters for RX/TX,
  packets per second and errors. Live host network access cannot simply
  be granted through an unrestricted marketplace binary.
- **AuthGuard**, **LogTail**, **CertCheck** and related tools provide additional
  source starting points but require scoped host-data/network access.

## Required host capabilities (future)

1. `metrics.read`: fixed read-only host kernel counters exposed through an
   authenticated broker and per-server scope, not arbitrary path reads.
2. `firewall.propose` and `firewall.apply`: read-only evaluation first;
   changes require a second MFA-backed administrator approval, registered
   customer-owned target, exact normalized IP/CIDR, per-run cap, expiry,
   rollback and immutable evidence. Plugins cannot execute `iptables`
   directly or silently elevate to root.
3. `ai.generate`: bounded model requests with explicit customer consent,
   tenant-scoped model routing, secret-free structured diagnostics, output
   labeling, rate/cost limits and no agent tool execution by default.
4. `hosting.manage`: isolated listener and static-content access, TLS asset
   handling, rate limits, deployment rollback, and explicit port/hostname ACLs.

## Release gates

- Source and test review by maintainers, including attack and error cases.
- `python scripts/validate_plugins.py`, `go test ./...`, `go vet ./...`.
- Host protocol JSON v1 smoke tests against the exact compiled binary.
- OS-specific sandbox proof (Linux bubblewrap) under a non-privileged user.
- Reproducible no-CGO build, installer-compatible ZIP, SHA-256 and Ed25519
  artifact signature generated from a **persistent** publisher key.
- Independent publisher-key distribution and operator opt-in.
- Real SSH `plugins available`, install, permissions and enable verification,
  including negative tests and rollback.
- Public immutable release artifacts verified anonymously by checksum before
  the website may offer a copyable `plugins install <id>` command.

**No destructive automation or DDoS traffic generation belongs in these plugins.**
Firewall recommendations are advisory until an independently reviewed broker
implements actual changes with recovery protections.
