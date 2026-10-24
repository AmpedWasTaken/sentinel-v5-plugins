# Sentinel V5 community plugin release status

> Audit date: 2026-10-22. Source code existing in this repository is **not**
> the same as a reviewed, installable, sandbox-compatible release.

## Approved manual-install beta (not marketplace-approved)

Maintainer approval has been recorded for the **exact released builds** of `c2-relay`, `webserver`, `netwatch`, `hello-go`, and `hello-python` in [`approvals/plugins-manual-v0.1.0.json`](../approvals/plugins-manual-v0.1.0.json). Approval is scoped to release commit `80f82e9064e1fff2ccb3b7932b09b23fb5c2508a` after successful release CI, and permits administrator-reviewed, locally trusted installation. It is **not** a blanket approval of future updates, a complete independent security audit, automatic enablement, or marketplace approval. The host's existing security checks and platform restrictions remain in force.

**[plugins-manual-v0.1.0](https://github.com/AmpedWasTaken/sentinel-v5-plugins/releases/tag/plugins-manual-v0.1.0)** is publicly published and approved **for manual installation only**, with verified Linux/Windows builds for `c2-relay`, `webserver`, `hello-go`, Linux-only `netwatch`, cross-platform `hello-python`, and a separate SDK examples archive. CI source tests, package ZIP layout, SHA-256 checks and anonymous asset download verification passed. This is an **unsigned manual-install** prerelease, not a signed approved catalog: the command `plugins install` does not support these packages. Every plugin remains disabled until a host admin explicitly reviews, installs, and enables trusted code. `c2-relay` has no attack dispatch implementation. See [manual beta installation](MANUAL_BETA_INSTALL.md).

## Publicly published

**[plugins-v0.1.0](https://github.com/AmpedWasTaken/sentinel-v5-plugins/releases/tag/plugins-v0.1.0)**
was already published. Its signed catalog contains `hashkit`, `jsonfix`, and `uptimez`
for Linux AMD64/ARM64 and Windows AMD64. All are disabled by default.

Important caveats:
- Managed binary execution in Sentinel currently requires Linux bubblewrap.
  Published Windows binaries can be downloaded/installed but **cannot be
  enabled as managed executables** on Windows using the current isolation policy.
- `uptimez` needs outbound networking, which the current bubblewrap profile
  intentionally blocks. Do **not** advertise it as a working managed HTTP probe.
- The historical v0.1 signing key may be release-scoped; operators must trust
  the *exact* independently verified publisher key, not silently assume it
  authenticates later releases.

## Proposed curated v0.2 Linux release

The following source is in the **reviewed release candidate allowlist**.
The new `plugins-v0.2.0` workflow builds six statically linked Go binaries
and wraps them in exactly the two files accepted by the current installer.

| ID | Function | Linux managed compatibility |
| --- | --- | --- |
| `hashkit` | Hash caller-supplied text using SHA-256 | No host filesystem/network needed |
| `jsonfix` | Format caller-supplied JSON | No host filesystem/network needed |
| `hookbin` | Pretty-print caller-supplied JSON | No host filesystem/network needed |

Targets: **Linux AMD64 and ARM64 only**. Every package is disabled on
installation. These are not yet published until the workflow creates and
verifies a public release, and even then the operator must independently
install a pinned trusted publisher key and configure trusted-code opt-in.

Source tests, successful compilation, exact installer archive shape, signed
artifact digests, immutable release tagging, and anonymous HTTPS download
checks are all required before announcing full publication.

## Not currently releasable as self-contained marketplace binaries

These are **not deprecated or deleted**. They remain in the community source
repository for trusted manual installation, ongoing development and review.

| Blocker | Plugin IDs | Reason |
| --- | --- | --- |
| External networking | `certcheck`, `dnsdig`, `httpxray`, `ioclookup`, `latency`, `netcatty`, `portfox`, `reqr`, `snet`, `uptimez` | Current managed sandbox does not grant network namespace access; individual sources still need endpoint/SSRF reviews |
| Host files / OS commands / monitoring | `authguard`, `docktop`, `filewatch`, `gitty`, `logtail`, `netwatch`, `pktpeek`, `servectl`, `socktop`, `sshwatch`, `sysmon`, `termfiles`, `whoiz` | `netwatch` is approved for manual Linux installation; marketplace-managed distribution still needs host resources, external binaries or privileges blocked by the existing sandbox |
| Requires additional marketplace security review | `jwtpeek`, `api-command-bridge`, `c2-relay`, `local-loadtest` | `c2-relay` is approved for manual installation with metadata/read-only health only. Any signed managed marketplace distribution, network dispatch, or increased functionality requires separate approval, constraints and isolation. |
| Alternative plugin packaging | `classic-ops`, `local-capacity`, `server-health`, `hello-go`, `hello-php`, `hello-python`, `native-stats`, `rpc-counter`, `webserver` | Presentation/provider plugins and PHP/Python or persistent RPC runtimes need packaging beyond the current strict two-file native installer; `hello-go` returns a missing SML view in that package format |

This inventory covers the plugin source directories at the time of the audit.
Do not conflate static validation, successful `go build`, an installer checksum
or a green PR with production-ready distribution.

## New community plugin review candidates (2026-10-24)

These are **source contributions**, not published signed marketplace releases:

| Candidate | What works in source | Why it is not an approved SSH release |
| --- | --- | --- |
| `trafficguard` | Offline combined-log analysis and iptables/ip6tables single-IP **proposals** with rollback text; never applies rules | Needs full Go/security tests, Linux sandbox smoke test, signed immutable artifact and operator trust |
| `serverwatch` | Fixed read-only Linux procfs load, uptime and memory summary | Sandboxed counters may not reflect the managed physical server; needs `metrics.read` broker |
| `sentinel-ai` | Explicit local OpenAI-compatible model requests with no tools or automatic context | Managed bubblewrap forbids host-loopback egress; needs `ai.generate` broker with consent and quotas |

The already published Webserver and NetWatch manual beta is **unchanged**.
To support real-time protection, a privileged firewall policy broker with
MFA-backed approval, time limits, audit evidence, quotas and automated rollback
is necessary; never solve this by making the marketplace worker privileged.
See [the release roadmap](SECURITY_MONITORING_AI_ROADMAP.md).

## TrafficGuard v0.3.0 signed-release candidate (not published)

A separate, explicit allowlist adds `trafficguard` to the existing
`hashkit`, `jsonfix` and `hookbin` Linux AMD64/ARM64 utilities.
The `.github/workflows/trafficguard-v0.3.yml` workflow runs source
validation, Go tests/vet, cross-compilation, real protocol smoke tests and
strict two-member ZIP packaging. Pull requests use a **CI-only** signing
key for validation; they cannot release artifacts. Public release requires
a **manual workflow dispatch from the reviewed main branch** and the
long-lived `SENTINEL_PUBLISHER_SEED_B64` repository secret.

Do not advertise `plugins install trafficguard` as usable until the
`plugins-v0.3.0` tag exists with anonymously verifiable checksums,
the SHA-256 of `catalog.json` is independently published, and the
approved website catalog and operators' trusted publisher policy are updated.
The user interface must not advertise source-only `serverwatch` or
`sentinel-ai` as installer-compatible.

## Security prerequisites for the next release

1. A **persistent** Ed25519 signing seed must be installed as the repository
   secret `SENTINEL_PUBLISHER_SEED_B64`. The new workflow fails closed rather
   than silently generating a disposable signing identity.
2. Operators must obtain and independently verify the public publisher key
   and place it in `assets/marketplace/trusted-publishers.json`. Never learn a
   new trusted publisher key solely from the catalog you are about to install.
3. The Sentinel host requires a functional **non-setuid** `/usr/bin/bwrap`
   on Linux with usable unprivileged namespaces. Otherwise managed executable
   activation fails closed.
4. Sentinel's `plugins.trusted_code` host opt-in remains necessary, and the
   administrator must explicitly enable each installed plugin.
5. The new release tag must have immutable public GitHub assets that are
   anonymously downloadable and match the signed catalog.
6. End-to-end validation from the intended SSH/CNC client remains necessary
   before calling Windows/Linux installations production ready.

## Installing through the SSH/CNC console

After **v0.2 is actually published** and the operator has independently
configured its signing key:

```text
plugins catalog sync https://github.com/AmpedWasTaken/sentinel-v5-plugins/releases/download/plugins-v0.2.0/catalog.json <trusted-catalog-sha256>
plugins available
plugins install hookbin
plugins permissions hookbin
plugins enable hookbin
hookbin inspect data={"hello":"world"}
```

Obtain the real catalog SHA-256 from independently reviewed release notes or
`SHA256SUMS` after publication; do not invent or reuse an obsolete digest.
`plugins catalog sync` does not trust new publisher keys automatically.
This command path does not make the native binaries executable on Windows.

## Separate release responsibilities

- `scripts/package-curated-release.py`: builds exact two-member ZIPs from an
  explicit allowlist of reviewed Linux Go plugin binaries.
- `cmd/sign-curated-release/main.go`: signs exact artifact IDs and hashes with
  a persistent, operator-approved publisher seed.
- `scripts/verify-curated-release.py`: verifies file layout, digests, signer
  metadata and emits `SHA256SUMS`.
- `.github/workflows/publish-curated.yml`: runs build/vet/checks, immutable
  public release publication and anonymous download verification.
- `.github/workflows/validate.yml`: dry-runs build/sign/packaging with a
  clearly labeled deterministic **CI-only key** that is never shipped.

Historical v0.1 scripts and release files are preserved for auditability,
not used as a substitute for the current trusted release policy.
