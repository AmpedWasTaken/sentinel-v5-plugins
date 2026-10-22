<div align="center">

# Sentinel V5 — Community Plugins

**Build, share and improve plugins for Sentinel V5.**

Community-maintained extensions for the Sentinel V5 SSH workspace: diagnostics, administration, observability, integrations and terminal-first tools.

[Contribute a plugin](CONTRIBUTING.md) · [Developer guide](docs/PLUGIN_GUIDE.md) · [Security policy](SECURITY.md) · [Request a plugin](https://github.com/AmpedWasTaken/sentinel-v5-plugins/issues/new/choose)

</div>

---

## Welcome

This is the **public contribution repository** for [Sentinel V5](https://github.com/AmpedWasTaken/Sentinel-V5). Anyone can propose a plugin, contribute source code, improve SML screens, or help review existing contributions.

This is also the canonical source for Sentinel's extracted example and community plugins. **This repository is not an automatically published marketplace.** A merged pull request means the source is accepted into this repository; it does **not** mean the plugin has passed a full security audit, been compiled for all platforms, or become installable from Sentinel's marketplace.

### What can you build?

| Category | Example ideas |
| --- | --- |
| Observability | Network traffic snapshots, logs, process summaries, health dashboards |
| SSH & server administration | Service status, deployment diagnostics, inventory reports |
| Developer tools | Git insights, HTTP inspection, JSON utilities, environment checks |
| Python examples | [hello-python](plugins/hello-python/) demonstrates the one-shot Python SDK and isolated interpreter launch |
| Security & defense | Local auditing, certificate expiry, DNS diagnostics, auth event summaries |
| Integrations | Read-only status providers for approved external APIs |
| Terminal experiences | SML dashboards, interactive views, styled reports |

Only contribute plugins you are authorized to run and test. We do not accept credential theft, unauthorized access, malware, DDoS/booter tools, stealth persistence or destructive functionality.

## Contribute your first plugin

1. **Fork** this repository and create a feature branch.
2. Add your source under `plugins/<plugin-id>/` using a unique lowercase slug.
3. Include `plugin.yaml` with `enabled: false`, a small `README.md`, and any views, provider config, or source files you need.
4. Run the local validator (see below) and test in a disposable Sentinel installation with the minimum necessary permissions.
5. Open a **pull request**. Our submission checklist appears automatically.

A source-only sample is available at [`examples/sample-health/`](examples/sample-health/). It is a **configuration example** with a placeholder HTTPS URL, not a live integration.

```text
plugins/
  your-plugin/
    plugin.yaml
    README.md
    providers.yaml       # optional: read-only HTTPS provider integration
    views/
      report.sml         # optional: terminal UI
    main.go              # optional: code plugin source; never a compiled binary
```

### Minimal manifest

```yaml
version: 1
id: your-plugin
name: Your Plugin
description: Read-only utility for your Sentinel workspace
enabled: false
roles: [admin, operator]
commands:
  - name: report
    description: Show a status report
    provider: status
```

That declarative example also requires a matching `providers.yaml` and optional SML view. For executable Go/PHP plugins, follow the linked Sentinel SDK documentation and disclose every required host capability.

## Validate locally

Requires Python 3.11+ and PyYAML (version used by CI: 6.0.2).

```bash
python -m pip install PyYAML==6.0.2
python scripts/validate_plugins.py
python -m unittest discover -s tests -v
```

The validator checks path hygiene, manifest shape, disabled-by-default state, declared commands, and well-formed XML in `.sml` files. **Static validation does not execute plugin code and is not a malware scanner or security approval.** Maintainers review dependencies, capabilities, source and release artifacts separately.

## Using community plugins

During development, a server administrator can manually review and place a trusted plugin folder under Sentinel's `assets/plugins/<id>/`, then configure and enable it in the host. Executable plugins additionally require host-level trusted-code opt-in and should not be installed on a sensitive system without isolation and review.

For released plugins, Sentinel's intended command flow is:

```text
plugins available
plugins install <id>
plugins enable <id>
```

**This only works after a maintainer publishes a reviewed, platform-compatible ZIP to a reachable public HTTPS host and updates the locally approved catalog with the real SHA-256.** This repository currently does not produce, approve or publish downloadable releases automatically. A pull request by itself is not an install command.

## Review and publication

Every contribution goes through basic format checks, manual code/security review and compatibility review. Maintainers may request changes or decline code they cannot safely review.

See [Review process](docs/REVIEW_PROCESS.md) for the complete workflow and clear distinction between *submitted*, *merged*, *reviewed*, and *published*.

## Community

- [Contributing](CONTRIBUTING.md) — fork/PR workflow, review requirements and quality bar
- [Plugin guide](docs/PLUGIN_GUIDE.md) — file format, SML, manifest examples and testing
- [Issue templates](https://github.com/AmpedWasTaken/sentinel-v5-plugins/issues/new/choose) — propose plugins, request features, report bugs
- [Code of conduct](CODE_OF_CONDUCT.md) — how we collaborate
- [Security policy](SECURITY.md) — private vulnerability reporting

### Maintainers & license

Maintained by **AmpedWasTaken** with community contributions. Source in this repository is distributed under the [MIT License](LICENSE); contributors retain their own copyright and must have the rights to submit their code. Check individual dependencies' licenses before redistribution.

> Sentinel V5 and this community repository are active development projects. Plugin interfaces, packaging and marketplace availability may evolve. Consult the actual Sentinel version and SDK before writing code that depends on specific host APIs.

## Extracted plugin source

Previously bundled extensions now live in [`plugins/`](plugins/), with their sources and SML assets. Plugin Go code builds independently from the private core:

```sh
go test ./...
go vet ./...
go build -o /tmp/netwatch ./plugins/netwatch
```

See [MIGRATION.md](MIGRATION.md). Merging source never automatically approves, publishes or enables binaries.
