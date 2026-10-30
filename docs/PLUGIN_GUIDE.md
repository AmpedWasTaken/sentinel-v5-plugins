# Building a Sentinel V5 plugin

Sentinel supports declarative read-only report plugins and opt-in trusted code plugins. This guide focuses on the formats actually used in the [Sentinel V5 source](https://github.com/AmpedWasTaken/Sentinel-V5).

> Interfaces are under active development. Always test against a specific Sentinel version. Community submissions do not become public installer artifacts by merging a PR.

## Choose a runtime

| Approach | Manifest | Use case | Security |
| --- | --- | --- | --- |
| Declarative | `commands[].provider` plus `providers.yaml` | Read-only HTTPS JSON data and SML reports | No custom executable |
| Python CLI | `runtime.kind: python`, `entry: main.py` | Python diagnostics, scripting, AI integrations | Requires reviewed Python source, interpreter and host trusted-code opt-in |
| PHP CLI | `runtime.kind: php`, `entry: main.php` | Custom command handler | Requires host trusted-code opt-in |
| Compiled Go/other | `runtime.kind: exec`, `binary: <id>` | One-shot command handler | Requires reviewed compiled binary and trusted-code opt-in |
| Persistent Go/other | `runtime.kind: exec-rpc`, `binary: <id>` | Long-running stateful handler with brokered services | Requires reviewed binary; isolation remains incomplete |

## Layout

```text
plugins/
  my-plugin/
    plugin.yaml
    README.md
    providers.yaml         # optional for a provider-based plugin
    config.yaml            # optional plugin configuration (config.yml and config.json also accepted)
    views/
      my-report.sml        # optional
    main.go                # optional source for a Go plugin
```

### Manifest

```yaml
version: 1
id: my-plugin
name: My Plugin
description: Display approved service telemetry
enabled: false
roles: [admin, operator]
commands:
  - name: report
    description: Read a health report
    provider: health
```

A declarative `commands[].provider` requires an entry with the same key in `providers.yaml`. Source-based commands instead declare a code capability, e.g.:

```yaml
version: 1
id: my-plugin
name: My Plugin
description: A trusted Go CLI example
enabled: false
roles: [admin]
runtime:
  kind: exec
  binary: my-plugin
  timeout_ms: 4000
commands:
  - name: status
    description: Print a status
    capability: code.invoke
```

The manifest is not an installer: source must be separately built and packaged before approved publication. **Do not commit a binary to this repo.**

### Declarative provider

A matching `providers.yaml` can request an explicitly configured public HTTPS GET report:

```yaml
version: 1
providers:
  health:
    enabled: true
    roles: [admin, operator]
    request:
      method: GET
      url: "https://api.example.com/v1/metrics"
      arguments:
        instance:
          query: instance
          type: string
          required: false
    response:
      success: {path: success, equals: "true"}
      fields:
        health: data.status
      views:
        success: health-report
```

Replace the placeholder host with an authorized API when configuring your own installation. Sentinel's provider transport has URL/SSRF restrictions; do not try to bypass them.

### SML view

```xml
<screen name="health-report" version="3">
  <panel title="SERVICE HEALTH" border="round" padding="1">
    <badge tone="success" variant="outline">Telemetry</badge>
    <field label="HEALTH" key="api.health"/>
  </panel>
</screen>
```

SML is validated XML for terminal presentation, not HTML/CSS or executable code. Current v3 supports inline attributes on supported elements (borders, padding, variants and more), presentation-only bindings and validated interactive actions.

### Invoking a command

After local administrator configuration and explicit enablement, the first command in a manifest is used as the default direct SSH command:

```text
my-plugin
my-plugin report
```

Older installations may also support `plugins run my-plugin report`. Exact command availability is version- and plugin-dependent. Name collisions require qualifying the command with the plugin ID.

## Native C from Python

Python plugins can call precompiled native C libraries through `ctypes` while keeping the same Sentinel `runtime.kind: python` command protocol. The SDK includes `sentinel_native.load_c_library`, which loads a fixed library basename from the plugin's `native/` folder using an absolute path. Libraries must be built separately for each operating system and architecture and reviewed as trusted code. The [native-stats example](../plugins/native-stats/) includes real C source, Python bindings, cross-platform compilation, SML screens and end-to-end tests.

## Local test checklist

1. Run `python scripts/validate_plugins.py` and the repository unit tests.
2. Validate that `plugin.yaml` parses in your installed Sentinel version.
3. Confirm all referenced SML views exist, match their screen names and render at narrow terminal widths.
4. Verify command output, error handling, authorization and disabled-by-default behavior.
5. Verify external requests only reach documented approved endpoints.
6. Verify role/capability restrictions and that secrets are not printed or committed.
7. Document the supported OS/architecture and exact build/install instructions.

## Core documentation

- [Plugin SDK and declarative provider format](https://github.com/AmpedWasTaken/Sentinel-V5/blob/main/docs/plugins-sdk.md)
- [Code plugins / PHP and executable example](https://github.com/AmpedWasTaken/Sentinel-V5/blob/main/docs/code-plugin-sdk.md)
- [Persistent Go runtime](https://github.com/AmpedWasTaken/Sentinel-V5/blob/main/docs/plugin-app-runtime.md)
- [Direct SSH commands](https://github.com/AmpedWasTaken/Sentinel-V5/blob/main/docs/direct-plugin-commands.md)
- [Verified installer](https://github.com/AmpedWasTaken/Sentinel-V5/blob/main/docs/verified-plugin-installer.md)

The core repo may be private or inaccessible to some contributors. This guide supplies a minimal public starting point; maintainers should keep it synchronized with source changes.

## Community Marketplace developer workflow

The website lets signed-in developers publish source-only versions using a ZIP or a public GitHub repository pinned to a commit SHA. Public listings are **community-made and unreviewed by default**. They are never SSH-installable merely because a user uploaded code or passed automated checks.

Generate a minimal SML starter with Python 3.9+:

```sh
python scripts/plugin-devkit.py init my-widget ./my-widget
python scripts/plugin-devkit.py check ./my-widget
python scripts/plugin-devkit.py pack ./my-widget ./my-widget-1.0.0.zip
```

The archive has a root-level `plugin.yaml`. Upload it from **Dashboard → Community Plugins**. Alternatively use **Import GitHub**, specify a public repository and optional subdirectory. The importer selects supported SDK files from a pinned commit and validates the resulting package.

The developer tool's layout checks are not a malware scan. Source inspection and heuristic warnings cannot establish safety. Review network endpoints, dependencies, privileges and opaque executables before running third-party code.

An uploaded source package is not an approved distribution release. Consult [Community plugin releases](community-plugin-releases.md) for independently signed artifacts and host isolation requirements.

```sh
python -m unittest discover -s scripts -p 'test_plugin_devkit.py'
```
