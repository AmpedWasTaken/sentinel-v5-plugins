# Plugin migration

On 2026-10-20, the Sentinel V5 project's plugin manifests, SML assets and Go/PHP plugin implementations were extracted to `plugins/`, with community Go helpers under `pkg/` and the example PHP SDK under `sdk/php/`.

Sentinel V5 core retains plugin loading, the security scanner, the marketplace installer and SDK APIs. New installs do not automatically bundle the examples; existing installed plugins remain untouched.

Review manifests and binary releases before installation. This repository is source-only. Compiled releases still require an explicit manual build, checksum verification, immutable public hosting and an administrator-approved catalog.

Run `go test ./...` and `go vet ./...` here. The `plugins/c2-relay` module has separate CI.
