# Community plugin releases and CNC installation

The signed public [v0.1.0 beta](https://github.com/AmpedWasTaken/sentinel-v5-plugins/releases/tag/plugins-v0.1.0)
already contains binary assets for `hashkit`, `jsonfix`, and `uptimez`.
See [release status](RELEASE_STATUS.md) for why some shipped binary artifacts
are **not** executable under Sentinel's current host isolation policy.

## Current supported release path: curated Linux utilities

`release-manifests/plugins-v0.2.0.json` is the independent maintainer-reviewed
allowlist. The workflow `.github/workflows/publish-curated.yml`:

1. Validates source plugin manifests and runs Go tests/vet.
2. Builds static Go executables for **Linux AMD64 and ARM64**.
3. Packages only the allowlisted `hashkit`, `jsonfix`, `hookbin` utilities.
4. Requires an existing `SENTINEL_PUBLISHER_SEED_B64` GitHub Actions secret.
5. Signs the exact artifact identity/version/platform/SHA-256 using Ed25519.
6. Verifies every ZIP is compatible with the strict two-file Sentinel installer.
7. Refuses to overwrite an existing tag.
8. Publishes immutable GitHub Release assets from this **public repository**.
9. Verifies downloaded public ZIP bytes match the approved catalog hashes.

Without the persistent private signing seed, publication fails closed instead
of introducing a new unverifiable publisher identity. The private key must
never be committed, uploaded to a plugin or included in a portable release.

```sh
python -m pip install PyYAML==6.0.2
go test ./...
go vet ./...
# Build binaries at build-plugins/linux-{amd64,arm64}/<plugin>
python scripts/package-curated-release.py
SENTINEL_PUBLISHER_SEED_B64="<from-approved-secret-store>" go run ./cmd/sign-curated-release
python scripts/verify-curated-release.py
(cd release-plugins && sha256sum -c SHA256SUMS)
```

The CI `curated-release-dry-run` job uses an explicitly **test-only** key and
does not publish artifacts. A green pull request is not the same as a signed
public release.

## Use from the Sentinel SSH/CNC command console

Once v0.2 is **actually public and independently verified**, download/review
its publisher's public key and install it into your local trusted-publishers
store. An administrator must separately obtain the published catalog SHA-256
from a trusted source, then run:

```text
plugins catalog sync https://github.com/AmpedWasTaken/sentinel-v5-plugins/releases/download/plugins-v0.2.0/catalog.json <verified-sha256>
plugins available
plugins install hookbin
plugins permissions hookbin
plugins enable hookbin
hookbin inspect data={"hello":"world"}
```

Sentinel's managed binary runtime currently requires Linux `/usr/bin/bwrap`
with non-setuid installation and functional unprivileged namespaces, in
addition to administrator trusted-code opt-in. The Windows native runtime
**fails closed** for marketplace-managed executables until proper Windows
OS isolation is implemented. A release ZIP alone cannot fix that.

## Historical / build-only tools

- `publish-initial-beta.yml` and `package-initial-beta.py` remain archived
  in place as historical v0.1 tooling; they target the existing immutable tag.
- `publish-community-plugins.yml` is now **build-only** for developer review
  artifacts and is not an approved release path. Its generic 25-plugin
  packager does not provide a complete signing, sandbox or compatibility
  review. Do not publish its unsigned catalog as an installable release.
- Declarative SML experiences, Python/PHP script packages, RPC workers and
  host-network/admin tools need separate, reviewed distribution contracts.

Publishing and enabling arbitrary executables can expose the entire Sentinel
OS account. Do not work around the sandbox simply to make an install command
succeed.
