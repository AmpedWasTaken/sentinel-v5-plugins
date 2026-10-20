# Community plugin release pipeline

The reviewed Sentinel source can now produce 75 Go plugin archives (25 plugins × Linux amd64, Linux arm64, and Windows amd64) through the manual **Publish verified community plugins** GitHub Actions workflow.

## Release procedure

1. Merge this PR after local build/tests and security review.
2. In GitHub Actions, run **Publish verified community plugins** with a unique tag such as `plugins-v1.0.0`.
3. The workflow runs `go test ./...`, compiles each target binary, creates ZIPs containing `plugin.yaml` and `bin/<binary>`, and publishes a generated `catalog.json` with real SHA-256 checksums.
4. Review published assets and checksums.
5. Distribute the vetted generated `catalog.json` as `assets/marketplace/catalog.json` in Sentinel portable builds, or copy the reviewed catalog to the existing installation before using `plugins install`.
6. Start Sentinel, opt into trusted code only where appropriate, then SSH as admin: `plugins install netcatty`, followed by `plugins enable netcatty`.

## Important restrictions

- Nothing is auto-published merely because code is merged; this workflow requires an explicit manual dispatch.
- The default checked-in catalog is deliberately empty. Until a reviewed release has been published and its generated catalog deployed, `plugins install` has no available packages.
- The installer verifies SHA-256, but archive hashing **does not prove code safety or authorship**. Signed release metadata, install locking, stronger URL pinning, and integration verification remain recommended.
- Public releases host executable Go programs; all contributors and changes need review.
- The portable distributor omits source-only community plugin manifests so they do not block installing the real binary package.
- All plugins remain disabled until an administrator explicitly enables them. This is not a silently auto-activated marketplace.
- Plugins that depend on linux-specific system resources or binaries may not function on Windows, even when cross-compilation succeeds. The catalog should ultimately publish compatibility per plugin.
- Verify the release workflow and tests before relying on it; no release was dispatched in this change.

Build ZIPs locally for an existing set of cross-compiled binaries with:

```sh
python3 scripts/package-plugin-releases.py --tag plugins-v1.0.0
```
