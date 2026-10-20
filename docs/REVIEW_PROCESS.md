# Community review and release process

We separate **source contributions** from **trusted releases**.

## 1. Proposal

Open an issue for a plugin idea, missing feature or compatibility problem. Describe the legitimate use case, users, expected output and host permissions.

## 2. Source PR

Fork this repo and submit `plugins/<id>/` with manifest, README, views and source. Keep submitted manifests disabled by default. Reviewers can comment publicly on code and documentation.

## 3. Automated validation

The `Validate community plugins` workflow parses manifests with a safe YAML loader, checks folder IDs, roles, entry points, archive/file restrictions, and checks SML files as XML. It does **not run contributed plugin code**.

A green validation check is a *format signal only*. It does not imply plugin review, binary trust, safety or marketplace acceptance.

## 4. Manual review

Maintainers check:
- Purpose, scope, permissions, compatibility and dependencies
- Code execution entry points, supply chain, exfiltration possibilities and resource use
- Secret handling, data retention, network access and users' informed consent
- Source/build reproducibility, licensing and tests
- SML readability and behavior in ordinary terminals

Changes can be rejected or require reduced capabilities. High-risk code may be unsuitable for public distribution even if it is functional.

## 5. Source merge

After approval, the source may be merged. **No executable runs in production and no catalog changes automatically occur when this happens.** Contributor identity is not considered verified simply because a PR exists.

## 6. Separate release

A maintainer independently builds the plugin for supported systems from reviewed source, verifies each archive, scans dependencies/artifacts, hosts immutable files on a publicly reachable HTTPS release endpoint, and publishes **real** SHA-256s in the administrator-approved marketplace catalog. The artifact must contain a disabled manifest. Cross-platform support must be declared accurately.

The private Sentinel V5 source repo cannot be treated as a public unauthenticated binary release host. Until a real host and reviewed catalog entry exist, do not advertise one-command marketplace installation.

## 7. Activation & maintenance

Admins explicitly install and enable trusted plugins. Executable runtimes additionally need the Sentinel host trusted-code opt-in and independent least-privilege isolation. Maintainers may revoke a listing or advise removal if a vulnerability is found.

**Never auto-execute or auto-publish code from a community PR.**
