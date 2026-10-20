# Contributing to Sentinel V5 Community Plugins

Thank you for building for the Sentinel community. We want real, useful plugins with clear behavior, minimal permissions and enough documentation that another person can maintain them.

## Before you start

- Read [the plugin guide](docs/PLUGIN_GUIDE.md), [security policy](SECURITY.md), and [code of conduct](CODE_OF_CONDUCT.md).
- For a new or major plugin, [open a proposal issue](https://github.com/AmpedWasTaken/sentinel-v5-plugins/issues/new/choose) first to discuss scope.
- Confirm you own or have permission to use the API, server or test environment.
- Prefer a read-only, least-privilege design and document any side effects.

## Submit a plugin

1. Fork the repository.
2. Create a branch such as `feat/my-plugin`.
3. Add `plugins/my-plugin/plugin.yaml`, a plugin-local `README.md`, and needed source/views/config. One plugin per folder and PR is preferred.
4. Use a unique lowercase ID (letters, digits, hyphens); keep the folder name and `plugin.yaml` ID identical.
5. Set `enabled: false` and use only roles and capabilities essential for the task.
6. Keep secrets out of commits. Provide placeholder configuration examples and explain environment variables instead.
7. Run the validator and unit tests; test actual behavior locally and document OS/architecture requirements.
8. Open a PR using the automatic checklist. Include an example command, expected output, risks, a screenshot or terminal capture when visual changes are involved, and test notes.

```bash
python -m pip install PyYAML==6.0.2
python scripts/validate_plugins.py
python -m unittest discover -s tests -v
```

For a plugin that uses Go/PHP, **commit source code, not precompiled binaries**. Do not check in archives, installers, build outputs, credential files or vendored third-party executables.

## What belongs in a plugin README?

- Purpose, supported Sentinel version and supported OS/architectures
- Commands and examples, with real expected outputs
- Installation/configuration steps, without implying automatic marketplace publication
- Manifest roles/capabilities and why they are necessary
- Environment variables (names only; never secret values)
- Network calls, local file access, data collected or written, and retention
- How to test, known limitations, dependencies, source attribution and license

## Code and security expectations

Changes must be focused, reviewable and safe by default. A reviewer must be able to identify every external dependency, host-side side effect, executable entry point and network destination.

We do not accept unauthorized intrusion features, traffic flooders, credential harvesting, malicious persistence, evasion, hidden remote access, or logic that bypasses Sentinel's permissions. Approved internal diagnostic and defensive functionality should be limited in scope, rate and impact.

**No executable plugin is sandboxed merely because it runs in a separate process.** The current runtime requires explicit administrator trust; submission or passing CI is not a trust signal.

## PR review & maintenance

A maintainer may ask for:
- Compatibility fixes for the actual Sentinel SDK.
- Tests or proof of expected terminal behavior.
- Reduced capabilities, dependencies, I/O, privileged features or permissions.
- Security and privacy documentation or changes.
- Removal of opaque/binary assets.

Do not assume an accepted PR becomes a marketplace entry or installable artifact. Releases are a separate, explicitly reviewed and verified process documented in [Review process](docs/REVIEW_PROCESS.md).

Small, focused PRs are easier to review. Be respectful of review time, keep branches up to date and avoid unrelated file changes.

## Licensing

By contributing you agree to license your original contribution under this repository's MIT license. You retain copyright. Do not submit code, third-party assets or dependencies you lack permission to redistribute. Disclose relevant third-party licenses in the plugin README.
