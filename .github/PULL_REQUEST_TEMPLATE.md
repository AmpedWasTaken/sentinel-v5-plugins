## Summary

<!-- What does this change add/fix? Include the plugin ID and its purpose. -->

## Plugin / compatibility

- **Plugin ID or affected area:**
- **Sentinel version tested:**
- **Platforms tested:** 
- **Example SSH command and expected result:**

## Permissions and effects

<!-- Describe needed roles, host capabilities, external endpoints, filesystem access, dependencies, personal data collected, and side effects. Use "none" where appropriate. -->

## Validation

- [ ] `plugin.yaml` is accurate and `enabled: false` (for new plugins).
- [ ] The plugin folder includes a useful README and documents required permissions/limitations.
- [ ] All changes contain **source only**; no compiled executables or release archives.
- [ ] I ran `python scripts/validate_plugins.py`.
- [ ] I ran `python -m unittest discover -s tests -v` (or explained why not).
- [ ] I tested actual functionality in a disposable, authorized Sentinel setup (or noted it is not tested).
- [ ] I disclosed external calls, dependencies, permissions and storage behavior.
- [ ] No real credentials, private keys, sensitive logs or other secrets are committed.
- [ ] I own or have rights to license my contribution under MIT.

## Evidence and known limitations

<!-- Screenshots / text output for SML changes; explain what you could not test. -->

## Maintainer checklist (maintainers only)

- [ ] Source and dependency review
- [ ] Manifest and permission review
- [ ] Compatibility and functional review
- [ ] Separate release/security approval if publication is desired

> Merging this PR is **not** an automatic marketplace publication or a safety endorsement.
