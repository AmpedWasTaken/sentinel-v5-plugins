# Sample Health

A **non-functional until configured** declarative example for new Sentinel contributors. It shows a disabled `plugin.yaml`, a read-only HTTPS JSON provider and a styled SML v3 view. It does not contain application code or a real service endpoint.

## Try it in a disposable Sentinel host

1. Copy this folder to `assets/plugins/sample-health/` in a Sentinel installation you control.
2. Configure `providers.yaml` with an authorized, accessible public HTTPS GET metrics API. Do **not** use the placeholder `api.example.com` or embed a token directly.
3. Adjust `request.response` mappings to match that API's actual JSON response.
4. As an administrator, review and enable the plugin (it ships disabled).
5. Run `sample-health report` and inspect the SML result.

## Permissions and behavior

- Roles: `admin` and `operator`.
- Runtime: declarative HTTPS JSON provider, **no code execution**.
- Network: an operator-configured, approved HTTPS GET endpoint.
- Storage: none.
- Sensitive data: none should be configured or logged.
- OS support: host-dependent, no compiled binaries.
- SDK compatibility: test against the installed Sentinel V5 revision before assuming the example works.

See [Plugin guide](../../docs/PLUGIN_GUIDE.md). This is a documentation sample and **not** an approved marketplace release.
