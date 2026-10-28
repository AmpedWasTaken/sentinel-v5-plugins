# Persistent Counter — verified runtime example

Source: `plugins/rpc-counter/main.go`. Build this example locally:

```sh
go build -o plugins/rpc-counter/bin/rpc-counter ./plugins/rpc-counter
```

On Windows use `rpc-counter.exe`.

Set `plugins.trusted_code=true` in your administrator-managed Sentinel configuration or explicitly opt in through the documented trusted-code environment variable. This is **trusted host code** and is not sandboxed.

```text
plugins enable rpc-counter
plugins run rpc-counter counter
plugins run rpc-counter counter
plugins disable rpc-counter
```

The counter persists under server-managed `plugin-data/rpc-counter.json`, not in the plugin asset directory. It also publishes `plugin.rpc-counter.changed` on the in-memory event bus. Plugin state survives restart, while event delivery is currently in-memory and not durable.

The manifest requests only three explicit capabilities. The host performs all storage operations and validates the plugin identity independently of the worker's requests.

This example is installed disabled; a compiled executable is required before enabling it.

## Native Sentinel Apps example

This plugin also declares an optional multi-page `app` section for the native
Sentinel Apps foundation (Sentinel-V5 PR #289). It continues to support the
traditional `plugins run rpc-counter counter` command unchanged.

1. Build and install the compiled plugin and reviewed `views/*.sml` assets.
2. Enable trusted local plugin code according to your host security policy.
3. Run `plugins enable rpc-counter` as an authorized administrator.
4. Enter `mode tui`, switch to **Apps**, and open **Persistent Counter**.
5. Select **Increment Counter** to invoke the declared `counter` command
   through the existing host-authorized RPC dispatch.

The count and health status use the existing bounded, expiring `ui.publish`
bindings `plugin.rpc_counter.count` and `plugin.rpc_counter.health`.
They are blank before the first successful publish and are not a durable
streaming subscription. The separate old `counter.sml` screen remains
available when running the command directly.

**Security:** This executable is trusted local code and is not inherently
sandboxed. The requested storage and telemetry capabilities must remain
explicitly granted. No new host capabilities are required for app pages.
