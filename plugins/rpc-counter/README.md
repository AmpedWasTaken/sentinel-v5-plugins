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
