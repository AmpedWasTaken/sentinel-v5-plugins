# Sentinel Python SDK (one-shot, v1)

This is a **standard-library-only Python 3.10+ SDK** for trusted Sentinel V5 code plugins. It implements the same JSON request/response version used by the Go/PHP one-shot plugins. There is no independent Python process supervisor or Python RPC host-service SDK yet.

## Usage

```python
from sentinel_sdk import Plugin, Request, Result

plugin = Plugin()

@plugin.command("greet")
def greet(request: Request) -> Result:
    name = request.args.get("name", request.actor)
    return Result(view="greeting", values={"name": name})

if __name__ == "__main__":
    plugin.serve()
```

Declare the command in `plugin.yaml`:

```yaml
version: 1
id: hello-python
name: Hello Python
enabled: false
roles: [admin]
runtime:
  kind: python
  entry: main.py
  timeout_ms: 2500
commands:
  - name: greet
    capability: code.invoke
```

`Plugin.command(name, handler)` also supports direct registration without a decorator. `Request` exposes `command`, `actor`, `role` and `args`; `Result` exposes `text`, `view` and `values`.

## Deployment

The updated Sentinel binary distribution includes the SDK at `assets/sdk/python/sentinel_sdk.py` and invokes the entry point using a trusted Python interpreter with **`-I` isolated mode**. Add its absolute directory to `sys.path` explicitly in your entry point (see `plugins/hello-python/main.py`). Do not rely on `PYTHONPATH` or user site-packages.

Python must be installed separately on the host. The interpreter defaults to `python3` on Linux/macOS and `python` on Windows. An administrator may configure `SENTINEL_PYTHON_BIN` with the trusted interpreter path.

## Contracts

- One bounded JSON request on stdin; one JSON response on stdout.
- Version 1; commands declared in the manifest, checked by the Sentinel host.
- `key=value` arguments, maximum 12, each at most 256 characters.
- Maximum 16 KiB request, 32 KiB response, 8 KiB text and 24 bindings.
- Only plugin-local SML views can be selected.
- Bad requests and handler exceptions produce an `error` response without a traceback on stdout.
- Do not print diagnostics to stdout (use stderr for development-only logging).

The SDK does **not** enforce host-level RBAC. Sentinel performs authorization before launching the plugin. The SDK validates protocol framing; local Python execution is **not OS-sandboxed** and requires explicit administrator trusted-code opt-in. Never run unreviewed source on sensitive hosts. Signed native marketplace release installation does not currently support source-only Python packages.

## Tests

```sh
python3 -m unittest discover -s tests -v
python3 scripts/validate_plugins.py
```
