# Hello Python — Sentinel V5

A minimal, **one-shot** Python plugin using the standard-library-only Sentinel Python SDK.

## Requirements

- Sentinel V5 with `runtime.kind: python` support and `assets/sdk/python/sentinel_sdk.py`
- Python 3.10+ on the Sentinel host (`python3` on Linux/macOS, `python` on Windows)
- Administrator-reviewed plugin source and the host-level trusted-code opt-in

## Install for local development

1. Copy this `hello-python/` directory to `assets/plugins/hello-python/`.
2. Ensure `assets/sdk/python/sentinel_sdk.py` exists (bundled with updated Sentinel, or copy from `sdk/python/sentinel_sdk.py` in this repository).
3. Configure `plugins.trusted_code=true` (or `SENTINEL_TRUSTED_CODE_PLUGINS=enabled`) and restart Sentinel.
4. As an administrator, run:

```text
plugins validate
plugins enable hello-python
hello-python greet name=Sentinel
plugins run hello-python greet name=Python
plugins disable hello-python
```

The entry point resolves the trusted SDK explicitly because Sentinel launches Python with `-I` isolated mode. It does not use PYTHONPATH or the user's site-packages.

## Protocol

The SDK reads one bounded version-1 JSON request on stdin and prints exactly one JSON response to stdout. Do not use `print()` for debugging; stderr is for diagnostics. Python execution is allowed only for trusted local code plugins and **is not OS-sandboxed**. Marketplace installers still accept signed native binary releases only.

## Test

```sh
python3 -m unittest discover -s tests -v
python3 scripts/validate_plugins.py
```
