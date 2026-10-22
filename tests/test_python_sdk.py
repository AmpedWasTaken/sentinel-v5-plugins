"""Python SDK and hello-python protocol tests (no Sentinel server required)."""
from __future__ import annotations

import importlib.util
import io
import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SDK = ROOT / "sdk" / "python" / "sentinel_sdk.py"
EXAMPLE = ROOT / "plugins" / "hello-python" / "main.py"

spec = importlib.util.spec_from_file_location("sentinel_sdk", SDK)
assert spec is not None and spec.loader is not None
sdk = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = sdk
spec.loader.exec_module(sdk)


class PythonSDKTests(unittest.TestCase):
    def request(self, command="greet", **args):
        return json.dumps({
            "version": 1, "command": command, "actor": "tester",
            "role": "admin", "args": args,
        }).encode("utf-8")

    def test_one_shot_protocol(self):
        app = sdk.Plugin()

        @app.command("greet")
        def greet(request):
            return sdk.Result(view="greeting", values={"name": request.args["name"]})

        result = app.handle(self.request(name="Sentinel"))
        self.assertEqual(result["version"], 1)
        self.assertEqual(result["result"]["values"]["name"], "Sentinel")
        self.assertEqual(result["result"]["view"], "greeting")
        target = io.StringIO()
        app.serve_io(io.BytesIO(self.request(name="Test")), target)
        self.assertEqual(len(target.getvalue().splitlines()), 1)
        self.assertEqual(json.loads(target.getvalue())["result"]["values"]["name"], "Test")

    def test_rejects_invalid_input(self):
        app = sdk.Plugin()
        for bad in (
            b"",
            b"not JSON",
            b'{"version":1,"version":1}',
            b'{"version":2,"command":"greet","actor":"tester","role":"admin","args":{}}',
            b'{"version":1,"command":"../../wrong","actor":"tester","role":"admin","args":{}}',
            b'x' * 16385,
            self.request(command="missing"),
        ):
            response = app.handle(bad)
            self.assertIn("error", response)
            self.assertEqual(response["version"], 1)

    def test_rejects_bad_result(self):
        app = sdk.Plugin()
        app.command("greet", lambda _: sdk.Result(view="../escape"))
        self.assertIn("error", app.handle(self.request()))
        with self.assertRaises(ValueError):
            app.command("greet", lambda _: sdk.Result())

    def test_example_under_isolated_python(self):
        completed = subprocess.run(
            [sys.executable, "-I", str(EXAMPLE)],
            input=self.request(name="Python"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=8,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr.decode("utf-8", "replace"))
        result = json.loads(completed.stdout)
        self.assertEqual(result["result"]["view"], "greeting")
        self.assertEqual(result["result"]["values"]["name"], "Python")


if __name__ == "__main__":
    unittest.main()
