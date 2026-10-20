"""Regression tests for the static, no-execution plugin validator."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1] / "scripts" / "validate_plugins.py"
spec = importlib.util.spec_from_file_location("validate_plugins", SOURCE)
validator = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validator)


MANIFEST = """version: 1
id: sample
name: Sample
description: Read-only status
enabled: false
roles: [admin]
commands:
  - name: report
    description: Display an authorized status
    provider: health
"""

PROVIDERS = """version: 1
providers:
  health:
    enabled: true
    roles: [admin]
    request:
      method: GET
      url: https://api.example.com/v1/status
    response:
      fields:
        health: data.status
      views:
        success: report
"""


class ValidatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.plugin = self.root / "plugins" / "sample"
        self.plugin.mkdir(parents=True)
        (self.plugin / "plugin.yaml").write_text(MANIFEST, encoding="utf-8")
        (self.plugin / "providers.yaml").write_text(PROVIDERS, encoding="utf-8")
        (self.plugin / "README.md").write_text("# Sample\n", encoding="utf-8")
        (self.plugin / "views").mkdir()
        (self.plugin / "views" / "report.sml").write_text(
            '<screen name="report" version="3"><text>OK</text></screen>',
            encoding="utf-8",
        )

    def test_valid_declarative_plugin(self):
        self.assertEqual([], validator.validate_repo(self.root))

    def test_disabled_by_default(self):
        path = self.plugin / "plugin.yaml"
        path.write_text(MANIFEST.replace("enabled: false", "enabled: true"), encoding="utf-8")
        self.assertIn("enabled: false", "\n".join(validator.validate_repo(self.root)))

    def test_matching_id(self):
        path = self.plugin / "plugin.yaml"
        path.write_text(MANIFEST.replace("id: sample", "id: other"), encoding="utf-8")
        self.assertIn("id must match", "\n".join(validator.validate_repo(self.root)))

    def test_duplicate_yaml_keys(self):
        path = self.plugin / "plugin.yaml"
        path.write_text(MANIFEST + "enabled: true\n", encoding="utf-8")
        self.assertIn("duplicate", "\n".join(validator.validate_repo(self.root)))

    def test_missing_provider(self):
        (self.plugin / "providers.yaml").unlink()
        self.assertIn("require providers.yaml", "\n".join(validator.validate_repo(self.root)))

    def test_invalid_sml(self):
        (self.plugin / "views" / "report.sml").write_text(
            '<screen name="report"><text>broken', encoding="utf-8"
        )
        self.assertIn("invalid SML XML", "\n".join(validator.validate_repo(self.root)))

    def test_reject_opaque_binary(self):
        (self.plugin / "payload.exe").write_bytes(b"MZ" + b"0" * 20)
        self.assertIn("binary, archive or secret", "\n".join(validator.validate_repo(self.root)))

    def test_reject_unsafe_url(self):
        path = self.plugin / "providers.yaml"
        path.write_text(PROVIDERS.replace(
            "https://api.example.com/v1/status", "http://localhost:8000/status"
        ), encoding="utf-8")
        self.assertIn("needs HTTPS", "\n".join(validator.validate_repo(self.root)))

    def test_reject_missing_readme(self):
        (self.plugin / "README.md").unlink()
        self.assertIn("missing plugin README.md", "\n".join(validator.validate_repo(self.root)))

    def test_reject_symlink(self):
        shortcut = self.plugin / "secret.txt"
        try:
            shortcut.symlink_to(self.plugin / "README.md")
        except (OSError, NotImplementedError):
            self.skipTest("Symlinks not available")
        self.assertIn("symlinks are not allowed", "\n".join(validator.validate_repo(self.root)))

    def test_valid_code_manifest(self):
        (self.plugin / "providers.yaml").unlink()
        source = MANIFEST.replace(
            "    provider: health", "    capability: code.invoke"
        ) + """runtime:
  kind: exec
  binary: sample
  timeout_ms: 4000
"""
        (self.plugin / "plugin.yaml").write_text(source, encoding="utf-8")
        self.assertEqual([], validator.validate_repo(self.root))


if __name__ == "__main__":
    unittest.main()
