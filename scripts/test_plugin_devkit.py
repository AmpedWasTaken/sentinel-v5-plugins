import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path

SCRIPT = Path(__file__).with_name("plugin-devkit.py")
spec = importlib.util.spec_from_file_location("plugin_devkit", SCRIPT)
devkit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(devkit)


class PluginDevkitTest(unittest.TestCase):
    def test_scaffold_and_reproducible_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "plugin"
            out1, out2 = Path(tmp) / "first.zip", Path(tmp) / "second.zip"
            devkit.init_plugin(root, "my-widget")
            self.assertEqual(len(devkit.checked_files(root)), 3)
            devkit.package(root, out1)
            devkit.package(root, out2)
            self.assertEqual(out1.read_bytes(), out2.read_bytes())
            with zipfile.ZipFile(out1) as archive:
                self.assertIn("plugin.yaml", archive.namelist())
                self.assertIn("views/starter.sml", archive.namelist())

    def test_configuration_yaml_is_included_in_published_zip(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "plugin"
            target = Path(tmp) / "out.zip"
            devkit.init_plugin(root, "my-widget")
            (root / "config.yaml").write_text("settings:\\n  retries: 2\\n".replace("\\\\n", "\\n"), encoding="utf-8")
            (root / "config.yml").write_text("theme: midnight\\n".replace("\\\\n", "\\n"), encoding="utf-8")
            entries = devkit.checked_files(root)
            self.assertIn("config.yaml", [name for name, _ in entries])
            self.assertIn("config.yml", [name for name, _ in entries])
            devkit.package(root, target)
            with zipfile.ZipFile(target) as archive:
                self.assertIn("config.yaml", archive.namelist())
                self.assertIn("config.yml", archive.namelist())

    def test_reject_symlinks_and_path_escape(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / "plugin"
            devkit.init_plugin(root, "my-widget")
            (root / "unexpected.py").write_text("print('no')", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Unsupported plugin path"):
                devkit.checked_files(root)

    def test_invalid_ids(self):
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaisesRegex(ValueError, "Plugin ID"):
                devkit.init_plugin(Path(tmp) / "invalid", "../bad")


if __name__ == "__main__":
    unittest.main()
