"""Exercise installation/rollback in a temp directory; mock all policy loads."""
from contextlib import ExitStack, redirect_stdout
import importlib.util
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location("panel_installer", Path(__file__).resolve().parents[1] / "install-panel.py")
installer = importlib.util.module_from_spec(spec)
spec.loader.exec_module(installer)


@unittest.skipUnless(os.geteuid() == 0, "Temp installer tests require root ownership; no system paths are used")
class InstallerTests(unittest.TestCase):
    def setUp(self):
        self.context = ExitStack()
        self.addCleanup(self.context.close)
        root = Path(self.context.enter_context(tempfile.TemporaryDirectory()))
        self.app = root / "opt/athenasec/service-panel"
        self.launcher = root / "bin/athenasec-service-panel"
        self.desktop = root / "applications/athenasec-service-panel.desktop"
        self.profile = root / "apparmor/athenasec-service-panel"
        enabled = root / "enabled"
        enabled.write_text("Y")
        parser = root / "apparmor_parser"
        parser.touch()
        targets = {"app": self.app, "launcher": self.launcher, "desktop": self.desktop, "profile": self.profile}
        for key, value in dict(APP=self.app, LAUNCHER=self.launcher, DESKTOP=self.desktop, PROFILE=self.profile, TARGETS=targets, APPARMOR_ENABLED=enabled, PARSER=str(parser)).items():
            self.context.enter_context(patch.object(installer, key, value))
        self.parser = self.context.enter_context(patch.object(installer, "run_parser"))
        self.context.enter_context(redirect_stdout(io.StringIO()))

    def backup(self):
        return next(self.app.parent.glob("service-panel-v3-backup.*"))

    def test_fresh_install_and_rollback_are_scoped(self):
        self.app.parent.mkdir(parents=True)
        sentinel = self.app.parent / "misp-do-not-touch"
        sentinel.write_text("preserve")
        installer.install()
        self.assertTrue((self.app / "auth.py").is_file())
        self.assertEqual(self.launcher.stat().st_mode & 0o777, 0o755)
        self.assertEqual((self.app / "metrics.py").stat().st_mode & 0o777, 0o644)
        installer.restore(self.backup())
        self.assertFalse(self.app.exists())
        self.assertFalse(self.launcher.exists())
        self.assertFalse(self.profile.exists())
        self.assertEqual(sentinel.read_text(), "preserve")

    def test_upgrade_restores_previous_files(self):
        self.app.mkdir(parents=True)
        (self.app / "app.py").write_text("# old app\n")
        self.launcher.parent.mkdir(parents=True)
        self.launcher.write_text("old launcher\n")
        installer.install()
        installer.restore(self.backup())
        self.assertEqual((self.app / "app.py").read_text(), "# old app\n")
        self.assertEqual(self.launcher.read_text(), "old launcher\n")
        self.assertFalse((self.app / "auth.py").exists())

    def test_custom_policy_stops_before_backup_or_mutation(self):
        self.profile.parent.mkdir(parents=True)
        self.profile.write_text("custom")
        with self.assertRaises(RuntimeError):
            installer.install()
        self.assertEqual(self.profile.read_text(), "custom")
        self.assertFalse(self.app.exists())

    def test_failed_policy_load_restores_files(self):
        self.app.mkdir(parents=True)
        (self.app / "app.py").write_text("# old app\n")
        self.parser.side_effect = [None, subprocess.CalledProcessError(1, "mock-policy-load"), None]
        with self.assertRaises(subprocess.CalledProcessError):
            installer.install()
        self.assertEqual((self.app / "app.py").read_text(), "# old app\n")
        self.assertFalse(self.profile.exists())

    def test_failed_kernel_removal_still_restores_files_and_reports_incomplete(self):
        installer.install()
        self.parser.side_effect = subprocess.CalledProcessError(1, "mock-policy-remove")
        with self.assertRaisesRegex(RuntimeError, "AppArmor rollback failed"):
            installer.restore(self.backup())
        self.assertFalse(self.app.exists())
        self.assertFalse(self.launcher.exists())


if __name__ == "__main__":
    unittest.main()
