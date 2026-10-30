"""Controller tests with GTK stand-ins; these are not GUI rendering tests."""
import importlib.util
from pathlib import Path
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

ROOT = Path(__file__).resolve().parents[1] / "service-panel"
sys.path.insert(0, str(ROOT))
gi = ModuleType("gi")
gi.require_version = lambda *_: None
repo = ModuleType("gi.repository")
repo.Gtk = SimpleNamespace(Box=object, ApplicationWindow=object, Application=object)
repo.Gdk = MagicMock()
repo.Gio = MagicMock()
repo.GLib = SimpleNamespace(SOURCE_REMOVE=False, SOURCE_CONTINUE=True, source_remove=MagicMock())
repo.Pango = MagicMock()
with patch.dict(sys.modules, {"gi": gi, "gi.repository": repo}):
    spec = importlib.util.spec_from_file_location("panel_controller_under_test", ROOT / "app.py")
    app = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(app)


class LoginLifecycleTests(unittest.TestCase):
    def test_failed_login_clears_password_and_never_opens_panel(self):
        login = MagicMock()
        login.email.get_text.return_value = "admin@athenasec.com"
        login.password.get_text.return_value = "wrong"
        app.LoginWindow.submit(login)
        login.password.set_text.assert_called_with("")
        login.get_application.assert_not_called()
        login.error.set_visible.assert_called_with(True)

    def test_successful_login_opens_panel_once_and_clears_password(self):
        login = MagicMock()
        login.email.get_text.return_value = "admin@athenasec.com"
        login.password.get_text.return_value = "admin123"
        app.LoginWindow.submit(login)
        login.get_application.return_value.open_panel.assert_called_once_with(login)
        login.password.set_text.assert_called_once_with("")

    def test_success_creates_panel_before_destroying_login(self):
        application, login = MagicMock(), MagicMock()
        with patch.object(app, "Panel") as panel:
            app.Application.open_panel(application, login)
            panel.assert_called_once_with(application)
            panel.return_value.present.assert_called_once()
        login.destroy.assert_called_once()

    def test_sign_out_closes_old_panel_and_shows_fresh_login(self):
        application, panel = MagicMock(), MagicMock()
        with patch.object(app, "LoginWindow") as login:
            app.Application.sign_out(application, panel)
            login.assert_called_once_with(application)
            login.return_value.present.assert_called_once()
        panel.close_panel.assert_called_once()
        panel.destroy.assert_called_once()

    def test_late_background_results_do_not_touch_closed_widgets(self):
        panel = MagicMock(closed=True)
        self.assertFalse(app.Panel.apply_results(panel, ()))
        self.assertFalse(app.Panel.apply_usage(panel, object()))
        panel.usage.update.assert_not_called()
        panel.cards.__getitem__.assert_not_called()

    def test_close_stops_both_timers_and_closes_pages_once(self):
        page = MagicMock()
        panel = MagicMock(closed=False, timer=10, metrics_timer=20, pages={"misp": page})
        app.GLib.source_remove.reset_mock()
        app.Panel.close_panel(panel)
        self.assertTrue(panel.closed)
        self.assertEqual(app.GLib.source_remove.call_count, 2)
        page.close_page.assert_called_once()
        self.assertEqual(panel.pages, {})
        app.Panel.close_panel(panel)
        page.close_page.assert_called_once()


if __name__ == "__main__":
    unittest.main()
