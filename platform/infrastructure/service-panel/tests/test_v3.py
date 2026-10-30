"""v3 behavioral tests; no GTK, Docker permissions, or live services needed."""
from pathlib import Path
import sys
import unittest
from unittest.mock import patch, mock_open, MagicMock

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "service-panel"))
import auth
import metrics
import services as s

LOGIN = b'''<html><title>MISP</title><form action="/users/login" id="UserLoginForm">
<input type="text" id="UserEmail" name="data[User][email]">
<input type="password" id="UserPassword" name="data[User][password]">
</form></html>'''


class AuthTests(unittest.TestCase):
    def test_mock_admin_matches(self):
        self.assertTrue(auth.authenticate("admin@athenasec.com", "admin123"))

    def test_email_normalizes_but_password_does_not(self):
        self.assertTrue(auth.authenticate(" Admin@AthenaSec.com ", "admin123"))
        for password in ("Admin123", "admin123 ", " admin123", ""):
            self.assertFalse(auth.authenticate(auth.ADMIN_EMAIL, password))

    def test_wrong_accounts_unicode_and_non_strings_fail(self):
        for email, password in (("user@athenasec.com", "admin123"), ("", ""), ("管理员", "密码"), (None, None), (1, 1)):
            self.assertFalse(auth.authenticate(email, password))


class MetricTests(unittest.TestCase):
    def test_guest_is_not_counted_twice(self):
        self.assertEqual(metrics.parse_cpu("cpu 10 20 30 40 5 6 7 8 500 400\n"), (10, 20, 30, 40, 5, 6, 7, 8))

    def test_percentage_uses_delta_and_iowait_is_idle(self):
        old = (100, 0, 50, 800, 20, 0, 0, 0)
        new = (120, 0, 60, 850, 40, 0, 0, 0)
        self.assertEqual(metrics.cpu_percent(old, new), 30.0)

    def test_first_sample_reset_and_zero_delta_have_no_fake_value(self):
        counters = (10,) * 8
        for old, new in ((None, counters), (counters, counters), (counters, (9,) * 8)):
            self.assertIsNone(metrics.cpu_percent(old, new))

    def test_invalid_cpu_rejected(self):
        for data in ("", "cpu0 1 2 3 4", "cpu 1 2", "cpu -1 2 3 4", "cpu x 2 3 4"):
            with self.assertRaises((ValueError, IndexError)):
                metrics.parse_cpu(data)

    def test_ram_available_includes_reclaimable_memory(self):
        used, total, percent = metrics.parse_memory("MemTotal: 1000 kB\nMemAvailable: 600 kB\nMemFree: 100 kB\n")
        self.assertEqual((used, total, percent), (409600, 1024000, 40.0))

    def test_invalid_ram_is_not_zero_percent(self):
        for data in ("MemTotal: 0 kB\nMemAvailable: 0 kB", "MemTotal: 1 kB", "MemTotal: 1 kB\nMemAvailable: 2 kB", "MemTotal: 1 MB\nMemAvailable: 1 kB"):
            with self.assertRaises((ValueError, KeyError)):
                metrics.parse_memory(data)

    def test_proc_failure_does_not_crash(self):
        sampler = metrics.Sampler()
        with patch("builtins.open", side_effect=PermissionError):
            usage = sampler.sample()
        self.assertIsNone(usage.cpu_percent)
        self.assertIsNone(usage.memory_percent)
        self.assertEqual(usage.cpu_detail, "Unavailable")

    def test_cpu_failure_does_not_hide_ram(self):
        memory_file = mock_open(read_data="MemTotal: 1000 kB\nMemAvailable: 600 kB\n").return_value
        with patch("builtins.open", side_effect=[PermissionError, memory_file]):
            usage = metrics.Sampler().sample()
        self.assertIsNone(usage.cpu_percent)
        self.assertEqual(usage.memory_percent, 40.0)


class MispTests(unittest.TestCase):
    def test_redirect_can_fall_back_to_identified_login(self):
        replies = [(302, "text/html", b""), (200, "text/html", LOGIN)]
        with patch.object(s, "_request", side_effect=replies) as request:
            result = s.check(s.SERVICES[3])
        self.assertEqual(result.state, "running")
        self.assertEqual(result.display_status, "Available")
        self.assertIn("302", result.detail)
        self.assertIn("web availability only", result.detail)
        self.assertEqual(request.call_args.args[1], "/users/login")

    def test_auth_or_missing_heartbeat_can_use_login(self):
        for status in (401, 403, 404):
            with patch.object(s, "_request", side_effect=[(status, "", b""), (200, "text/html", LOGIN)]):
                self.assertEqual(s.check(s.SERVICES[3]).state, "running")

    def test_unknown_heartbeat_body_can_use_login(self):
        with patch.object(s, "_request", side_effect=[(200, "application/json", b'{"message":"alive"}'), (200, "text/html", LOGIN)]):
            self.assertEqual(s.check(s.SERVICES[3]).display_status, "Available")

    def test_generic_login_proxy_and_incomplete_form_are_not_misp(self):
        for body in (b"<html>Login</html>", b"<html>MISP unavailable</html>", LOGIN.replace(b'UserPassword', b'OtherPassword'), LOGIN.replace(b'</form>', b''), LOGIN.replace(b'MISP', b'Other app')):
            self.assertEqual(s._misp_login_result((200, "text/html", body)).state, "unknown")

    def test_http_error_or_redirect_is_not_followed(self):
        for status in (301, 302, 401, 403, 404, 502):
            self.assertEqual(s._misp_login_result((status, "text/html", LOGIN)).state, "unhealthy" if status == 502 else "unknown")

    def test_oversize_login_is_not_available(self):
        self.assertEqual(s._misp_login_result((200, "text/html", LOGIN + b" " * 131072)).state, "unknown")

    def test_heartbeat_server_failure_is_not_masked(self):
        with patch.object(s, "_request", return_value=(503, "", b"")) as request:
            self.assertEqual(s.check(s.SERVICES[3]).state, "unhealthy")
            request.assert_called_once()

    def test_explicit_negative_health_is_not_masked(self):
        for body in (b'{"status":"failed"}', b'{"success":false}', b'false'):
            with patch.object(s, "_request", return_value=(200, "application/json", body)) as request:
                self.assertEqual(s.check(s.SERVICES[3]).state, "unhealthy")
                request.assert_called_once()

    def test_successful_heartbeat_skips_login(self):
        with patch.object(s, "_request", return_value=(200, "application/json", b'{"status":"ok"}')) as request:
            self.assertEqual(s.check(s.SERVICES[3]).state, "running")
            request.assert_called_once()

    def test_misp_uses_fixed_loopback_and_public_host_without_credentials(self):
        with patch.object(s.http.client, "HTTPSConnection") as constructor:
            conn = constructor.return_value
            conn.getresponse.return_value.status = 200
            conn.getresponse.return_value.getheader.return_value = "text/html"
            conn.getresponse.return_value.read1.side_effect = [LOGIN, b""]
            s._request(s.SERVICES[3], "/users/login", 131072)
            self.assertEqual(constructor.call_args.args, ("127.0.0.1", 9445))
            headers = conn.request.call_args.kwargs["headers"]
            self.assertEqual(headers["Host"], "192.168.1.164:9445")
            self.assertNotIn("Authorization", headers)
            self.assertNotIn("Cookie", headers)
            conn.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
