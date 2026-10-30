"""Fault-oriented tests; no live system commands, connections or secrets."""
from pathlib import Path
from types import SimpleNamespace
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "service-panel"))
import services as s


def response(text, code=0):
    return SimpleNamespace(stdout=text, returncode=code)


class StatusTests(unittest.TestCase):
    def test_missing_unit_is_unknown_even_if_inactive(self):
        with patch.object(s, "_command", side_effect=[response("inactive", 3), response("LoadState=not-found")]):
            self.assertEqual(s.check(s.SERVICES[0]).state, "unknown")

    def test_bus_failure_is_not_stopped(self):
        with patch.object(s, "_command", return_value=response("", 1)):
            self.assertEqual(s.check(s.SERVICES[0]).state, "unknown")

    def test_failed_unit_is_unhealthy(self):
        with patch.object(s, "_command", side_effect=[response("failed", 3), response("LoadState=loaded")]):
            self.assertEqual(s.check(s.SERVICES[0]).state, "unhealthy")

    def test_activating_and_inactive(self):
        for raw, expected in (("activating", "starting"), ("inactive", "stopped")):
            with self.subTest(raw=raw), patch.object(s, "_command", side_effect=[response(raw, 3), response("LoadState=loaded")]):
                result = s.check(s.SERVICES[0])
                self.assertEqual(result.state, expected)
                self.assertIsNone(result.uptime)

    def test_real_monotonic_uptime(self):
        props = "LoadState=loaded\nActiveState=active\nActiveEnterTimestampMonotonic=100000000"
        with patch.object(s, "_command", side_effect=[response("active"), response(props)]), patch.object(s.time, "monotonic", return_value=240):
            self.assertEqual(s.check(s.SERVICES[0]).uptime, 140)

    def test_invalid_timestamps_never_invent_uptime(self):
        for stamp in ("0", "-1", "bad", "999999999999999999"):
            props = f"LoadState=loaded\nActiveState=active\nActiveEnterTimestampMonotonic={stamp}"
            with self.subTest(stamp=stamp), patch.object(s, "_command", side_effect=[response("active"), response(props)]):
                self.assertIsNone(s.check(s.SERVICES[0]).uptime)

    def test_state_race_hides_uptime(self):
        with patch.object(s, "_command", side_effect=[response("active"), response("LoadState=loaded\nActiveState=inactive\nActiveEnterTimestampMonotonic=1")]):
            self.assertIsNone(s.check(s.SERVICES[0]).uptime)

    def test_timeout_is_handled_and_commands_are_read_only(self):
        with patch.object(s.subprocess, "run", side_effect=subprocess.TimeoutExpired("systemctl", 2)) as run:
            self.assertEqual(s.check(s.SERVICES[0]).state, "unknown")
            args, kwargs = run.call_args
            self.assertEqual(args[0], ["/usr/bin/systemctl", "is-active", "wazuh-manager"])
            self.assertFalse(kwargs["shell"])
            self.assertEqual(kwargs["timeout"], 2)

    def test_unapproved_service_is_rejected_before_execution(self):
        with patch.object(s.subprocess, "run") as run:
            with self.assertRaises(ValueError):
                s.check(s.Service("bad", "bad", "", "", "docker; whoami"))
            run.assert_not_called()

    def test_https_error_responses_do_not_look_running(self):
        for service in s.SERVICES[3:5]:
            for status in (301, 302, 401, 403, 404, 500, 502, 503):
                with self.subTest(service=service.key, status=status):
                    result = s._http_result(service, status, "text/plain", b"")
                    self.assertEqual(result.state, "unhealthy" if status >= 500 else "unknown")

    def test_login_pages_and_large_bodies_are_not_health(self):
        for service in s.SERVICES[3:5]:
            for content_type, body in (("text/html", b"<html>Login</html>"), ("application/json", b"x" * 16385)):
                self.assertEqual(s._http_result(service, 200, content_type, body).state, "unknown")

    def test_expected_misp_heartbeat_and_negative_json(self):
        misp = s.SERVICES[3]
        for body in (b"", b"OK", b'{"status":"ok"}'):
            self.assertEqual(s._http_result(misp, 200, "application/json", body).state, "running")
        for body in (b'{"status":"failed"}', b"false", b'{"success":false}'):
            self.assertEqual(s._http_result(misp, 200, "application/json", body).state, "unknown")

    def test_cortex_requires_application_identity(self):
        cortex = s.SERVICES[4]
        self.assertEqual(s._http_result(cortex, 200, "application/json", b'{"versions":{"Cortex":"3.1"}}').state, "running")
        for body in (b"{}", b'{"versions":{"Proxy":"1"}}', b"[]", b"OK"):
            self.assertEqual(s._http_result(cortex, 200, "application/json", body).state, "unknown")

    def test_refused_endpoint_is_unknown_and_connection_closes(self):
        with patch.object(s.http.client, "HTTPSConnection") as constructor:
            conn = constructor.return_value
            conn.request.side_effect = ConnectionRefusedError
            result = s.check(s.SERVICES[3])
            self.assertEqual(result.state, "unknown")
            self.assertEqual(constructor.call_args.args, ("127.0.0.1", 9445))
            conn.close.assert_called_once()

    def test_collection_contains_six_results_even_if_one_probe_fails(self):
        with patch.object(s, "_systemd", side_effect=RuntimeError("do not expose")), patch.object(s, "_https", return_value=s.Result("misp", "unknown", "Unavailable")):
            results = s.collect()
            self.assertEqual(len(results), 6)
            self.assertNotIn("do not expose", repr(results))


if __name__ == "__main__":
    unittest.main()
