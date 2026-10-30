"""Aggregation correctness and embedded-page navigation boundaries."""
import itertools
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "service-panel"))
from services import Result, summarize
from site_policy import SITES, allowed_uri


def results(states, uptimes=(None, None, None)):
    return [Result(key, state, "", uptime) for key, state, uptime in zip(("manager", "indexer", "dashboard"), states, uptimes)]


class OverviewTests(unittest.TestCase):
    def test_running_requires_all_three_checks(self):
        for states in itertools.product(("running", "stopped", "starting", "unhealthy", "unknown"), repeat=3):
            with self.subTest(states=states):
                actual = summarize(results(states))[0]
                self.assertEqual(actual.state == "running", all(state == "running" for state in states))
                if "unknown" in states:
                    self.assertEqual(actual.state, "unknown")
                elif 0 < states.count("running") < 3:
                    self.assertEqual(actual.state, "partial")

    def test_partial_card_identifies_failed_component(self):
        card = summarize(results(("running", "stopped", "running")))[0]
        self.assertEqual(card.display_status, "Partially running — 2/3")
        self.assertIn("Indexer: Stopped", card.detail)
        self.assertIsNone(card.uptime)

    def test_all_stopped_and_zero_running_failure_are_distinct(self):
        self.assertEqual(summarize(results(("stopped",) * 3))[0].state, "stopped")
        self.assertEqual(summarize(results(("stopped", "unhealthy", "stopped")))[0].state, "unhealthy")

    def test_missing_result_is_unknown(self):
        self.assertEqual(summarize([Result("manager", "running", "")])[0].state, "unknown")

    def test_group_uptime_is_time_since_last_component_became_active(self):
        self.assertEqual(summarize(results(("running",) * 3, (600, 300, 400)))[0].uptime, 300)

    def test_no_group_uptime_when_a_timestamp_is_missing(self):
        self.assertIsNone(summarize(results(("running",) * 3, (600, None, 400)))[0].uptime)

    def test_four_logical_services_preserve_independent_results(self):
        rows = results(("running",) * 3) + [Result("misp", "unhealthy", "HTTP 503"), Result("cortex", "running", "Available"), Result("docker", "running", "Active")]
        cards = summarize(rows)
        self.assertEqual([r.key for r in cards], ["wazuh", "misp", "cortex", "docker"])
        self.assertEqual(sum(r.state == "running" for r in cards), 3)
        self.assertEqual(cards[1].detail, "HTTP 503")


class NavigationTests(unittest.TestCase):
    def test_normal_login_paths_and_spa_routes(self):
        for key, (_, origin) in SITES.items():
            for suffix in ("", "/", "/users/login", "/app/dashboards#/view/123", "/login?next=%2Fapp"):
                self.assertTrue(allowed_uri(key, origin + suffix))
        self.assertTrue(allowed_uri("wazuh", "https://192.168.1.164:443/app"))

    def test_external_schemes_hosts_and_ports_are_blocked(self):
        cases = (
            "http://192.168.1.164/", "https://192.168.1.164:0/", "https://192.168.1.164:9444/",
            "https://192.168.1.164.evil.example/", "https://192.168.1.164@evil.example/",
            "https://user:password@192.168.1.164/", "https://127.0.0.1/",
            "file:///etc/passwd", "javascript:alert(1)", "data:text/html,hi",
            "mailto:test@example.com", "//192.168.1.164/", "about:blank",
            " https://192.168.1.164/", "https://192.168.1.164/\n",
            "https://192.168.1.164\\@evil.example/", "https://192.168.1.164:65536/",
        )
        for uri in cases:
            with self.subTest(uri=uri):
                self.assertFalse(allowed_uri("wazuh", uri))

    def test_services_cannot_navigate_into_each_others_origins(self):
        for source in SITES:
            for target, (_, origin) in SITES.items():
                self.assertEqual(allowed_uri(source, origin), source == target)

    def test_invalid_inputs_fail_closed(self):
        for value in (None, "", "https://[", "https://192.168.1.164:abc/"):
            self.assertFalse(allowed_uri("wazuh", value))
        self.assertFalse(allowed_uri("unknown", "https://192.168.1.164"))


if __name__ == "__main__":
    unittest.main()
