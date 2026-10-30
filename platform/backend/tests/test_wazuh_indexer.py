from app.schemas import SecurityAlertInput
from app.tools.wazuh_indexer import (
    WazuhEvidenceProvider,
    WazuhIndexerClient,
    build_wazuh_query,
)


def make_alert():
    return SecurityAlertInput(
        alert_id="WAZUH-001",
        source="wazuh",
        event_text=(
            "Multiple SSH authentication failures."
        ),
        metadata={
            "source_ip": "192.168.1.45",
            "target_user": "root",
            "agent_id": "007",
            "timestamp": "2026-10-05T18:31:39.237+0000",
        },
    )


def test_authentication_query_uses_alert_scope():
    query = build_wazuh_query(
        make_alert(),
        "authentication_history",
    )

    assert query is not None

    must = query["query"]["bool"]["must"]

    assert {
        "term": {
            "data.srcip": "192.168.1.45"
        }
    } in must

    assert {
        "terms": {
            "rule.groups": [
                "authentication_failed",
                "authentication_success",
            ]
        }
    } in must


def test_endpoint_query_uses_source_agent_ip_not_victim_agent():
    query = build_wazuh_query(make_alert(), "source_endpoint_context")
    assert query is not None
    must = query["query"]["bool"]["must"]
    assert {"term": {"agent.ip": "192.168.1.45"}} in must
    assert {"exists": {"field": "agent.name"}} in must
    assert {"term": {"agent.id": "007"}} not in must
    assert any(
        {"term": {"agent.id": "000"}} in entry.get("bool", {}).get("must_not", [])
        for entry in must
    )

def test_related_events_query_requires_high_level():
    query = build_wazuh_query(
        make_alert(),
        "related_security_events",
    )

    assert query is not None

    must = query["query"]["bool"]["must"]

    assert {
        "range": {
            "rule.level": {
                "gte": 7
            }
        }
    } in must


def test_provider_returns_grounded_wazuh_evidence():
    class FakeClient:
        def search_alerts(
            self,
            query,
        ):
            return [
                {
                    "_id": "alert-123",
                    "_index": "wazuh-alerts-test",
                    "_source": {
                        "timestamp": (
                            "2026-08-14T18:30:00Z"
                        ),
                        "rule": {
                            "id": "5710",
                            "level": 5,
                            "description": (
                                "sshd: Attempt to login "
                                "using a non-existent user"
                            ),
                            "groups": [
                                "authentication_failed",
                                "invalid_login",
                            ],
                        },
                        "agent": {
                            "id": "007",
                            "name": "workstation-07",
                            "ip": "192.168.1.20",
                        },
                        "data": {
                            "srcip": "192.168.1.45",
                            "dstuser": "root",
                        },
                        "full_log": (
                            "Invalid SSH login attempt"
                        ),
                    },
                }
            ]

    provider = WazuhEvidenceProvider(
        FakeClient()
    )

    evidence = provider.gather(
        make_alert(),
        [
            "authentication_history",
        ],
    )

    assert len(evidence) == 1

    assert evidence[0].source == "wazuh"

    assert "5710" in evidence[0].content

    assert (
        "workstation-07"
        in evidence[0].content
    )

    assert (
        "192.168.1.45"
        in evidence[0].content
    )


def test_indexer_client_calls_wazuh_search(
    monkeypatch,
):
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "hits": {
                    "hits": [
                        {
                            "_id": "1",
                            "_source": {},
                        }
                    ]
                }
            }

    def fake_post(
        url,
        *,
        auth,
        json,
        verify,
        timeout,
    ):
        captured["url"] = url
        captured["auth"] = auth
        captured["json"] = json
        captured["verify"] = verify
        captured["timeout"] = timeout

        return FakeResponse()

    monkeypatch.setattr(
        "app.tools.wazuh_indexer.requests.post",
        fake_post,
    )

    client = WazuhIndexerClient(
        base_url=(
            "https://wazuh-indexer:9200"
        ),
        username="athenasec",
        password="secret",
        verify_ssl=False,
    )

    hits = client.search_alerts(
        {
            "query": {
                "match_all": {}
            }
        }
    )

    assert len(hits) == 1

    assert captured["url"] == (
        "https://wazuh-indexer:9200/"
        "wazuh-alerts*/_search"
    )

    assert captured["auth"] == (
        "athenasec",
        "secret",
    )

def test_indexer_client_checks_cluster_health(
    monkeypatch,
):
    captured = {}

    class FakeResponse:
        def raise_for_status(self):
            return None

        def json(self):
            return {
                "cluster_name": (
                    "wazuh-cluster"
                ),
                "status": "green",
            }

    def fake_get(
        url,
        *,
        auth,
        verify,
        timeout,
    ):
        captured["url"] = url
        captured["auth"] = auth
        captured["verify"] = verify
        captured["timeout"] = timeout

        return FakeResponse()

    monkeypatch.setattr(
        "app.tools.wazuh_indexer.requests.get",
        fake_get,
    )

    client = WazuhIndexerClient(
        base_url=(
            "https://wazuh-indexer:9200"
        ),
        username="athenasec",
        password="secret",
        verify_ssl=False,
    )

    health = client.health()

    assert health["status"] == "green"

    assert captured["url"] == (
        "https://wazuh-indexer:9200/"
        "_cluster/health"
    )

    assert captured["auth"] == (
        "athenasec",
        "secret",
    )

def test_authentication_evidence_has_30_minute_window():
    alert = make_alert()
    alert.metadata["timestamp"] = "2026-10-05T18:31:39.237+0000"

    query = build_wazuh_query(
        alert,
        "authentication_history",
    )

    assert query is not None
    must = query["query"]["bool"]["must"]

    bounds = [
        item["range"]["timestamp"]
        for item in must
        if "range" in item and "timestamp" in item["range"]
    ]

    assert bounds == [{
        "gte": "2026-10-05T18:01:39.237000+00:00",
        "lte": "2026-10-05T19:01:39.237000+00:00",
    }]


def test_missing_timestamp_fails_closed():
    alert = make_alert()
    alert.metadata.pop("timestamp", None)
    assert build_wazuh_query(
        alert,
        "authentication_history",
    ) is None


def test_untrusted_timestamp_fails_closed():
    alert = make_alert()
    alert.metadata["timestamp"] = "not-a-timestamp"

    assert build_wazuh_query(
        alert,
        "authentication_history",
    ) is None


def test_source_endpoint_requires_incident_source_ip():
    alert = make_alert()
    alert.metadata.pop("source_ip")
    assert build_wazuh_query(alert, "source_endpoint_context") is None

    # The Wazuh alert agent may be a victim or Manager and must NOT be
    # interpreted as the attacker's source endpoint.
    alert = make_alert()
    alert.metadata.pop("agent_id")
    assert build_wazuh_query(alert, "source_endpoint_context") is not None



def test_source_endpoint_provider_rejects_manager_and_victim_events():
    class FakeClient:
        def search_alerts(self, query):
            return [
                {"_id": "manager-sudo", "_source": {
                    "timestamp": "2026-10-05T18:31:39Z",
                    "agent": {"id": "000", "name": "manager", "ip": "192.168.1.45"},
                    "rule": {"id": "5405", "groups": ["sudo"]},
                }},
                {"_id": "victim-gpasswd", "_source": {
                    "timestamp": "2026-10-05T18:31:39Z",
                    "agent": {"id": "007", "name": "victim", "ip": "192.168.1.20"},
                    "rule": {"id": "5406", "groups": ["sudo"]},
                }},
            ]

    result = WazuhEvidenceProvider(FakeClient()).gather(
        make_alert(), ["source_endpoint_context"]
    )
    assert result == []


def test_source_endpoint_provider_rejects_authentication_only_events():
    class FakeClient:
        def search_alerts(self, query):
            return [{"_id": "auth-only", "_source": {
                "timestamp": "2026-10-05T18:31:39Z",
                "agent": {"id": "008", "name": "source-host", "ip": "192.168.1.45"},
                "rule": {"id": "5716", "groups": ["authentication_failed"]},
            }}]

    result = WazuhEvidenceProvider(FakeClient()).gather(
        make_alert(), ["source_endpoint_context"]
    )
    assert result == []


def test_source_endpoint_provider_accepts_identified_source_telemetry():
    class FakeClient:
        def search_alerts(self, query):
            return [{"_id": "telemetry-source", "_source": {
                "timestamp": "2026-10-05T18:31:39Z",
                "agent": {"id": "008", "name": "source-host", "ip": "192.168.1.45"},
                "rule": {"id": "550", "groups": ["syscheck"]},
            }}]

    result = WazuhEvidenceProvider(FakeClient()).gather(
        make_alert(), ["source_endpoint_context"]
    )
    assert len(result) == 1
    assert result[0].evidence_type == "source_endpoint_context"
    assert result[0].source == "wazuh"
    assert "telemetry-source" in result[0].content

# --- Final Indexer privilege-evidence regression coverage ---

def test_privilege_query_requires_agent_user_and_privilege_marker():
    alert = make_alert()
    query = build_wazuh_query(alert, "privilege_activity")
    assert query is not None
    must = query["query"]["bool"]["must"]
    assert {"term": {"agent.id": "007"}} in must
    assert {"term": {"data.srcip": "192.168.1.45"}} not in must
    assert any("timestamp" in item.get("range", {}) for item in must)
    bool_conditions = [item["bool"] for item in must if "bool" in item]
    assert any("should" in part and part.get("minimum_should_match") == 1 for part in bool_conditions)
    assert len(bool_conditions) >= 2


def test_privilege_query_missing_actor_or_agent_fails_closed():
    alert = make_alert()
    alert.metadata.pop("agent_id")
    assert build_wazuh_query(alert, "privilege_activity") is None
    alert = make_alert()
    alert.metadata.pop("target_user")
    assert build_wazuh_query(alert, "privilege_activity") is None


def test_privilege_provider_rejects_generic_and_other_user_events():
    class FakeClient:
        def search_alerts(self, query):
            return [
                {"_id": "generic", "_source": {
                    "agent": {"id": "007"}, "rule": {"groups": ["syslog"]},
                    "data": {"srcuser": "root"}}},
                {"_id": "wrong-agent", "_source": {
                    "agent": {"id": "009"}, "rule": {"groups": ["sudo"]},
                    "data": {"srcuser": "root"}}},
                {"_id": "wrong-user", "_source": {
                    "agent": {"id": "007"}, "rule": {"groups": ["sudo"]},
                    "data": {"srcuser": "other", "dstuser": "other"}}},
            ]
    assert WazuhEvidenceProvider(FakeClient()).gather(
        make_alert(), ["privilege_activity"]
    ) == []


def test_privilege_provider_accepts_same_agent_actor_sudo_record():
    class FakeClient:
        def search_alerts(self, query):
            return [{"_id": "actual-sudo", "_source": {
                "agent": {"id": "007"},
                "rule": {"id": "5405", "groups": ["syslog", "sudo"]},
                "data": {"srcuser": "root"}}}]
    observations = WazuhEvidenceProvider(FakeClient()).gather(
        make_alert(), ["privilege_activity"]
    )
    assert len(observations) == 1
    assert observations[0].evidence_type == "privilege_activity"
    assert "actual-sudo" in observations[0].content
