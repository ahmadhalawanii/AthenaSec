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


def test_endpoint_query_uses_source_ip():
    query = build_wazuh_query(
        make_alert(),
        "source_endpoint_context",
    )

    assert query is not None

    must = query["query"]["bool"]["must"]

    assert {
        "term": {
            "data.srcip": "192.168.1.45"
        }
    } in must


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