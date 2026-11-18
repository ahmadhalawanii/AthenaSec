"""External attacker corroboration must use independent network telemetry."""

from app.schemas import SecurityAlertInput
from app.tools.wazuh_indexer import (
    WazuhEvidenceProvider,
    build_wazuh_query,
)


def make_alert():
    return SecurityAlertInput(
        alert_id="wazuh:trigger-001",
        source="wazuh",
        event_text="Repeated SSH authentication failures",
        metadata={
            "source_ip": "198.51.100.25",
            "agent_id": "007",
            "timestamp": "2026-11-17T18:30:00Z",
        },
    )


def make_hit(
    *,
    hit_id="independent-network-002",
    source_ip="198.51.100.25",
    groups=None,
):
    return {
        "_id": hit_id,
        "_index": "wazuh-alerts-test",
        "_source": {
            "timestamp": "2026-11-17T18:29:00Z",
            "rule": {
                "id": "NETWORK-001",
                "level": 8,
                "groups": groups if groups is not None else ["firewall"],
            },
            "agent": {
                "id": "007",
                "name": "monitored-target",
                "ip": "192.168.1.20",
            },
            "data": {"srcip": source_ip},
        },
    }


def gather(hit):
    class FakeClient:
        def search_alerts(self, query):
            return [hit]

    return WazuhEvidenceProvider(FakeClient()).gather(
        make_alert(),
        ["source_network_context"],
    )


def test_external_source_network_query_is_ip_scoped():
    query = build_wazuh_query(
        make_alert(), "source_network_context"
    )
    assert query is not None
    assert {"term": {"data.srcip": "198.51.100.25"}} in (
        query["query"]["bool"]["must"]
    )


def test_independent_network_event_can_corrob_external_ip():
    observations = gather(make_hit())
    assert len(observations) == 1
    assert observations[0].source == "wazuh"
    assert observations[0].evidence_type == "source_network_context"
    assert "independent-network-002" in observations[0].content


def test_other_source_ip_cannot_corrob_attacker():
    assert gather(make_hit(source_ip="198.51.100.99")) == []


def test_authentication_event_is_not_independent_network_context():
    assert gather(make_hit(groups=["authentication_failed"])) == []


def test_triggering_alert_is_not_independent_network_context():
    assert gather(make_hit(hit_id="trigger-001")) == []
