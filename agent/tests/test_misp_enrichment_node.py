from app.graph.nodes.misp_enrichment import (
    make_misp_enrichment_node,
)
from app.schemas import (
    MISPEnrichment,
    MISPMatch,
    SecurityAlertInput,
)


class FakeMISPClient:
    def __init__(self):
        self.calls = []

    def enrich(
        self,
        indicators,
    ) -> MISPEnrichment:
        self.calls.append(
            indicators
        )

        return MISPEnrichment(
            queried_indicators=[
                value
                for _, value in indicators
            ],
            matches=[
                MISPMatch(
                    indicator_type="ip-src",
                    indicator_value="203.0.113.10",
                    event_id="42",
                    event_info=(
                        "Known brute-force "
                        "infrastructure"
                    ),
                    threat_level="high",
                )
            ],
        )


def test_misp_enrichment_node_queries_alert_indicators():
    client = FakeMISPClient()

    node = make_misp_enrichment_node(
        client
    )

    alert = SecurityAlertInput(
        alert_id="ALT-MISP-NODE-001",
        source="wazuh",
        event_text=(
            "Suspicious SSH authentication activity."
        ),
        metadata={
            "source_ip": "203.0.113.10",
            "destination_ip": "10.0.0.25",
        },
    )

    result = node(
        {
            "alert": alert,
        }
    )

    assert client.calls == [
        [
            (
                "ip-src",
                "203.0.113.10",
            ),
            (
                "ip-dst",
                "10.0.0.25",
            ),
        ]
    ]

    assert (
        result["misp_enrichment"]
        .queried_indicators
        == [
            "203.0.113.10",
            "10.0.0.25",
        ]
    )

    assert len(
        result["misp_enrichment"].matches
    ) == 1

    assert (
        result["misp_enrichment"]
        .matches[0]
        .threat_level
        == "high"
    )

class FailingMISPClient:
    def enrich(
        self,
        indicators,
    ):
        raise RuntimeError(
            "MISP unavailable"
        )


def test_misp_enrichment_node_records_failure_without_crashing():
    client = FailingMISPClient()

    node = make_misp_enrichment_node(
        client
    )

    alert = SecurityAlertInput(
        alert_id="ALT-MISP-NODE-002",
        source="wazuh",
        event_text=(
            "Suspicious SSH authentication activity."
        ),
        metadata={
            "source_ip": "203.0.113.10",
        },
    )

    result = node(
        {
            "alert": alert,
        }
    )

    assert (
        result["misp_error"]
        == "MISP unavailable"
    )

    assert (
        result["misp_enrichment"]
        .queried_indicators
        == [
            "203.0.113.10",
        ]
    )

    assert (
        result["misp_enrichment"].matches
        == []
    )