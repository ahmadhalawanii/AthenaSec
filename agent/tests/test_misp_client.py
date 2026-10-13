from app.schemas import (
    MISPEnrichment,
    MISPMatch,
)
from app.services.misp_client import (
    MISPClient,
)


class FakeMISPClient:
    def enrich(
        self,
        indicators,
    ) -> MISPEnrichment:
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
                        "Known brute-force infrastructure"
                    ),
                    threat_level="high",
                )
            ],
        )


def test_misp_client_protocol_accepts_valid_client():
    client: MISPClient = FakeMISPClient()

    enrichment = client.enrich(
        [
            (
                "ip-src",
                "203.0.113.10",
            )
        ]
    )

    assert enrichment.queried_indicators == [
        "203.0.113.10"
    ]

    assert len(
        enrichment.matches
    ) == 1

    assert (
        enrichment.matches[0].threat_level
        == "high"
    )