import pytest
from pydantic import ValidationError

from app.schemas import (
    MISPEnrichment,
    MISPMatch,
)


def test_misp_match_accepts_valid_indicator_match():
    match = MISPMatch(
        indicator_type="ip-src",
        indicator_value="203.0.113.10",
        event_id="42",
        event_info="Known brute-force infrastructure",
        threat_level="high",
    )

    assert match.indicator_type == "ip-src"
    assert match.indicator_value == "203.0.113.10"
    assert match.event_id == "42"
    assert match.threat_level == "high"


def test_misp_enrichment_contains_matches():
    enrichment = MISPEnrichment(
        queried_indicators=[
            "203.0.113.10",
        ],
        matches=[
            MISPMatch(
                indicator_type="ip-src",
                indicator_value="203.0.113.10",
                event_id="42",
                event_info="Known brute-force infrastructure",
                threat_level="high",
            )
        ],
    )

    assert enrichment.queried_indicators == [
        "203.0.113.10"
    ]

    assert len(enrichment.matches) == 1


def test_misp_match_rejects_invalid_threat_level():
    with pytest.raises(
        ValidationError,
    ):
        MISPMatch(
            indicator_type="ip-src",
            indicator_value="203.0.113.10",
            event_id="42",
            event_info="Known malicious infrastructure",
            threat_level="extreme",
        )