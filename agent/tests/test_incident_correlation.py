from datetime import (
    datetime,
    timedelta,
    timezone,
)

import pytest

from app.schemas import (
    IncidentCorrelationProfile,
    SecurityAlertInput,
)
from app.services.incident_correlation import (
    build_alert_correlation_fingerprint,
    evaluate_correlation,
    update_correlation_profile,
)


BASE_TIME = datetime(
    2026,
    10,
    8,
    8,
    0,
    tzinfo=timezone.utc,
)


def make_alert(
    *,
    alert_id: str = "ALT-001",
    timestamp: str = "2026-10-08T08:00:00+00:00",
    source_ip: str | None = "203.0.113.10",
    target_user: str | None = "root",
    agent_id: str | None = "007",
    mitre_ids: list[str] | None = None,
) -> SecurityAlertInput:
    return SecurityAlertInput(
        alert_id=alert_id,
        source="wazuh",
        event_text=(
            "Repeated SSH authentication failures."
        ),
        metadata={
            "timestamp": timestamp,
            "source_ip": source_ip,
            "target_user": target_user,
            "agent_id": agent_id,
            "mitre_ids": (
                mitre_ids
                if mitre_ids is not None
                else ["T1110.001"]
            ),
        },
    )


def make_profile(
    *,
    classification: str = "brute_force",
    first_seen: datetime = BASE_TIME,
    last_seen: datetime = BASE_TIME,
) -> IncidentCorrelationProfile:
    return IncidentCorrelationProfile(
        incident_id="INC-001",
        classification=classification,
        source_ips=[
            "203.0.113.10",
        ],
        target_users=[
            "root",
        ],
        agent_ids=[
            "007",
        ],
        mitre_ids=[
            "T1110.001",
        ],
        first_seen=first_seen,
        last_seen=last_seen,
    )


def test_builds_fingerprint_from_parsed_wazuh_metadata():
    alert = make_alert()

    fingerprint = (
        build_alert_correlation_fingerprint(
            alert,
            classification="brute_force",
        )
    )

    assert fingerprint.alert_id == "ALT-001"

    assert (
        fingerprint.classification
        == "brute_force"
    )

    assert (
        fingerprint.source_ip
        == "203.0.113.10"
    )

    assert (
        fingerprint.target_user
        == "root"
    )

    assert (
        fingerprint.agent_id
        == "007"
    )

    assert fingerprint.mitre_ids == [
        "T1110.001",
    ]

    assert (
        fingerprint.observed_at
        == BASE_TIME
    )


def test_fingerprint_deduplicates_and_sorts_mitre_ids():
    alert = make_alert(
        mitre_ids=[
            "T1110.001",
            "T1078",
            "T1110.001",
        ]
    )

    fingerprint = (
        build_alert_correlation_fingerprint(
            alert,
            classification="brute_force",
        )
    )

    assert fingerprint.mitre_ids == [
        "T1078",
        "T1110.001",
    ]


def test_wazuh_fingerprint_requires_timestamp():
    alert = make_alert()

    alert = alert.model_copy(
        update={
            "metadata": {
                **alert.metadata,
                "timestamp": None,
            }
        }
    )

    with pytest.raises(
        ValueError,
        match="timestamp",
    ):
        build_alert_correlation_fingerprint(
            alert,
            classification="brute_force",
        )


def test_same_source_ip_correlates_within_window():
    profile = make_profile()

    fingerprint = (
        build_alert_correlation_fingerprint(
            make_alert(
                timestamp=(
                    "2026-10-08T08:10:00+00:00"
                ),
                target_user="another-user",
                agent_id="999",
                mitre_ids=[
                    "T9999",
                ],
            ),
            classification="brute_force",
        )
    )

    result = evaluate_correlation(
        profile,
        fingerprint,
    )

    assert result.matched is True

    assert result.score == 5

    assert (
        "source_ip"
        in result.reasons
    )


def test_same_agent_and_target_user_correlate():
    profile = make_profile()

    fingerprint = (
        build_alert_correlation_fingerprint(
            make_alert(
                timestamp=(
                    "2026-10-08T08:05:00+00:00"
                ),
                source_ip=None,
                target_user="root",
                agent_id="007",
                mitre_ids=[],
            ),
            classification="brute_force",
        )
    )

    result = evaluate_correlation(
        profile,
        fingerprint,
    )

    assert result.matched is True

    assert result.score == 5

    assert result.reasons == [
        "agent_id",
        "target_user",
    ]


def test_same_agent_and_mitre_correlate():
    profile = make_profile()

    fingerprint = (
        build_alert_correlation_fingerprint(
            make_alert(
                timestamp=(
                    "2026-10-08T08:05:00+00:00"
                ),
                source_ip=None,
                target_user="different-user",
                agent_id="007",
                mitre_ids=[
                    "T1110.001",
                ],
            ),
            classification="brute_force",
        )
    )

    result = evaluate_correlation(
        profile,
        fingerprint,
    )

    assert result.matched is True

    assert result.score == 5

    assert result.reasons == [
        "agent_id",
        "mitre_id",
    ]


def test_weak_target_user_match_does_not_correlate():
    profile = make_profile()

    fingerprint = (
        build_alert_correlation_fingerprint(
            make_alert(
                timestamp=(
                    "2026-10-08T08:05:00+00:00"
                ),
                source_ip="198.51.100.99",
                target_user="root",
                agent_id="999",
                mitre_ids=[],
            ),
            classification="brute_force",
        )
    )

    result = evaluate_correlation(
        profile,
        fingerprint,
    )

    assert result.matched is False

    assert result.score == 2


def test_different_classification_never_correlates():
    profile = make_profile(
        classification="privilege_misuse",
    )

    fingerprint = (
        build_alert_correlation_fingerprint(
            make_alert(),
            classification="brute_force",
        )
    )

    result = evaluate_correlation(
        profile,
        fingerprint,
    )

    assert result.matched is False

    assert result.score == 0

    assert result.reasons == [
        "classification_mismatch",
    ]


def test_alert_outside_window_does_not_correlate():
    profile = make_profile()

    fingerprint = (
        build_alert_correlation_fingerprint(
            make_alert(
                timestamp=(
                    "2026-10-08T08:16:00+00:00"
                ),
            ),
            classification="brute_force",
        )
    )

    result = evaluate_correlation(
        profile,
        fingerprint,
    )

    assert result.matched is False

    assert result.score == 0

    assert result.reasons == [
        "outside_time_window",
    ]


def test_out_of_order_alert_inside_window_can_correlate():
    profile = make_profile(
        first_seen=(
            BASE_TIME
            + timedelta(minutes=5)
        ),
        last_seen=(
            BASE_TIME
            + timedelta(minutes=10)
        ),
    )

    fingerprint = (
        build_alert_correlation_fingerprint(
            make_alert(
                timestamp=(
                    "2026-10-08T07:55:00+00:00"
                ),
            ),
            classification="brute_force",
        )
    )

    result = evaluate_correlation(
        profile,
        fingerprint,
    )

    assert result.matched is True


def test_profile_update_merges_unique_correlation_values():
    profile = make_profile()

    fingerprint = (
        build_alert_correlation_fingerprint(
            make_alert(
                alert_id="ALT-002",
                timestamp=(
                    "2026-10-08T08:07:00+00:00"
                ),
                source_ip="203.0.113.11",
                target_user="admin",
                agent_id="008",
                mitre_ids=[
                    "T1078",
                    "T1110.001",
                ],
            ),
            classification="brute_force",
        )
    )

    updated = update_correlation_profile(
        profile,
        fingerprint,
    )

    assert updated.source_ips == [
        "203.0.113.10",
        "203.0.113.11",
    ]

    assert updated.target_users == [
        "admin",
        "root",
    ]

    assert updated.agent_ids == [
        "007",
        "008",
    ]

    assert updated.mitre_ids == [
        "T1078",
        "T1110.001",
    ]

    assert (
        updated.first_seen
        == BASE_TIME
    )

    assert (
        updated.last_seen
        == BASE_TIME
        + timedelta(minutes=7)
    )


def test_profile_update_preserves_earliest_first_seen():
    profile = make_profile(
        first_seen=BASE_TIME,
        last_seen=BASE_TIME,
    )

    fingerprint = (
        build_alert_correlation_fingerprint(
            make_alert(
                timestamp=(
                    "2026-10-08T07:58:00+00:00"
                ),
            ),
            classification="brute_force",
        )
    )

    updated = update_correlation_profile(
        profile,
        fingerprint,
    )

    assert updated.first_seen == (
        BASE_TIME
        - timedelta(minutes=2)
    )

    assert updated.last_seen == BASE_TIME