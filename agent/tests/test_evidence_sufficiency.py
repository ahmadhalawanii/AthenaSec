from app.schemas import (
    EvidenceRecord,
)
from app.services.evidence_sufficiency import (
    evaluate_evidence_sufficiency,
)


def evidence(
    evidence_id: str,
    evidence_type: str,
) -> EvidenceRecord:
    return EvidenceRecord(
        evidence_id=evidence_id,
        source="wazuh",
        evidence_type=evidence_type,
        content=(
            f"Evidence for {evidence_type}"
        ),
    )


def test_brute_force_requires_authentication_and_endpoint_context():
    result = evaluate_evidence_sufficiency(
        classification="brute_force",
        evidence_records=[
            evidence(
                "E002",
                "authentication_history",
            ),
            evidence(
                "E003",
                "source_endpoint_context",
            ),
        ],
    )

    assert result.sufficient is True

    assert result.required_evidence == [
        "authentication_history",
        "source_endpoint_context",
    ]

    assert result.satisfied_evidence == [
        "authentication_history",
        "source_endpoint_context",
    ]

    assert result.missing_evidence == []


def test_brute_force_is_insufficient_without_endpoint_context():
    result = evaluate_evidence_sufficiency(
        classification="brute_force",
        evidence_records=[
            evidence(
                "E002",
                "authentication_history",
            ),
        ],
    )

    assert result.sufficient is False

    assert result.missing_evidence == [
        "source_endpoint_context",
    ]


def test_privilege_misuse_requires_privilege_and_authentication_evidence():
    result = evaluate_evidence_sufficiency(
        classification="privilege_misuse",
        evidence_records=[
            evidence(
                "E002",
                "privilege_activity",
            ),
            evidence(
                "E003",
                "authentication_history",
            ),
        ],
    )

    assert result.sufficient is True

    assert result.required_evidence == [
        "privilege_activity",
        "authentication_history",
    ]


def test_privilege_escalation_uses_privilege_requirements():
    result = evaluate_evidence_sufficiency(
        classification="privilege_escalation",
        evidence_records=[
            evidence(
                "E002",
                "privilege_activity",
            ),
            evidence(
                "E003",
                "authentication_history",
            ),
        ],
    )

    assert result.sufficient is True


def test_unknown_requires_general_security_evidence():
    result = evaluate_evidence_sufficiency(
        classification="unknown",
        evidence_records=[
            evidence(
                "E002",
                "related_security_events",
            ),
        ],
    )

    assert result.sufficient is True

    assert result.required_evidence == [
        "related_security_events",
    ]


def test_alert_record_does_not_satisfy_tool_requirement():
    record = EvidenceRecord(
        evidence_id="E001",
        source="alert",
        evidence_type="alert",
        content="Original Wazuh alert.",
    )

    result = evaluate_evidence_sufficiency(
        classification="brute_force",
        evidence_records=[
            record,
        ],
    )

    assert result.sufficient is False

    assert result.satisfied_evidence == []

    assert result.missing_evidence == [
        "authentication_history",
        "source_endpoint_context",
    ]


def test_duplicate_evidence_types_are_counted_once():
    result = evaluate_evidence_sufficiency(
        classification="brute_force",
        evidence_records=[
            evidence(
                "E002",
                "authentication_history",
            ),
            evidence(
                "E003",
                "authentication_history",
            ),
            evidence(
                "E004",
                "source_endpoint_context",
            ),
        ],
    )

    assert result.satisfied_evidence == [
        "authentication_history",
        "source_endpoint_context",
    ]


def test_benign_requires_no_investigation_evidence():
    result = evaluate_evidence_sufficiency(
        classification="benign",
        evidence_records=[],
    )

    assert result.sufficient is True

    assert result.required_evidence == []

    assert result.missing_evidence == []