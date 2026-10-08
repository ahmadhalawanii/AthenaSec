from app.schemas import (
    AttackClassification,
    EvidenceRecord,
    EvidenceRequest,
    EvidenceSufficiencyAssessment,
)


REQUIRED_EVIDENCE: dict[
    AttackClassification,
    tuple[EvidenceRequest, ...],
] = {
    "brute_force": (
        "authentication_history",
        "source_endpoint_context",
    ),
    "privilege_misuse": (
        "privilege_activity",
        "authentication_history",
    ),
    "privilege_escalation": (
        "privilege_activity",
        "authentication_history",
    ),
    "unknown": (
        "related_security_events",
    ),
    "benign": (),
}


def required_evidence_for_classification(
    classification: AttackClassification,
) -> list[EvidenceRequest]:
    return list(
        REQUIRED_EVIDENCE.get(
            classification,
            (),
        )
    )


def evaluate_evidence_sufficiency(
    *,
    classification: AttackClassification,
    evidence_records: list[EvidenceRecord],
) -> EvidenceSufficiencyAssessment:
    required = (
        required_evidence_for_classification(
            classification
        )
    )

    observed_types = {
        record.evidence_type
        for record in evidence_records
        if (
            record.evidence_type
            is not None
            and record.evidence_type
            != "alert"
        )
    }

    satisfied = [
        evidence_type
        for evidence_type in required
        if evidence_type in observed_types
    ]

    missing = [
        evidence_type
        for evidence_type in required
        if evidence_type
        not in observed_types
    ]

    return EvidenceSufficiencyAssessment(
        classification=classification,
        sufficient=(
            len(missing) == 0
        ),
        required_evidence=required,
        satisfied_evidence=satisfied,
        missing_evidence=missing,
    )