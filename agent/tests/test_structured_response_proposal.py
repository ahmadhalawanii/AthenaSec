from datetime import (
    datetime,
    timezone,
)

import pytest

from app.graph.nodes.propose_response import (
    make_response_proposal_node,
)
from app.schemas import (
    AlertAnalysis,
    AnalysisVerificationResult,
    EvidenceRecord,
    ResponseActionProposal,
    RiskAssessment,
    SecurityAlertInput,
    StructuredResponseProposal,
)
from app.services.response_proposal import (
    build_proposed_action_records,
    validate_response_proposal,
)


PROPOSED_AT = datetime(
    2026,
    10,
    8,
    12,
    0,
    tzinfo=timezone.utc,
)


def make_alert() -> SecurityAlertInput:
    return SecurityAlertInput(
        alert_id="ALT-M4-001",
        source="wazuh",
        event_text=(
            "Repeated SSH authentication "
            "failures."
        ),
        metadata={
            "source_ip": "203.0.113.10",
            "target_user": "root",
            "agent_id": "007",
            "agent_name": "workstation-07",
        },
    )


def make_analysis() -> AlertAnalysis:
    return AlertAnalysis(
        classification="brute_force",
        confidence=0.95,
        severity_assessment="critical",
        summary=(
            "Critical SSH brute-force "
            "activity was detected."
        ),
        evidence_refs=[
            "E001",
            "E002",
        ],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[],
        needs_more_evidence=False,
    )


def make_verification(
    verified: bool = True,
) -> AnalysisVerificationResult:
    return AnalysisVerificationResult(
        verified=verified,
        classification_consistent=verified,
        evidence_sufficient=verified,
        checked_evidence_refs=[
            "E001",
            "E002",
        ],
        blocking_issues=(
            []
            if verified
            else [
                "classification_mismatch",
            ]
        ),
        warnings=[],
    )


def make_evidence() -> list[EvidenceRecord]:
    return [
        EvidenceRecord(
            evidence_id="E001",
            source="alert",
            evidence_type="alert",
            content=(
                "source_ip=203.0.113.10; "
                "target_user=root; "
                "agent_id=007; "
                "agent_name=workstation-07"
            ),
        ),
        EvidenceRecord(
            evidence_id="E002",
            source="wazuh",
            evidence_type=(
                "authentication_history"
            ),
            content=(
                "source_ip=203.0.113.10; "
                "target_user=root; "
                "authentication failures observed"
            ),
        ),
    ]


def make_state(
    *,
    verified: bool = True,
):
    return {
        "alert": make_alert(),
        "analysis": make_analysis(),
        "analysis_verification": (
            make_verification(
                verified
            )
        ),
        "risk_assessment": RiskAssessment(
            score=95,
            band="critical",
            factors=[],
        ),
        "evidence_records": (
            make_evidence()
        ),
    }


def make_block_proposal():
    return StructuredResponseProposal(
        summary=(
            "Temporarily contain the "
            "grounded malicious source."
        ),
        actions=[
            ResponseActionProposal(
                action_type="block_ip",
                target_type="ip",
                target="203.0.113.10",
                duration_minutes=30,
                reason=(
                    "Temporarily contain the "
                    "source of the brute-force "
                    "activity."
                ),
                evidence_refs=[
                    "E001",
                    "E002",
                ],
            ),
        ],
    )


def test_grounded_block_ip_proposal_is_valid():
    proposal = make_block_proposal()

    validate_response_proposal(
        proposal=proposal,
        state=make_state(),
    )


def test_ungrounded_ip_is_rejected():
    proposal = (
        StructuredResponseProposal(
            summary="Contain source.",
            actions=[
                ResponseActionProposal(
                    action_type="block_ip",
                    target_type="ip",
                    target="198.51.100.99",
                    duration_minutes=30,
                    reason="Contain source.",
                    evidence_refs=[
                        "E001",
                    ],
                ),
            ],
        )
    )

    with pytest.raises(
        ValueError,
        match="not grounded",
    ):
        validate_response_proposal(
            proposal=proposal,
            state=make_state(),
        )


def test_action_target_type_must_match_action():
    proposal = (
        StructuredResponseProposal(
            summary="Contain source.",
            actions=[
                ResponseActionProposal(
                    action_type="block_ip",
                    target_type="account",
                    target="root",
                    duration_minutes=30,
                    reason="Contain source.",
                    evidence_refs=[
                        "E001",
                    ],
                ),
            ],
        )
    )

    with pytest.raises(
        ValueError,
        match="target type",
    ):
        validate_response_proposal(
            proposal=proposal,
            state=make_state(),
        )


def test_block_ip_requires_temporary_duration():
    proposal = (
        StructuredResponseProposal(
            summary="Contain source.",
            actions=[
                ResponseActionProposal(
                    action_type="block_ip",
                    target_type="ip",
                    target="203.0.113.10",
                    duration_minutes=None,
                    reason="Contain source.",
                    evidence_refs=[
                        "E001",
                    ],
                ),
            ],
        )
    )

    with pytest.raises(
        ValueError,
        match="duration",
    ):
        validate_response_proposal(
            proposal=proposal,
            state=make_state(),
        )


def test_proposal_node_does_not_call_qwen_when_verification_failed():
    calls = []

    def proposer(
        context: str,
    ):
        calls.append(
            context
        )

        raise AssertionError(
            "Qwen must not be called "
            "for unverified analysis."
        )

    node = make_response_proposal_node(
        proposer
    )

    result = node(
        make_state(
            verified=False,
        )
    )

    assert calls == []

    assert (
        result[
            "response_proposal"
        ].actions
        == []
    )

    assert (
        result["status"]
        == "response_proposal_blocked"
    )


def test_proposal_node_accepts_grounded_qwen_proposal():
    calls = []

    def proposer(
        context: str,
    ):
        calls.append(
            context
        )

        return make_block_proposal()

    node = make_response_proposal_node(
        proposer
    )

    result = node(
        make_state()
    )

    assert len(calls) == 1

    assert (
        "INCIDENT RISK"
        in calls[0]
    )

    assert (
        "[E001]"
        in calls[0]
    )

    assert (
        result[
            "response_proposal"
        ].actions[0].action_type
        == "block_ip"
    )

    assert (
        result["status"]
        == "response_proposed"
    )


def test_proposed_action_record_is_deterministic_and_reversible():
    proposal = make_block_proposal()

    first = build_proposed_action_records(
        proposal=proposal,
        incident_id="INC-001",
        investigation_id="INV-001",
        proposed_at=PROPOSED_AT,
    )

    second = build_proposed_action_records(
        proposal=proposal,
        incident_id="INC-001",
        investigation_id="INV-001",
        proposed_at=PROPOSED_AT,
    )

    assert len(first) == 1

    assert (
        first[0].proposed_action_id
        == second[0].proposed_action_id
    )

    assert (
        first[0].action_type
        == "block_ip"
    )

    assert (
        first[0].target
        == "203.0.113.10"
    )

    assert first[0].reversible is True

    assert (
        first[0].rollback_action_type
        == "unblock_ip"
    )

    assert (
        first[0].parameters
        == {
            "duration_minutes": 30,
        }
    )


def test_capture_telemetry_is_non_destructive_and_non_reversible():
    proposal = StructuredResponseProposal(
        summary=(
            "Capture additional endpoint "
            "telemetry."
        ),
        actions=[
            ResponseActionProposal(
                action_type=(
                    "capture_telemetry"
                ),
                target_type="endpoint",
                target="007",
                duration_minutes=None,
                reason=(
                    "Gather endpoint telemetry."
                ),
                evidence_refs=[
                    "E001",
                ],
            ),
        ],
    )

    validate_response_proposal(
        proposal=proposal,
        state=make_state(),
    )

    records = (
        build_proposed_action_records(
            proposal=proposal,
            incident_id="INC-001",
            investigation_id="INV-001",
            proposed_at=PROPOSED_AT,
        )
    )

    assert (
        records[0].reversible
        is False
    )

    assert (
        records[0].rollback_action_type
        is None
    )