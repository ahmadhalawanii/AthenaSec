from datetime import (
    datetime,
    timezone,
)

from app.graph.nodes.policy import (
    evaluate_investigation_policy,
)
from app.graph.nodes.verify_analysis import (
    verify_investigation_analysis,
)
from app.schemas import (
    AlertAnalysis,
    AnalysisVerificationResult,
    AttackPrediction,
    EvidenceRecord,
    EvidenceSufficiencyAssessment,
    RiskAssessment,
    SecurityAlertInput,
)
from app.services.analysis_verifier import (
    verify_analysis,
)


ALERT_TIME = datetime(
    2026,
    10,
    8,
    8,
    0,
    tzinfo=timezone.utc,
)


def make_alert() -> SecurityAlertInput:
    return SecurityAlertInput(
        alert_id="ALT-VERIFY-001",
        source="wazuh",
        event_text=(
            "Repeated SSH authentication "
            "failures were detected."
        ),
        metadata={
            "timestamp": (
                ALERT_TIME.isoformat()
            ),
            "source_ip": "203.0.113.10",
            "target_user": "root",
        },
    )


def make_prediction(
    classification: str = "brute_force",
) -> AttackPrediction:
    return AttackPrediction(
        classification=classification,
        confidence=0.97,
        model_version="test-model",
    )


def make_analysis(
    *,
    classification: str = "brute_force",
    summary: str = (
        "SSH brute-force activity "
        "was detected."
    ),
    evidence_refs: list[str] | None = None,
) -> AlertAnalysis:
    return AlertAnalysis(
        classification=classification,
        confidence=0.95,
        severity_assessment="high",
        summary=summary,
        evidence_refs=(
            evidence_refs
            if evidence_refs is not None
            else [
                "E001",
                "E002",
                "E003",
            ]
        ),
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[],
        needs_more_evidence=False,
    )


def make_evidence() -> list[EvidenceRecord]:
    return [
        EvidenceRecord(
            evidence_id="E001",
            source="alert",
            evidence_type="alert",
            content=(
                "Repeated SSH authentication "
                "failures were detected."
            ),
        ),
        EvidenceRecord(
            evidence_id="E002",
            source="wazuh",
            evidence_type=(
                "authentication_history"
            ),
            content=(
                "timestamp="
                "2026-10-08T08:05:00+00:00; "
                "source_ip=203.0.113.10; "
                "target_user=root; "
                "authentication failures observed"
            ),
        ),
        EvidenceRecord(
            evidence_id="E003",
            source="wazuh",
            evidence_type=(
                "source_endpoint_context"
            ),
            content=(
                "timestamp="
                "2026-10-08T08:04:00+00:00; "
                "source_ip=203.0.113.10; "
                "agent_name=workstation-07"
            ),
        ),
    ]


def make_sufficiency(
    *,
    sufficient: bool = True,
) -> EvidenceSufficiencyAssessment:
    if sufficient:
        return EvidenceSufficiencyAssessment(
            classification="brute_force",
            sufficient=True,
            required_evidence=[
                "authentication_history",
                "source_endpoint_context",
            ],
            satisfied_evidence=[
                "authentication_history",
                "source_endpoint_context",
            ],
            missing_evidence=[],
        )

    return EvidenceSufficiencyAssessment(
        classification="brute_force",
        sufficient=False,
        required_evidence=[
            "authentication_history",
            "source_endpoint_context",
        ],
        satisfied_evidence=[
            "authentication_history",
        ],
        missing_evidence=[
            "source_endpoint_context",
        ],
    )


def test_consistent_grounded_analysis_is_verified():
    result = verify_analysis(
        alert=make_alert(),
        analysis=make_analysis(),
        evidence_records=make_evidence(),
        ml_prediction=make_prediction(),
        evidence_sufficiency=(
            make_sufficiency()
        ),
        investigation_budget_exhausted=False,
    )

    assert result.verified is True

    assert (
        result.classification_consistent
        is True
    )

    assert (
        result.evidence_sufficient
        is True
    )

    assert result.blocking_issues == []


def test_ml_analysis_classification_mismatch_is_blocking():
    result = verify_analysis(
        alert=make_alert(),
        analysis=make_analysis(
            classification=(
                "privilege_misuse"
            ),
        ),
        evidence_records=make_evidence(),
        ml_prediction=make_prediction(
            "brute_force"
        ),
        evidence_sufficiency=(
            make_sufficiency()
        ),
        investigation_budget_exhausted=False,
    )

    assert result.verified is False

    assert (
        result.classification_consistent
        is False
    )

    assert (
        "classification_mismatch"
        in result.blocking_issues
    )


def test_insufficient_wazuh_evidence_is_blocking():
    result = verify_analysis(
        alert=make_alert(),
        analysis=make_analysis(),
        evidence_records=make_evidence(),
        ml_prediction=make_prediction(),
        evidence_sufficiency=(
            make_sufficiency(
                sufficient=False
            )
        ),
        investigation_budget_exhausted=True,
    )

    assert result.verified is False

    assert (
        result.evidence_sufficient
        is False
    )

    assert (
        "evidence_insufficient"
        in result.blocking_issues
    )

    assert (
        "investigation_budget_exhausted"
        in result.warnings
    )


def test_successful_authentication_claim_can_be_contradicted():
    evidence_records = (
        make_evidence()
    )

    evidence_records[1] = (
        EvidenceRecord(
            evidence_id="E002",
            source="wazuh",
            evidence_type=(
                "authentication_history"
            ),
            content=(
                "timestamp="
                "2026-10-08T08:05:00+00:00; "
                "No successful SSH "
                "authentication was found."
            ),
        )
    )

    result = verify_analysis(
        alert=make_alert(),
        analysis=make_analysis(
            summary=(
                "A successful authentication "
                "occurred after the brute-force "
                "attempts."
            ),
        ),
        evidence_records=evidence_records,
        ml_prediction=make_prediction(),
        evidence_sufficiency=(
            make_sufficiency()
        ),
        investigation_budget_exhausted=False,
    )

    assert result.verified is False

    assert (
        "successful_authentication_contradiction"
        in result.blocking_issues
    )


def test_stale_cited_wazuh_evidence_is_blocking():
    evidence_records = (
        make_evidence()
    )

    evidence_records[1] = (
        EvidenceRecord(
            evidence_id="E002",
            source="wazuh",
            evidence_type=(
                "authentication_history"
            ),
            content=(
                "timestamp="
                "2026-10-08T06:00:00+00:00; "
                "authentication failures observed"
            ),
        )
    )

    result = verify_analysis(
        alert=make_alert(),
        analysis=make_analysis(),
        evidence_records=evidence_records,
        ml_prediction=make_prediction(),
        evidence_sufficiency=(
            make_sufficiency()
        ),
        investigation_budget_exhausted=False,
    )

    assert result.verified is False

    assert (
        "stale_cited_evidence:E002"
        in result.blocking_issues
    )


def test_tool_evidence_not_cited_is_warning_only():
    result = verify_analysis(
        alert=make_alert(),
        analysis=make_analysis(
            evidence_refs=[
                "E001",
            ],
        ),
        evidence_records=make_evidence(),
        ml_prediction=make_prediction(),
        evidence_sufficiency=(
            make_sufficiency()
        ),
        investigation_budget_exhausted=False,
    )

    assert result.verified is True

    assert (
        "tool_evidence_not_cited"
        in result.warnings
    )


def test_verification_graph_node_stores_result():
    state = {
        "alert": make_alert(),
        "analysis": make_analysis(),
        "evidence_records": (
            make_evidence()
        ),
        "ml_prediction": (
            make_prediction()
        ),
        "evidence_sufficiency": (
            make_sufficiency()
        ),
        "investigation_budget_exhausted": (
            False
        ),
    }

    result = (
        verify_investigation_analysis(
            state
        )
    )

    assert (
        result[
            "analysis_verification"
        ].verified
        is True
    )

    assert (
        result["status"]
        == "analysis_verified"
    )


def test_policy_fails_closed_when_analysis_verification_fails():
    verification = (
        AnalysisVerificationResult(
            verified=False,
            classification_consistent=False,
            evidence_sufficient=True,
            checked_evidence_refs=[
                "E001",
            ],
            blocking_issues=[
                "classification_mismatch",
            ],
            warnings=[],
        )
    )

    state = {
        "analysis": make_analysis(),
        "risk_assessment": (
            RiskAssessment(
                score=95,
                band="critical",
                factors=[],
            )
        ),
        "analysis_verification": (
            verification
        ),
    }

    result = (
        evaluate_investigation_policy(
            state
        )
    )

    decision = result[
        "policy_decision"
    ]

    assert (
        decision.response_allowed
        is False
    )

    assert decision.actions == []

    assert (
        "analysis verification failed"
        in decision.reason.lower()
    )