from datetime import (
    datetime,
    timezone,
)

from app.graph.graph import (
    build_investigation_graph,
)
from app.schemas import (
    AlertAnalysis,
    AnalysisVerificationResult,
    EvidenceRecord,
    InvestigationResponse,
    PolicyDecision,
    ResponseActionProposal,
    ResponsePlan,
    RiskAssessment,
    SecurityAlertInput,
    StructuredResponseProposal,
)
from app.services.incident_response_store import (
    InMemoryIncidentResponseStore,
)
from app.services.response_risk_lifecycle import (
    persist_response_risk_lifecycle,
)
from app.services.structured_response_hold import (
    hold_legacy_execution_for_structured_response,
)


FIXED_TIME = datetime(
    2026,
    10,
    8,
    14,
    0,
    tzinfo=timezone.utc,
)


def make_analysis():
    return AlertAnalysis(
        classification="brute_force",
        confidence=0.95,
        severity_assessment="high",
        summary=(
            "SSH brute-force activity "
            "was detected."
        ),
        evidence_refs=[
            "E001",
        ],
        uncertainties=[],
        recommended_investigation_steps=[],
        recommended_response_actions=[],
        requested_evidence=[],
        needs_more_evidence=False,
    )


def make_proposal():
    return StructuredResponseProposal(
        summary=(
            "Temporarily contain the "
            "grounded source IP."
        ),
        actions=[
            ResponseActionProposal(
                action_type="block_ip",
                target_type="ip",
                target="203.0.113.10",
                duration_minutes=30,
                reason=(
                    "Contain the brute-force "
                    "source temporarily."
                ),
                evidence_refs=[
                    "E001",
                ],
            ),
        ],
    )


def test_graph_builds_proposed_action_and_action_risk():
    def analyzer(
        context: str,
    ):
        return make_analysis()

    def proposer(
        context: str,
    ):
        return make_proposal()

    graph = build_investigation_graph(
        analyzer=analyzer,
        response_proposer=proposer,
    )

    result = graph.invoke(
        {
            "incident_id": "INC-001",
            "investigation_id": "INV-001",
            "alert": SecurityAlertInput(
                alert_id="ALT-M4-GRAPH-001",
                source="manual",
                event_text=(
                    "Failed SSH authentication "
                    "attempts from 203.0.113.10."
                ),
                metadata={
                    "source_ip": (
                        "203.0.113.10"
                    ),
                    "failed_attempts": 20,
                },
            ),
            "status": "received",
        }
    )

    assert (
        result[
            "response_proposal"
        ].actions[0].action_type
        == "block_ip"
    )

    assert len(
        result[
            "proposed_actions"
        ]
    ) == 1

    assert len(
        result[
            "action_risk_assessments"
        ]
    ) == 1

    action = result[
        "proposed_actions"
    ][0]

    action_risk = result[
        "action_risk_assessments"
    ][0]

    assert (
        action.incident_id
        == "INC-001"
    )

    assert (
        action.investigation_id
        == "INV-001"
    )

    assert (
        action.action_type
        == "block_ip"
    )

    assert (
        action_risk.proposed_action_id
        == action.proposed_action_id
    )

    assert action_risk.score == 10

    assert (
        action_risk.requires_approval
        is False
    )


def make_investigation():
    proposal = make_proposal()

    graph = build_investigation_graph(
        analyzer=lambda context: (
            make_analysis()
        ),
        response_proposer=(
            lambda context: proposal
        ),
    )

    result = graph.invoke(
        {
            "incident_id": "INC-001",
            "investigation_id": "INV-001",
            "alert": SecurityAlertInput(
                alert_id="ALT-M4-001",
                source="manual",
                event_text=(
                    "Failed SSH authentication "
                    "attempts from 203.0.113.10."
                ),
                metadata={
                    "source_ip": (
                        "203.0.113.10"
                    ),
                    "failed_attempts": 20,
                },
            ),
            "status": "received",
        }
    )

    return InvestigationResponse(
        alert_id="ALT-M4-001",
        incident_id="INC-001",
        investigation_id="INV-001",
        source="manual",
        alert_metadata={
            "source_ip": (
                "203.0.113.10"
            ),
        },
        status="complete",
        normalized_event=(
            result["normalized_event"]
        ),
        analysis=result["analysis"],
        evidence_records=(
            result["evidence_records"]
        ),
        evidence_sufficiency=(
            result.get(
                "evidence_sufficiency"
            )
        ),
        analysis_verification=(
            result.get(
                "analysis_verification"
            )
        ),
        investigation_budget_exhausted=(
            result.get(
                "investigation_budget_exhausted",
                False,
            )
        ),
        investigation_trace=(
            result.get(
                "investigation_trace",
                [],
            )
        ),
        risk_assessment=(
            result["risk_assessment"]
        ),
        response_proposal=(
            result["response_proposal"]
        ),
        proposed_actions=(
            result["proposed_actions"]
        ),
        action_risk_assessments=(
            result[
                "action_risk_assessments"
            ]
        ),
        policy_decision=(
            result["policy_decision"]
        ),
        response_plan=(
            result["response_plan"]
        ),
        investigation_iteration=(
            result.get(
                "investigation_iteration",
                0,
            )
        ),
    )


def test_response_risk_lifecycle_persists_all_m4_records():
    investigation = (
        make_investigation()
    )

    store = (
        InMemoryIncidentResponseStore()
    )

    persisted = (
        persist_response_risk_lifecycle(
            store=store,
            investigation=investigation,
            assessed_at=FIXED_TIME,
        )
    )

    assert persisted is not None

    assert (
        persisted.incident_risk
        is not None
    )

    assert (
        persisted.incident_risk.score
        == investigation
        .risk_assessment
        .score
    )

    assert len(
        persisted.proposed_actions
    ) == 1

    assert len(
        persisted.action_risks
    ) == 1

    action = (
        persisted.proposed_actions[0]
    )

    risk = (
        persisted.action_risks[0]
    )

    assert (
        store.get_proposed_action(
            action.proposed_action_id
        )
        == action
    )

    assert (
        store.get_action_risk(
            risk.action_risk_id
        )
        == risk
    )

    assert (
        store.get_incident_risk(
            persisted
            .incident_risk
            .risk_assessment_id
        )
        == persisted.incident_risk
    )


def test_response_risk_persistence_requires_incident_identity():
    investigation = (
        make_investigation()
        .model_copy(
            update={
                "incident_id": None,
                "investigation_id": None,
            }
        )
    )

    store = (
        InMemoryIncidentResponseStore()
    )

    persisted = (
        persist_response_risk_lifecycle(
            store=store,
            investigation=investigation,
            assessed_at=FIXED_TIME,
        )
    )

    assert persisted is None


def test_structured_response_is_held_before_m5_policy():
    investigation = (
        make_investigation()
    )

    legacy_allowed = (
        investigation.model_copy(
            update={
                "policy_decision": (
                    PolicyDecision(
                        policy_id=(
                            "POL-BF-CRITICAL"
                        ),
                        policy_name=(
                            "Legacy Critical "
                            "Brute Force"
                        ),
                        matched=True,
                        response_allowed=True,
                        actions=[
                            "block_ip",
                        ],
                        reason=(
                            "Legacy policy "
                            "allowed execution."
                        ),
                    )
                ),
                "response_plan": (
                    ResponsePlan(
                        policy_id=(
                            "POL-BF-CRITICAL"
                        ),
                        actions=[
                            "block_ip",
                        ],
                        response_allowed=True,
                        status=(
                            "ready_for_execution"
                        ),
                        reason=(
                            "Legacy policy "
                            "allowed execution."
                        ),
                    )
                ),
            }
        )
    )

    held = (
        hold_legacy_execution_for_structured_response(
            legacy_allowed
        )
    )

    assert (
        held.policy_decision
        .response_allowed
        is False
    )

    assert (
        held.policy_decision.actions
        == []
    )

    assert (
        held.response_plan
        .response_allowed
        is False
    )

    assert (
        held.response_plan.actions
        == []
    )

    assert (
        held.response_plan.status
        == "create_case"
    )

    assert (
        "action policy"
        in held.response_plan.reason.lower()
    )


def test_legacy_investigation_without_structured_proposal_is_unchanged():
    investigation = (
        make_investigation()
        .model_copy(
            update={
                "response_proposal": None,
                "proposed_actions": [],
                "action_risk_assessments": [],
            }
        )
    )

    held = (
        hold_legacy_execution_for_structured_response(
            investigation
        )
    )

    assert held == investigation