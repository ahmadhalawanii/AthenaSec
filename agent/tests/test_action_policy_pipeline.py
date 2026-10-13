from datetime import (
    datetime,
    timedelta,
    timezone,
)

from app.graph.graph import (
    build_investigation_graph,
)
from app.schemas import (
    AlertAnalysis,
    InvestigationResponse,
    ResponseActionProposal,
    SecurityAlertInput,
    StructuredResponseProposal,
)
from app.services.action_policy_lifecycle import (
    persist_action_policy_lifecycle,
)
from app.services.incident_response_store import (
    InMemoryIncidentResponseStore,
)
from app.services.structured_action_policy import (
    apply_structured_action_policy,
    process_structured_policy_outcomes,
)


FIXED_TIME = datetime(
    2026,
    10,
    8,
    17,
    0,
    tzinfo=timezone.utc,
)


def make_analysis():
    return AlertAnalysis(
        classification="brute_force",
        confidence=0.95,
        severity_assessment="critical",
        summary=(
            "SSH brute-force activity "
            "was verified."
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


def make_proposal(
    duration_minutes: int = 30,
):
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
                duration_minutes=(
                    duration_minutes
                ),
                reason=(
                    "Temporarily contain "
                    "the brute-force source."
                ),
                evidence_refs=[
                    "E001",
                ],
            ),
        ],
    )


def build_result(
    duration_minutes: int,
):
    graph = build_investigation_graph(
        analyzer=lambda context: (
            make_analysis()
        ),
        response_proposer=(
            lambda context: (
                make_proposal(
                    duration_minutes
                )
            )
        ),
        action_policy_clock=(
            lambda: FIXED_TIME
        ),
    )

    return graph.invoke(
        {
            "incident_id": "INC-001",
            "investigation_id": "INV-001",
            "alert": SecurityAlertInput(
                alert_id="ALT-M5-001",
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


def make_investigation(
    duration_minutes: int,
):
    result = build_result(
        duration_minutes
    )

    return InvestigationResponse(
        alert_id="ALT-M5-001",
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
        action_policy_decisions=(
            result[
                "action_policy_decisions"
            ]
        ),
        approval_requests=(
            result["approval_requests"]
        ),
        risk_assessment=(
            result["risk_assessment"]
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


def test_long_block_creates_pending_exact_action_approval():
    result = build_result(
        480
    )

    decisions = result[
        "action_policy_decisions"
    ]

    approvals = result[
        "approval_requests"
    ]

    assert len(decisions) == 1

    assert (
        decisions[0].outcome
        == "APPROVAL_REQUIRED"
    )

    assert len(approvals) == 1

    assert (
        approvals[0].status
        == "PENDING"
    )

    assert (
        approvals[0]
        .proposed_action_id
        == result[
            "proposed_actions"
        ][0].proposed_action_id
    )

    assert (
        approvals[0].expires_at
        - approvals[0].requested_at
        == timedelta(minutes=30)
    )


def test_low_risk_short_block_is_auto_allowed():
    result = build_result(
        30
    )

    assert (
        result[
            "action_policy_decisions"
        ][0].outcome
        == "AUTO_ALLOWED"
    )

    assert (
        result["approval_requests"]
        == []
    )


def test_policy_and_approval_records_are_persisted():
    investigation = (
        make_investigation(
            480
        )
    )

    store = (
        InMemoryIncidentResponseStore()
    )

    persisted = (
        persist_action_policy_lifecycle(
            store=store,
            investigation=investigation,
        )
    )

    assert persisted is not None

    assert len(
        persisted.policy_decisions
    ) == 1

    assert len(
        persisted.approval_requests
    ) == 1

    decision = (
        persisted
        .policy_decisions[0]
    )

    approval = (
        persisted
        .approval_requests[0]
    )

    assert (
        store.get_policy_decision(
            decision.decision_id
        )
        == decision
    )

    assert (
        store.get_approval_request(
            approval.approval_id
        )
        == approval
    )


def test_approval_required_maps_to_awaiting_approval():
    investigation = (
        make_investigation(
            480
        )
    )

    updated = (
        apply_structured_action_policy(
            investigation
        )
    )

    assert (
        updated.response_plan.status
        == "awaiting_approval"
    )

    assert (
        updated.response_plan
        .response_allowed
        is False
    )

    assert (
        updated.response_plan.actions
        == []
    )


def test_auto_allowed_maps_to_structured_ready_not_legacy_execution():
    investigation = (
        make_investigation(
            30
        )
    )

    updated = (
        apply_structured_action_policy(
            investigation
        )
    )

    assert (
        updated.response_plan.status
        == "ready_for_structured_execution"
    )

    assert (
        updated.response_plan
        .response_allowed
        is False
    )

    assert (
        updated.response_plan.actions
        == []
    )


def test_not_allowed_creates_incident_case():
    investigation = (
        make_investigation(
            30
        )
    )

    original = (
        investigation
        .action_policy_decisions[0]
    )

    denied = original.model_copy(
        update={
            "policy_id": (
                "POL-ACTION-PROTECTED-TARGET"
            ),
            "outcome": "NOT_ALLOWED",
            "reason": (
                "Protected target."
            ),
        }
    )

    investigation = (
        investigation.model_copy(
            update={
                "action_policy_decisions": [
                    denied,
                ],
                "approval_requests": [],
            }
        )
    )

    investigation = (
        apply_structured_action_policy(
            investigation
        )
    )

    store = (
        InMemoryIncidentResponseStore()
    )

    outcome = (
        process_structured_policy_outcomes(
            investigation=investigation,
            store=store,
            now=FIXED_TIME,
        )
    )

    assert (
        outcome["outcome"]
        == "case_created"
    )

    cases = (
        store.list_incident_cases(
            "INC-001"
        )
    )

    assert len(cases) == 1

    assert (
        cases[0].policy_decision_id
        == denied.decision_id
    )

    assert cases[0].status == "open"


def test_graph_without_incident_identity_does_not_create_response_actions():
    graph = build_investigation_graph(
        analyzer=lambda context: (
            make_analysis()
        ),
        response_proposer=(
            lambda context: (
                make_proposal(30)
            )
        ),
        action_policy_clock=(
            lambda: FIXED_TIME
        ),
    )

    result = graph.invoke(
        {
            "alert": SecurityAlertInput(
                alert_id="ALT-MANUAL-001",
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
        result["proposed_actions"]
        == []
    )

    assert (
        result[
            "action_risk_assessments"
        ]
        == []
    )

    assert (
        result[
            "action_policy_decisions"
        ]
        == []
    )

    assert (
        result["approval_requests"]
        == []
    )
