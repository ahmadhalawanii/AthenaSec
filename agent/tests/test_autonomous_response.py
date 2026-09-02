from app.schemas import (
    ActionExecutionResult,
    AlertAnalysis,
    EvidenceRecord,
    InvestigationResponse,
    PolicyDecision,
    ResponseExecutionResult,
    ResponsePlan,
    RiskAssessment,
)
from app.services.autonomous_response import (
    process_autonomous_response,
)
from app.services.investigation_store import (
    InMemoryInvestigationStore,
)


def make_investigation(
    response_allowed: bool,
    status: str,
) -> InvestigationResponse:
    actions = (
        ["block_ip"]
        if response_allowed
        else []
    )

    return InvestigationResponse(
        alert_id="ALT-AUTO-001",
        source="wazuh",
        status="complete",
        normalized_event=(
            "Critical SSH brute force "
            "against root."
        ),
        analysis=AlertAnalysis(
            classification="brute_force",
            confidence=0.95,
            severity_assessment="critical",
            summary=(
                "Critical SSH brute force detected."
            ),
            evidence_refs=[
                "E001",
            ],
            uncertainties=[],
            recommended_investigation_steps=[],
            recommended_response_actions=[],
            requested_evidence=[],
            needs_more_evidence=False,
        ),
        evidence_records=[
            EvidenceRecord(
                evidence_id="E001",
                source="alert",
                content=(
                    "148 failed SSH login attempts "
                    "against root."
                ),
            ),
        ],
        risk_assessment=RiskAssessment(
            score=92,
            band="critical",
            factors=[],
        ),
        policy_decision=PolicyDecision(
            policy_id="POL-BF-CRITICAL",
            policy_name=(
                "Critical Brute Force Containment"
            ),
            matched=True,
            response_allowed=response_allowed,
            actions=actions,
            reason=(
                "Autonomous containment policy result."
            ),
        ),
        response_plan=ResponsePlan(
            policy_id="POL-BF-CRITICAL",
            actions=actions,
            response_allowed=response_allowed,
            status=status,
            reason=(
                "Autonomous containment policy result."
            ),
        ),
        investigation_iteration=1,
    )


class FakeSuccessfulExecutor:
    def __init__(self):
        self.calls = []

    def execute(
        self,
        investigation: InvestigationResponse,
    ) -> ResponseExecutionResult:
        self.calls.append(
            investigation.alert_id
        )

        return ResponseExecutionResult(
            policy_id=(
                investigation.policy_decision.policy_id
            ),
            executor="cortex",
            status="completed",
            action_results=[
                ActionExecutionResult(
                    action="block_ip",
                    status="completed",
                    message=(
                        "Source IP was blocked."
                    ),
                ),
            ],
        )


class FakeFailingExecutor:
    def __init__(self):
        self.calls = []

    def execute(
        self,
        investigation: InvestigationResponse,
    ) -> ResponseExecutionResult:
        self.calls.append(
            investigation.alert_id
        )

        raise RuntimeError(
            "Cortex execution failed."
        )


def test_allowed_response_executes_and_saves_result():
    store = InMemoryInvestigationStore()
    executor = FakeSuccessfulExecutor()

    investigation = make_investigation(
        response_allowed=True,
        status="ready_for_execution",
    )

    store.save(
        investigation
    )

    result = process_autonomous_response(
        investigation=investigation,
        store=store,
        executor=executor,
        autonomous_response_enabled=True,
    )

    assert executor.calls == [
        "ALT-AUTO-001",
    ]

    assert (
        result["outcome"]
        == "executed"
    )

    stored = store.get(
        "ALT-AUTO-001"
    )

    assert stored is not None

    assert stored.execution_result is not None

    assert (
        stored.execution_result.status
        == "completed"
    )

    assert (
        stored.execution_result.executor
        == "cortex"
    )

    assert (
        store.get_case_by_alert_id(
            "ALT-AUTO-001"
        )
        is None
    )


def test_executor_failure_creates_case():
    store = InMemoryInvestigationStore()
    executor = FakeFailingExecutor()

    investigation = make_investigation(
        response_allowed=True,
        status="ready_for_execution",
    )

    store.save(
        investigation
    )

    result = process_autonomous_response(
        investigation=investigation,
        store=store,
        executor=executor,
        autonomous_response_enabled=True,
    )

    assert executor.calls == [
        "ALT-AUTO-001",
    ]

    assert (
        result["outcome"]
        == "case_created"
    )

    case = store.get_case_by_alert_id(
        "ALT-AUTO-001"
    )

    assert case is not None

    assert case.status == "open"


def test_kill_switch_disabled_creates_case_instead():
    store = InMemoryInvestigationStore()
    executor = FakeSuccessfulExecutor()

    investigation = make_investigation(
        response_allowed=True,
        status="ready_for_execution",
    )

    store.save(
        investigation
    )

    result = process_autonomous_response(
        investigation=investigation,
        store=store,
        executor=executor,
        autonomous_response_enabled=False,
    )

    assert executor.calls == []

    assert (
        result["outcome"]
        == "case_created"
    )

    case = store.get_case_by_alert_id(
        "ALT-AUTO-001"
    )

    assert case is not None


def test_disallowed_response_creates_case_without_executor():
    store = InMemoryInvestigationStore()
    executor = FakeSuccessfulExecutor()

    investigation = make_investigation(
        response_allowed=False,
        status="create_case",
    )

    store.save(
        investigation
    )

    result = process_autonomous_response(
        investigation=investigation,
        store=store,
        executor=executor,
        autonomous_response_enabled=True,
    )

    assert executor.calls == []

    assert (
        result["outcome"]
        == "case_created"
    )

    case = store.get_case_by_alert_id(
        "ALT-AUTO-001"
    )

    assert case is not None


def test_no_action_does_not_execute_or_create_case():
    store = InMemoryInvestigationStore()
    executor = FakeSuccessfulExecutor()

    investigation = make_investigation(
        response_allowed=False,
        status="no_action",
    )

    store.save(
        investigation
    )

    result = process_autonomous_response(
        investigation=investigation,
        store=store,
        executor=executor,
        autonomous_response_enabled=True,
    )

    assert executor.calls == []

    assert (
        result["outcome"]
        == "no_action"
    )

    assert (
        store.get_case_by_alert_id(
            "ALT-AUTO-001"
        )
        is None
    )