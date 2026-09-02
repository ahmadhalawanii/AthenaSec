from app.schemas import (
    AlertAnalysis,
    EvidenceRecord,
    InvestigationResponse,
    PolicyDecision,
    ResponsePlan,
    RiskAssessment,
)
from app.services.cortex_executor import (
    CortexResponseExecutor,
)


class FakeCortexClient:
    def __init__(self):
        self.calls = []
        self.responder_id = "BlockIp_1_0"

    def run_responder(
        self,
        action: str,
        target: str,
    ) -> dict:
        self.calls.append(
            (
                action,
                target,
            )
        )

        return {
            "success": True,
            "full": {
                "message": (
                    "IP successfully blocked "
                    "by Cortex responder."
                ),
            },
            "operations": [],
        }

def make_investigation(
    source_ip: str | None = (
        "203.0.113.50"
    ),
) -> InvestigationResponse:
    metadata = {
        "target_user": "root",
        "failed_attempts": 148,
    }

    if source_ip is not None:
        metadata[
            "source_ip"
        ] = source_ip

    return InvestigationResponse(
        alert_id="ALT-CORTEX-001",
        source="wazuh",
        alert_metadata=metadata,
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
                    "Critical SSH brute force "
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
            response_allowed=True,
            actions=[
                "block_ip",
            ],
            reason=(
                "Critical threshold reached."
            ),
        ),
        response_plan=ResponsePlan(
            policy_id="POL-BF-CRITICAL",
            actions=[
                "block_ip",
            ],
            response_allowed=True,
            status="ready_for_execution",
            reason=(
                "Critical threshold reached."
            ),
        ),
        investigation_iteration=1,
    )


def test_cortex_executor_blocks_grounded_source_ip():
    client = FakeCortexClient()

    executor = CortexResponseExecutor(
        client=client
    )

    investigation = make_investigation()

    result = executor.execute(
        investigation
    )

    assert client.calls == [
        (
            "block_ip",
            "203.0.113.50",
        ),
    ]

    assert result.executor == "cortex"

    assert result.status == "completed"

    assert len(
        result.action_results
    ) == 1

    assert (
        result.action_results[0].action
        == "block_ip"
    )

    assert (
        result.action_results[0].status
        == "completed"
    )

    assert (
        result.action_results[0].message
        == (
            "IP successfully blocked "
            "by Cortex responder."
        )
    )
    assert (
        result.action_results[0].details[
            "target"
        ]
        == "203.0.113.50"
    )

    assert (
        result.action_results[0].details[
            "responder_id"
        ]
        == "BlockIp_1_0"
    )

    assert (
        result.action_results[0].details[
            "cortex_result"
        ]["success"]
        is True
    )


def test_cortex_executor_rejects_missing_source_ip():
    client = FakeCortexClient()

    executor = CortexResponseExecutor(
        client=client
    )

    investigation = make_investigation(
        source_ip=None
    )

    try:
        executor.execute(
            investigation
        )

        assert False, (
            "Expected missing source_ip "
            "to be rejected."
        )

    except ValueError as exc:
        assert (
            "source_ip"
            in str(exc)
        )

    assert client.calls == []