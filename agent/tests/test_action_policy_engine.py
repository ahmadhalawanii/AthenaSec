from datetime import (
    datetime,
    timezone,
)

from app.schemas import (
    ActionRiskAssessmentRecord,
    ProposedActionRecord,
)
from app.services.action_policy_engine import (
    evaluate_action_policy,
)


DECIDED_AT = datetime(
    2026,
    10,
    8,
    15,
    0,
    tzinfo=timezone.utc,
)


def make_action(
    *,
    action_type: str = "block_ip",
    target_type: str = "ip",
    target: str = "203.0.113.10",
    duration_minutes: int | None = 30,
    reversible: bool = True,
) -> ProposedActionRecord:
    parameters = {}

    if duration_minutes is not None:
        parameters[
            "duration_minutes"
        ] = duration_minutes

    return ProposedActionRecord(
        proposed_action_id="PACT-001",
        incident_id="INC-001",
        investigation_id="INV-001",
        action_type=action_type,
        target_type=target_type,
        target=target,
        parameters=parameters,
        reversible=reversible,
        rollback_action_type=(
            "unblock_ip"
            if (
                action_type
                == "block_ip"
                and reversible
            )
            else (
                "unlock_account"
                if (
                    action_type
                    == "lock_account"
                    and reversible
                )
                else None
            )
        ),
        rollback_parameters={},
        reason="Contain the confirmed threat.",
        proposed_at=DECIDED_AT,
    )


def make_action_risk(
    *,
    proposed_action_id: str = "PACT-001",
    score: int = 10,
    band: str = "low",
    blast_radius: str = "single",
    reversible: bool = True,
    protected_target: bool = False,
    requires_approval: bool = False,
) -> ActionRiskAssessmentRecord:
    return ActionRiskAssessmentRecord(
        action_risk_id="ARISK-001",
        proposed_action_id=(
            proposed_action_id
        ),
        score=score,
        band=band,
        blast_radius=blast_radius,
        reversible=reversible,
        protected_target=(
            protected_target
        ),
        requires_approval=(
            requires_approval
        ),
        reasons=[],
        assessed_at=DECIDED_AT,
    )


def test_low_risk_temporary_ip_block_is_auto_allowed():
    decision = evaluate_action_policy(
        proposed_action=make_action(),
        action_risk=make_action_risk(),
        decided_at=DECIDED_AT,
    )

    assert (
        decision.outcome
        == "AUTO_ALLOWED"
    )

    assert (
        decision.policy_id
        == "POL-ACTION-AUTO"
    )


def test_capture_telemetry_can_be_auto_allowed():
    decision = evaluate_action_policy(
        proposed_action=make_action(
            action_type="capture_telemetry",
            target_type="endpoint",
            target="007",
            duration_minutes=None,
            reversible=False,
        ),
        action_risk=make_action_risk(
            score=20,
            band="low",
            reversible=False,
        ),
        decided_at=DECIDED_AT,
    )

    assert (
        decision.outcome
        == "AUTO_ALLOWED"
    )


def test_account_lock_requires_human_approval():
    decision = evaluate_action_policy(
        proposed_action=make_action(
            action_type="lock_account",
            target_type="account",
            target="analyst",
        ),
        action_risk=make_action_risk(
            score=45,
            band="medium",
            requires_approval=True,
        ),
        decided_at=DECIDED_AT,
    )

    assert (
        decision.outcome
        == "APPROVAL_REQUIRED"
    )

    assert (
        decision.policy_id
        == "POL-ACTION-HUMAN-APPROVAL"
    )


def test_high_action_risk_requires_approval():
    decision = evaluate_action_policy(
        proposed_action=make_action(),
        action_risk=make_action_risk(
            score=60,
            band="high",
            requires_approval=True,
        ),
        decided_at=DECIDED_AT,
    )

    assert (
        decision.outcome
        == "APPROVAL_REQUIRED"
    )


def test_long_ip_block_requires_approval():
    decision = evaluate_action_policy(
        proposed_action=make_action(
            duration_minutes=480,
        ),
        action_risk=make_action_risk(
            score=30,
            band="medium",
        ),
        decided_at=DECIDED_AT,
    )

    assert (
        decision.outcome
        == "APPROVAL_REQUIRED"
    )

    assert (
        "duration"
        in decision.reason.lower()
    )


def test_protected_target_is_not_allowed():
    decision = evaluate_action_policy(
        proposed_action=make_action(),
        action_risk=make_action_risk(
            score=55,
            band="high",
            protected_target=True,
            requires_approval=True,
        ),
        decided_at=DECIDED_AT,
    )

    assert (
        decision.outcome
        == "NOT_ALLOWED"
    )

    assert (
        decision.policy_id
        == "POL-ACTION-PROTECTED-TARGET"
    )


def test_unsupported_action_is_not_allowed():
    decision = evaluate_action_policy(
        proposed_action=make_action(
            action_type="run_script",
            target_type="other",
            target="unknown",
            duration_minutes=None,
            reversible=False,
        ),
        action_risk=make_action_risk(
            score=100,
            band="critical",
            blast_radius="unknown",
            reversible=False,
            requires_approval=True,
        ),
        decided_at=DECIDED_AT,
    )

    assert (
        decision.outcome
        == "NOT_ALLOWED"
    )

    assert (
        decision.policy_id
        == "POL-ACTION-UNSUPPORTED"
    )


def test_mismatched_action_risk_identity_fails_closed():
    decision = evaluate_action_policy(
        proposed_action=make_action(),
        action_risk=make_action_risk(
            proposed_action_id=(
                "PACT-OTHER"
            ),
        ),
        decided_at=DECIDED_AT,
    )

    assert (
        decision.outcome
        == "NOT_ALLOWED"
    )

    assert (
        decision.policy_id
        == "POL-ACTION-INTEGRITY-DENY"
    )


def test_policy_decision_id_is_deterministic():
    action = make_action()

    action_risk = (
        make_action_risk()
    )

    first = evaluate_action_policy(
        proposed_action=action,
        action_risk=action_risk,
        decided_at=DECIDED_AT,
    )

    second = evaluate_action_policy(
        proposed_action=action,
        action_risk=action_risk,
        decided_at=DECIDED_AT,
    )

    assert (
        first.decision_id
        == second.decision_id
    )

    assert (
        first.incident_id
        == "INC-001"
    )

    assert (
        first.proposed_action_id
        == "PACT-001"
    )
