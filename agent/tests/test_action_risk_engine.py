from datetime import (
    datetime,
    timezone,
)

from app.schemas import (
    ActionRiskContext,
    ProposedActionRecord,
)
from app.services.action_risk_engine import (
    assess_action_risk,
)


ASSESSED_AT = datetime(
    2026,
    10,
    8,
    13,
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
        reason="Contain the threat.",
        proposed_at=ASSESSED_AT,
    )


def test_temporary_single_ip_block_is_low_risk():
    result = assess_action_risk(
        proposed_action=make_action(),
        context=ActionRiskContext(
            target_criticality="low",
        ),
        assessed_at=ASSESSED_AT,
    )

    assert result.score == 10

    assert result.band == "low"

    assert (
        result.blast_radius
        == "single"
    )

    assert result.reversible is True

    assert (
        result.requires_approval
        is False
    )


def test_long_ip_block_increases_action_risk():
    result = assess_action_risk(
        proposed_action=make_action(
            duration_minutes=480,
        ),
        context=ActionRiskContext(
            target_criticality="low",
        ),
        assessed_at=ASSESSED_AT,
    )

    assert result.score == 30

    assert result.band == "medium"

    assert (
        result.requires_approval
        is False
    )

    assert (
        "long_duration:+20"
        in result.reasons
    )


def test_account_lock_requires_approval_even_when_not_privileged():
    result = assess_action_risk(
        proposed_action=make_action(
            action_type="lock_account",
            target_type="account",
            target="analyst",
            duration_minutes=30,
        ),
        context=ActionRiskContext(
            target_criticality="low",
        ),
        assessed_at=ASSESSED_AT,
    )

    assert result.score == 45

    assert result.band == "medium"

    assert (
        result.requires_approval
        is True
    )


def test_privileged_account_lock_is_high_risk():
    result = assess_action_risk(
        proposed_action=make_action(
            action_type="lock_account",
            target_type="account",
            target="root",
            duration_minutes=30,
        ),
        context=ActionRiskContext(
            target_criticality="low",
            privileged_target=True,
        ),
        assessed_at=ASSESSED_AT,
    )

    assert result.score == 70

    assert result.band == "high"

    assert (
        result.requires_approval
        is True
    )

    assert (
        "privileged_target:+25"
        in result.reasons
    )


def test_protected_ip_block_requires_approval():
    result = assess_action_risk(
        proposed_action=make_action(),
        context=ActionRiskContext(
            target_criticality="medium",
            protected_target=True,
        ),
        assessed_at=ASSESSED_AT,
    )

    assert result.score == 55

    assert result.band == "high"

    assert result.protected_target is True

    assert (
        result.requires_approval
        is True
    )


def test_telemetry_capture_can_remain_non_approval():
    result = assess_action_risk(
        proposed_action=make_action(
            action_type=(
                "capture_telemetry"
            ),
            target_type="endpoint",
            target="007",
            duration_minutes=None,
            reversible=False,
        ),
        context=ActionRiskContext(
            target_criticality="critical",
        ),
        assessed_at=ASSESSED_AT,
    )

    assert result.score == 30

    assert result.band == "medium"

    assert (
        result.requires_approval
        is False
    )

    assert result.reversible is False


def test_broad_scope_requires_approval_even_below_score_threshold():
    result = assess_action_risk(
        proposed_action=make_action(),
        context=ActionRiskContext(
            target_criticality="low",
            affected_target_count=25,
        ),
        assessed_at=ASSESSED_AT,
    )

    assert result.score == 45

    assert (
        result.blast_radius
        == "broad"
    )

    assert (
        result.requires_approval
        is True
    )


def test_unsupported_action_fails_safe():
    result = assess_action_risk(
        proposed_action=make_action(
            action_type="run_script",
            target_type="other",
            target="unknown",
            duration_minutes=None,
            reversible=False,
        ),
        context=ActionRiskContext(
            target_criticality="low",
        ),
        assessed_at=ASSESSED_AT,
    )

    assert result.score == 100

    assert result.band == "critical"

    assert (
        result.blast_radius
        == "unknown"
    )

    assert (
        result.requires_approval
        is True
    )

    assert (
        "unsupported_action:+70"
        in result.reasons
    )


def test_action_risk_id_is_deterministic():
    action = make_action()

    context = ActionRiskContext(
        target_criticality="low",
    )

    first = assess_action_risk(
        proposed_action=action,
        context=context,
        assessed_at=ASSESSED_AT,
    )

    second = assess_action_risk(
        proposed_action=action,
        context=context,
        assessed_at=ASSESSED_AT,
    )

    assert (
        first.action_risk_id
        == second.action_risk_id
    )

    assert (
        first.proposed_action_id
        == "PACT-001"
    )