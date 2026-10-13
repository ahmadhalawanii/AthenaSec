from datetime import datetime
from uuid import (
    NAMESPACE_URL,
    uuid5,
)

from app.schemas import (
    ActionRiskAssessmentRecord,
    IncidentPolicyDecisionRecord,
    PolicyOutcome,
    ProposedActionRecord,
)


SUPPORTED_ACTIONS = {
    "block_ip",
    "lock_account",
    "capture_telemetry",
}


MAX_AUTO_BLOCK_DURATION_MINUTES = 240


def _decision_id(
    *,
    proposed_action_id: str,
    action_risk_id: str,
    policy_id: str,
) -> str:
    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-action-policy:"
            f"{proposed_action_id}:"
            f"{action_risk_id}:"
            f"{policy_id}"
        ),
    )

    return (
        "PDEC-"
        f"{str(value).upper()}"
    )


def _decision(
    *,
    proposed_action: ProposedActionRecord,
    action_risk: ActionRiskAssessmentRecord,
    policy_id: str,
    outcome: PolicyOutcome,
    reason: str,
    decided_at: datetime,
) -> IncidentPolicyDecisionRecord:
    return IncidentPolicyDecisionRecord(
        decision_id=(
            _decision_id(
                proposed_action_id=(
                    proposed_action
                    .proposed_action_id
                ),
                action_risk_id=(
                    action_risk
                    .action_risk_id
                ),
                policy_id=policy_id,
            )
        ),
        incident_id=(
            proposed_action.incident_id
        ),
        proposed_action_id=(
            proposed_action
            .proposed_action_id
        ),
        policy_id=policy_id,
        outcome=outcome,
        reason=reason,
        decided_at=decided_at,
    )


def _duration_minutes(
    proposed_action: ProposedActionRecord,
) -> int | None:
    value = (
        proposed_action.parameters.get(
            "duration_minutes"
        )
    )

    if isinstance(
        value,
        bool,
    ):
        return None

    if not isinstance(
        value,
        int,
    ):
        return None

    if value < 1:
        return None

    return value


def evaluate_action_policy(
    *,
    proposed_action: ProposedActionRecord,
    action_risk: ActionRiskAssessmentRecord,
    decided_at: datetime,
) -> IncidentPolicyDecisionRecord:
    if (
        action_risk.proposed_action_id
        != proposed_action.proposed_action_id
    ):
        return _decision(
            proposed_action=proposed_action,
            action_risk=action_risk,
            policy_id=(
                "POL-ACTION-INTEGRITY-DENY"
            ),
            outcome="NOT_ALLOWED",
            reason=(
                "Action-risk assessment does "
                "not belong to the proposed "
                "action. Execution is denied."
            ),
            decided_at=decided_at,
        )

    if (
        proposed_action.action_type
        not in SUPPORTED_ACTIONS
    ):
        return _decision(
            proposed_action=proposed_action,
            action_risk=action_risk,
            policy_id=(
                "POL-ACTION-UNSUPPORTED"
            ),
            outcome="NOT_ALLOWED",
            reason=(
                "The proposed action type is "
                "not supported by AthenaSec."
            ),
            decided_at=decided_at,
        )

    if action_risk.protected_target:
        return _decision(
            proposed_action=proposed_action,
            action_risk=action_risk,
            policy_id=(
                "POL-ACTION-PROTECTED-TARGET"
            ),
            outcome="NOT_ALLOWED",
            reason=(
                "The proposed action targets "
                "a protected or allowlisted "
                "resource."
            ),
            decided_at=decided_at,
        )

    if (
        proposed_action.action_type
        == "block_ip"
    ):
        duration = _duration_minutes(
            proposed_action
        )

        if duration is None:
            return _decision(
                proposed_action=(
                    proposed_action
                ),
                action_risk=action_risk,
                policy_id=(
                    "POL-ACTION-INTEGRITY-DENY"
                ),
                outcome="NOT_ALLOWED",
                reason=(
                    "Temporary block_ip actions "
                    "must contain a valid "
                    "duration."
                ),
                decided_at=decided_at,
            )

        if (
            duration
            > MAX_AUTO_BLOCK_DURATION_MINUTES
        ):
            return _decision(
                proposed_action=(
                    proposed_action
                ),
                action_risk=action_risk,
                policy_id=(
                    "POL-ACTION-HUMAN-APPROVAL"
                ),
                outcome=(
                    "APPROVAL_REQUIRED"
                ),
                reason=(
                    "The block duration exceeds "
                    "the automatic containment "
                    "duration limit."
                ),
                decided_at=decided_at,
            )

    if (
        proposed_action.action_type
        == "lock_account"
    ):
        return _decision(
            proposed_action=proposed_action,
            action_risk=action_risk,
            policy_id=(
                "POL-ACTION-HUMAN-APPROVAL"
            ),
            outcome="APPROVAL_REQUIRED",
            reason=(
                "Account lock actions require "
                "explicit human approval."
            ),
            decided_at=decided_at,
        )

    high_impact = (
        action_risk.requires_approval
        or action_risk.score >= 50
        or action_risk.blast_radius
        in {
            "limited",
            "broad",
            "unknown",
        }
    )

    if high_impact:
        return _decision(
            proposed_action=proposed_action,
            action_risk=action_risk,
            policy_id=(
                "POL-ACTION-HUMAN-APPROVAL"
            ),
            outcome="APPROVAL_REQUIRED",
            reason=(
                "The deterministic Action Risk "
                "Engine classified this action "
                "as requiring human approval."
            ),
            decided_at=decided_at,
        )

    return _decision(
        proposed_action=proposed_action,
        action_risk=action_risk,
        policy_id="POL-ACTION-AUTO",
        outcome="AUTO_ALLOWED",
        reason=(
            "The action is bounded, supported, "
            "not protected, and below the "
            "human-approval action-risk "
            "threshold."
        ),
        decided_at=decided_at,
    )
