from datetime import datetime
from uuid import (
    NAMESPACE_URL,
    uuid5,
)

from app.schemas import (
    ActionPolicyContent,
    ActionRiskAssessmentRecord,
    IncidentPolicyDecisionRecord,
    PolicyOutcome,
    ProposedActionRecord,
)


from app.services.policy.action_catalogue import (
    AGENT_ACTION_KEYS,
    is_blacklisted,
    target_is_protected,
    whitelist_entry,
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
    admin_policy: ActionPolicyContent | None = None,
    incident_risk: int | None = None,
) -> IncidentPolicyDecisionRecord:
    """Decide whether one proposed action may run, must wait for a person, or is denied.

    admin_policy is the administrator's whitelist and blacklist (action_policy_store).
    When given, it is checked first: blacklisted or unlisted actions are denied, and
    approval-mode actions always wait for a person. Automatic actions then go through
    the deterministic checks below. incident_risk is the investigation's risk score,
    compared with an approval action's minimum risk.
    """
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

    if admin_policy is not None:
        admin_decision = _apply_admin_policy(
            proposed_action=proposed_action,
            action_risk=action_risk,
            decided_at=decided_at,
            admin_policy=admin_policy,
            incident_risk=incident_risk,
        )

        if admin_decision is not None:
            return admin_decision

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

def _apply_admin_policy(
    *,
    proposed_action: ProposedActionRecord,
    action_risk: ActionRiskAssessmentRecord,
    decided_at: datetime,
    admin_policy: ActionPolicyContent,
    incident_risk: int | None,
) -> IncidentPolicyDecisionRecord | None:
    """The administrator's policy. None means the action is whitelisted as automatic."""

    def decide(policy_id, outcome, reason):
        return _decision(
            proposed_action=proposed_action,
            action_risk=action_risk,
            policy_id=policy_id,
            outcome=outcome,
            reason=reason,
            decided_at=decided_at,
        )

    key = AGENT_ACTION_KEYS.get(proposed_action.action_type, proposed_action.action_type)
    duration = _duration_minutes(proposed_action)

    if proposed_action.action_type == "block_ip" and duration is None:
        return decide(
            "POL-ACTION-INTEGRITY-DENY", "NOT_ALLOWED",
            "Temporary block_ip actions must contain a valid duration.",
        )

    if is_blacklisted(admin_policy, key):
        return decide(
            "POL-ADMIN-BLACKLIST", "NOT_ALLOWED",
            f"{key} is on the administrator's blacklist. The agent may never use it.",
        )

    entry = whitelist_entry(admin_policy, key)

    if entry is None:
        return decide(
            "POL-ADMIN-NOT-WHITELISTED", "NOT_ALLOWED",
            f"{key} is not on the administrator's whitelist, so it is denied.",
        )

    if proposed_action.action_type == "block_ip" and target_is_protected(
        proposed_action.target, admin_policy.never_block
    ):
        return decide(
            "POL-ADMIN-PROTECTED-TARGET", "NOT_ALLOWED",
            f"{proposed_action.target} is on the administrator's never-block list.",
        )

    limits = entry.limits

    if limits is not None and limits.max_minutes is not None and duration is not None and (
        duration > limits.max_minutes
    ):
        return decide(
            "POL-ADMIN-LIMIT", "NOT_ALLOWED",
            f"{duration} minutes is longer than the {limits.max_minutes} minutes the "
            f"administrator allows for {key}.",
        )

    if entry.mode != "approval":
        return None

    if limits is not None and incident_risk is not None and incident_risk < limits.min_risk:
        return decide(
            "POL-ADMIN-BELOW-MIN-RISK", "NOT_ALLOWED",
            f"Incident risk {incident_risk} is below the minimum risk of {limits.min_risk} the "
            f"administrator set for {key}.",
        )

    return decide(
        "POL-ADMIN-APPROVAL", "APPROVAL_REQUIRED",
        f"The administrator's response policy requires a person to approve {key}.",
    )
