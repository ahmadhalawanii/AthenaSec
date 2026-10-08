from datetime import datetime
from uuid import (
    NAMESPACE_URL,
    uuid5,
)

from app.schemas import (
    ActionBlastRadius,
    ActionRiskAssessmentRecord,
    ActionRiskContext,
    ProposedActionRecord,
    RiskBand,
)


ACTION_BASE_POINTS = {
    "capture_telemetry": 5,
    "block_ip": 10,
    "lock_account": 45,
}


TARGET_CRITICALITY_POINTS = {
    "low": 0,
    "medium": 5,
    "high": 15,
    "critical": 25,
}


DESTRUCTIVE_CONTAINMENT_ACTIONS = {
    "block_ip",
    "lock_account",
}


def determine_action_risk_band(
    score: int,
) -> RiskBand:
    if score >= 75:
        return "critical"

    if score >= 50:
        return "high"

    if score >= 25:
        return "medium"

    return "low"


def determine_blast_radius(
    *,
    proposed_action: ProposedActionRecord,
    context: ActionRiskContext,
) -> ActionBlastRadius:
    if (
        proposed_action.target_type
        == "network"
    ):
        return "broad"

    if (
        context.affected_target_count
        > 10
    ):
        return "broad"

    if (
        context.affected_target_count
        > 1
    ):
        return "limited"

    if (
        proposed_action.target_type
        in {
            "ip",
            "account",
            "endpoint",
        }
    ):
        return "single"

    return "unknown"


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


def _action_risk_id(
    proposed_action_id: str,
) -> str:
    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-action-risk:"
            f"{proposed_action_id}"
        ),
    )

    return (
        "ARISK-"
        f"{str(value).upper()}"
    )


def assess_action_risk(
    *,
    proposed_action: ProposedActionRecord,
    context: ActionRiskContext,
    assessed_at: datetime,
) -> ActionRiskAssessmentRecord:
    reasons: list[str] = []

    action_type = (
        proposed_action.action_type
    )

    supported_action = (
        action_type
        in ACTION_BASE_POINTS
    )

    if supported_action:
        base_points = (
            ACTION_BASE_POINTS[
                action_type
            ]
        )

        reasons.append(
            (
                "base_action_risk:"
                f"{action_type}:+"
                f"{base_points}"
            )
        )

    else:
        base_points = 70

        reasons.append(
            "unsupported_action:+70"
        )

    score = base_points

    criticality_points = (
        TARGET_CRITICALITY_POINTS[
            context.target_criticality
        ]
    )

    if criticality_points:
        score += criticality_points

        reasons.append(
            (
                "target_criticality:"
                f"{context.target_criticality}"
                f":+{criticality_points}"
            )
        )

    protected_target = (
        context.protected_target
        or context.allowlisted_target
    )

    if protected_target:
        score += 40

        reasons.append(
            (
                "protected_or_allowlisted_"
                "target:+40"
            )
        )

    if context.privileged_target:
        score += 25

        reasons.append(
            "privileged_target:+25"
        )

    blast_radius = (
        determine_blast_radius(
            proposed_action=(
                proposed_action
            ),
            context=context,
        )
    )

    if blast_radius == "limited":
        score += 15

        reasons.append(
            "limited_blast_radius:+15"
        )

    elif blast_radius == "broad":
        score += 35

        reasons.append(
            "broad_blast_radius:+35"
        )

    elif blast_radius == "unknown":
        score += 30

        reasons.append(
            "unknown_blast_radius:+30"
        )

    if (
        action_type
        in DESTRUCTIVE_CONTAINMENT_ACTIONS
    ):
        duration = _duration_minutes(
            proposed_action
        )

        if duration is None:
            score += 30

            reasons.append(
                (
                    "missing_or_invalid_"
                    "duration:+30"
                )
            )

        elif duration > 240:
            score += 20

            reasons.append(
                "long_duration:+20"
            )

        elif duration > 60:
            score += 10

            reasons.append(
                "extended_duration:+10"
            )

        if (
            not proposed_action.reversible
        ):
            score += 25

            reasons.append(
                (
                    "irreversible_containment:"
                    "+25"
                )
            )

    score = min(
        score,
        100,
    )

    requires_approval = (
        score >= 50
        or action_type
        == "lock_account"
        or protected_target
        or context.privileged_target
        or blast_radius
        in {
            "limited",
            "broad",
            "unknown",
        }
        or (
            action_type
            in DESTRUCTIVE_CONTAINMENT_ACTIONS
            and not (
                proposed_action.reversible
            )
        )
        or not supported_action
    )

    return ActionRiskAssessmentRecord(
        action_risk_id=(
            _action_risk_id(
                proposed_action
                .proposed_action_id
            )
        ),
        proposed_action_id=(
            proposed_action
            .proposed_action_id
        ),
        score=score,
        band=(
            determine_action_risk_band(
                score
            )
        ),
        blast_radius=blast_radius,
        reversible=(
            proposed_action.reversible
        ),
        protected_target=(
            protected_target
        ),
        requires_approval=(
            requires_approval
        ),
        reasons=reasons,
        assessed_at=assessed_at,
    )