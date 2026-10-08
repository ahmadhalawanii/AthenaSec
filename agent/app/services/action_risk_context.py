from app.graph.state import (
    InvestigationState,
)
from app.schemas import (
    ActionRiskContext,
    ProposedActionRecord,
)


VALID_CRITICALITIES = {
    "low",
    "medium",
    "high",
    "critical",
}


def _normalized(
    value,
) -> str | None:
    if not isinstance(
        value,
        str,
    ):
        return None

    value = value.strip().lower()

    if not value:
        return None

    return value


def build_default_action_risk_context(
    proposed_action: ProposedActionRecord,
    state: InvestigationState,
) -> ActionRiskContext:
    metadata = state[
        "alert"
    ].metadata

    target_criticality = "low"

    if (
        proposed_action.target_type
        in {
            "account",
            "endpoint",
        }
    ):
        configured_criticality = (
            metadata.get(
                "asset_criticality",
                "medium",
            )
        )

        if (
            configured_criticality
            in VALID_CRITICALITIES
        ):
            target_criticality = (
                configured_criticality
            )

        else:
            target_criticality = (
                "medium"
            )

    privileged_target = False

    if (
        proposed_action.target_type
        == "account"
        and bool(
            metadata.get(
                "privileged_target",
                False,
            )
        )
    ):
        target_user = _normalized(
            metadata.get(
                "target_user"
            )
        )

        proposed_target = (
            _normalized(
                proposed_action.target
            )
        )

        privileged_target = (
            target_user is not None
            and proposed_target
            == target_user
        )

    return ActionRiskContext(
        target_criticality=(
            target_criticality
        ),
        protected_target=False,
        allowlisted_target=False,
        privileged_target=(
            privileged_target
        ),
        affected_target_count=1,
    )