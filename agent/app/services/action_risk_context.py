from app.graph.state import (
    InvestigationState,
)
from app.schemas import (
    ActionRiskContext,
    ProposedActionRecord,
)
from app.services.target_protection import (
    TargetProtectionRegistry,
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
    *,
    target_protection_registry: (
        TargetProtectionRegistry | None
    ) = None,
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

    protected_target = False
    allowlisted_target = False

    if (
        target_protection_registry
        is not None
    ):
        observation = (
            target_protection_registry
            .inspect(
                target_type=(
                    proposed_action
                    .target_type
                ),
                target=(
                    proposed_action.target
                ),
            )
        )

        protected_target = (
            observation.protected_target
        )

        allowlisted_target = (
            observation.allowlisted_target
        )

    return ActionRiskContext(
        target_criticality=(
            target_criticality
        ),
        protected_target=(
            protected_target
        ),
        allowlisted_target=(
            allowlisted_target
        ),
        privileged_target=(
            privileged_target
        ),
        affected_target_count=1,
    )


def make_action_risk_context_provider(
    target_protection_registry: (
        TargetProtectionRegistry
    ),
):
    def provider(
        proposed_action,
        state,
    ):
        return (
            build_default_action_risk_context(
                proposed_action,
                state,
                target_protection_registry=(
                    target_protection_registry
                ),
            )
        )

    return provider