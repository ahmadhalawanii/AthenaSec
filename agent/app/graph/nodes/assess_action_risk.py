from collections.abc import Callable
from datetime import (
    datetime,
    timezone,
)

from app.graph.state import (
    InvestigationState,
)
from app.schemas import (
    ActionRiskContext,
    ProposedActionRecord,
)
from app.services.action_risk_context import (
    build_default_action_risk_context,
)
from app.services.action_risk_engine import (
    assess_action_risk,
)
from app.services.response_proposal import (
    build_proposed_action_records,
)


ActionRiskContextProvider = Callable[
    [
        ProposedActionRecord,
        InvestigationState,
    ],
    ActionRiskContext,
]


Clock = Callable[
    [],
    datetime,
]


def _utc_now() -> datetime:
    return datetime.now(
        timezone.utc
    )


def make_action_risk_node(
    *,
    context_provider: (
        ActionRiskContextProvider
    ) = (
        build_default_action_risk_context
    ),
    clock: Clock = _utc_now,
):
    def assess_response_actions(
        state: InvestigationState,
    ) -> InvestigationState:
        proposal = state.get(
            "response_proposal"
        )

        if proposal is None:
            return {
                "proposed_actions": [],
                "action_risk_assessments": [],
                "status": (
                    "action_risk_assessed"
                ),
            }

        incident_id = state.get(
            "incident_id"
        )

        investigation_id = (
            state.get(
                "investigation_id"
            )
        )

        if (
            not incident_id
            or not investigation_id
        ):
            return {
                "proposed_actions": [],
                "action_risk_assessments": [],
                "status": (
                    "action_risk_assessed"
                ),
            }

        assessed_at = clock()

        proposed_actions = (
            build_proposed_action_records(
                proposal=proposal,
                incident_id=incident_id,
                investigation_id=(
                    investigation_id
                ),
                proposed_at=(
                    assessed_at
                ),
            )
        )

        action_risks = []

        for proposed_action in (
            proposed_actions
        ):
            context = (
                context_provider(
                    proposed_action,
                    state,
                )
            )

            action_risks.append(
                assess_action_risk(
                    proposed_action=(
                        proposed_action
                    ),
                    context=context,
                    assessed_at=(
                        assessed_at
                    ),
                )
            )

        return {
            "proposed_actions": (
                proposed_actions
            ),
            "action_risk_assessments": (
                action_risks
            ),
            "status": (
                "action_risk_assessed"
            ),
        }

    return assess_response_actions