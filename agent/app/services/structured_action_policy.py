from datetime import (
    datetime,
    timezone,
)
from uuid import (
    NAMESPACE_URL,
    uuid5,
)

from app.schemas import (
    IncidentCaseRecord,
    InvestigationResponse,
    PolicyDecision,
    ResponsePlan,
)
from app.services.incident_response_store import (
    IncidentResponseStore,
)


STRUCTURED_POLICY_ID = (
    "POL-STRUCTURED-ACTION-V2"
)


def apply_structured_action_policy(
    investigation: InvestigationResponse,
) -> InvestigationResponse:
    if (
        investigation.response_proposal
        is None
    ):
        return investigation

    decisions = list(
        investigation
        .action_policy_decisions
    )

    outcomes = {
        decision.outcome
        for decision in decisions
    }

    if "NOT_ALLOWED" in outcomes:
        status = "create_case"

        reason = (
            "At least one structured "
            "response action was denied "
            "by deterministic action "
            "policy."
        )

    elif (
        "APPROVAL_REQUIRED"
        in outcomes
    ):
        status = "awaiting_approval"

        reason = (
            "At least one structured "
            "response action requires "
            "exact-action human approval."
        )

    elif (
        decisions
        and outcomes
        == {
            "AUTO_ALLOWED",
        }
    ):
        status = (
            "ready_for_structured_execution"
        )

        reason = (
            "Structured response actions "
            "were automatically authorized "
            "by deterministic action policy. "
            "Execution remains on the "
            "structured Cortex path."
        )

    elif not decisions:
        status = "no_action"

        reason = (
            "No structured response action "
            "was eligible for policy "
            "evaluation."
        )

    else:
        status = "create_case"

        reason = (
            "Structured response policy "
            "state was inconsistent and "
            "was denied fail-closed."
        )

    legacy_policy = PolicyDecision(
        policy_id=(
            STRUCTURED_POLICY_ID
        ),
        policy_name=(
            "Structured Action Policy"
        ),
        matched=bool(
            decisions
        ),
        response_allowed=False,
        actions=[],
        reason=reason,
    )

    response_plan = ResponsePlan(
        policy_id=(
            STRUCTURED_POLICY_ID
        ),
        actions=[],
        response_allowed=False,
        status=status,
        reason=reason,
    )

    return investigation.model_copy(
        update={
            "policy_decision": (
                legacy_policy
            ),
            "response_plan": (
                response_plan
            ),
        }
    )


def _case_id(
    investigation: InvestigationResponse,
) -> str:
    denied_ids = sorted(
        decision.decision_id
        for decision
        in investigation
        .action_policy_decisions
        if (
            decision.outcome
            == "NOT_ALLOWED"
        )
    )

    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-policy-case:"
            f"{investigation.incident_id}:"
            f"{investigation.investigation_id}:"
            + ",".join(
                denied_ids
            )
        ),
    )

    return (
        "CASE-"
        f"{str(value).upper()}"
    )


def process_structured_policy_outcomes(
    *,
    investigation: InvestigationResponse,
    store: IncidentResponseStore,
    now: datetime | None = None,
) -> dict[str, object]:
    if (
        investigation.response_proposal
        is None
    ):
        return {
            "outcome": "legacy",
        }

    decisions = list(
        investigation
        .action_policy_decisions
    )

    denied = [
        decision
        for decision in decisions
        if (
            decision.outcome
            == "NOT_ALLOWED"
        )
    ]

    if denied:
        if (
            investigation.incident_id
            is None
            or investigation
            .investigation_id
            is None
        ):
            raise ValueError(
                "A denied structured action "
                "requires incident and "
                "investigation identity."
            )

        if now is None:
            now = datetime.now(
                timezone.utc
            )

        reason = "; ".join(
            decision.reason
            for decision in denied
        )

        case = IncidentCaseRecord(
            case_id=(
                _case_id(
                    investigation
                )
            ),
            incident_id=(
                investigation.incident_id
            ),
            investigation_id=(
                investigation
                .investigation_id
            ),
            policy_decision_id=(
                denied[0].decision_id
            ),
            status="open",
            reason=reason,
            created_at=now,
            updated_at=now,
        )

        store.save_incident_case(
            case
        )

        return {
            "outcome": "case_created",
            "case": case,
        }

    if any(
        decision.outcome
        == "APPROVAL_REQUIRED"
        for decision in decisions
    ):
        return {
            "outcome": (
                "awaiting_approval"
            ),
        }

    if any(
        decision.outcome
        == "AUTO_ALLOWED"
        for decision in decisions
    ):
        return {
            "outcome": (
                "auto_allowed"
            ),
        }

    return {
        "outcome": "no_action",
    }
