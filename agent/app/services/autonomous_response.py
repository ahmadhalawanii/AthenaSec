from typing import Any, Protocol

from app.schemas import (
    InvestigationResponse,
    ResponseExecutionResult,
)
from app.services.case_service import (
    create_case_record,
)
from app.services.investigation_store import (
    InvestigationStore,
)


class ResponseExecutor(Protocol):
    def execute(
        self,
        investigation: InvestigationResponse,
    ) -> ResponseExecutionResult:
        ...


def _create_and_save_case(
    investigation: InvestigationResponse,
    store: InvestigationStore,
    reason: str | None = None,
) -> None:
    case_investigation = investigation

    if (
        investigation.response_plan.status
        != "create_case"
        or reason is not None
    ):
        fallback_reason = (
            reason
            if reason is not None
            else (
                "Autonomous response was not "
                "executed because autonomous "
                "response is disabled."
            )
        )

        fallback_plan = (
            investigation.response_plan.model_copy(
                update={
                    "response_allowed": False,
                    "status": "create_case",
                    "actions": [],
                    "reason": fallback_reason,
                }
            )
        )

        case_investigation = (
            investigation.model_copy(
                update={
                    "response_plan": fallback_plan,
                }
            )
        )

    case = create_case_record(
        case_investigation
    )

    store.save_case(
        case
    )


def process_autonomous_response(
    investigation: InvestigationResponse,
    store: InvestigationStore,
    executor: ResponseExecutor,
    autonomous_response_enabled: bool,
) -> dict[str, Any]:
    response_plan = (
        investigation.response_plan
    )

    if response_plan.status == "no_action":
        return {
            "outcome": "no_action",
        }

    if response_plan.status == "create_case":
        _create_and_save_case(
            investigation,
            store,
        )

        return {
            "outcome": "case_created",
        }

    if (
        response_plan.status
        == "ready_for_execution"
    ):
        if not autonomous_response_enabled:
            _create_and_save_case(
                investigation,
                store,
            )

            return {
                "outcome": "case_created",
            }

        try:
            execution_result = executor.execute(
                investigation
            )
        except Exception as exc:
            _create_and_save_case(
                investigation,
                store,
                reason=(
                    "Autonomous response execution "
                    "failed: "
                    f"{exc}"
                ),
            )

            return {
                "outcome": "case_created",
            }

        store.update_execution_result(
            investigation.alert_id,
            execution_result,
        )

        return {
            "outcome": "executed",
            "execution_result": (
                execution_result
            ),
        }

    raise ValueError(
        "Unsupported response plan status: "
        f"{response_plan.status}"
    )