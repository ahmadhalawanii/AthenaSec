from typing import Protocol

from app.schemas import (
    ActionExecutionResult,
    InvestigationResponse,
    ResponseExecutionResult,
)


class CortexClient(Protocol):
    responder_id: str

    def run_responder(
        self,
        action: str,
        target: str,
    ) -> dict:
        ...


class CortexResponseExecutor:
    def __init__(
        self,
        client: CortexClient,
    ):
        self.client = client

    def _execute_block_ip(
        self,
        investigation: InvestigationResponse,
    ) -> ActionExecutionResult:
        source_ip = investigation.alert_metadata.get(
            "source_ip"
        )

        if not isinstance(
            source_ip,
            str,
        ) or not source_ip.strip():
            raise ValueError(
                "Cannot execute block_ip because "
                "alert_metadata does not contain "
                "a valid source_ip."
            )

        cortex_result = self.client.run_responder(
            action="block_ip",
            target=source_ip,
        )

        message = (
            cortex_result.get(
                "full",
                {},
            ).get(
                "message"
            )
        )

        if not isinstance(
            message,
            str,
        ) or not message.strip():
            message = (
                f"Cortex completed block_ip "
                f"for {source_ip}."
            )

        return ActionExecutionResult(
            action="block_ip",
            status="completed",
            message=message,
            details={
                "target": source_ip,
                "responder_id": (
                    self.client.responder_id
                ),
                "cortex_result": cortex_result,
            },
        )

    def execute(
        self,
        investigation: InvestigationResponse,
    ) -> ResponseExecutionResult:
        response_plan = (
            investigation.response_plan
        )

        if (
            not response_plan.response_allowed
            or response_plan.status
            != "ready_for_execution"
        ):
            raise ValueError(
                "Investigation is not authorized "
                "for autonomous execution."
            )

        action_results = []

        for action in response_plan.actions:
            if action == "block_ip":
                action_results.append(
                    self._execute_block_ip(
                        investigation
                    )
                )

            else:
                raise ValueError(
                    "Unsupported Cortex action: "
                    f"{action}"
                )

        return ResponseExecutionResult(
            policy_id=(
                investigation.policy_decision.policy_id
            ),
            executor="cortex",
            status="completed",
            action_results=action_results,
        )