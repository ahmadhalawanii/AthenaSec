import ipaddress
from typing import Protocol

from app.schemas import (
    ProposedActionRecord,
)
from app.services.structured_execution import (
    StructuredExecutorResult,
)


class CortexBlockIpClient(
    Protocol
):
    responder_id: str

    def run_responder(
        self,
        action: str,
        target: str,
    ) -> dict:
        ...


class CortexStructuredActionExecutor:
    def __init__(
        self,
        *,
        client: CortexBlockIpClient,
    ):
        self.client = client

    def _validate_block_ip(
        self,
        proposed_action: (
            ProposedActionRecord
        ),
    ) -> int:
        if (
            proposed_action.target_type
            != "ip"
        ):
            raise ValueError(
                "block_ip target_type "
                "must be ip."
            )

        target = (
            proposed_action.target
        )

        if (
            target != target.strip()
        ):
            raise ValueError(
                "block_ip target must "
                "be a valid IP address."
            )

        try:
            ipaddress.ip_address(
                target
            )

        except ValueError as exc:
            raise ValueError(
                "block_ip target must "
                "be a valid IP address."
            ) from exc

        parameters = (
            proposed_action.parameters
        )

        if (
            set(parameters)
            != {
                "duration_minutes",
            }
        ):
            raise ValueError(
                "block_ip parameters "
                "must contain exactly "
                "duration_minutes."
            )

        duration_minutes = (
            parameters[
                "duration_minutes"
            ]
        )

        if (
            isinstance(
                duration_minutes,
                bool,
            )
            or not isinstance(
                duration_minutes,
                int,
            )
            or duration_minutes < 1
            or duration_minutes > 1440
        ):
            raise ValueError(
                "block_ip parameters "
                "contain an invalid "
                "duration_minutes value."
            )

        if (
            not proposed_action.reversible
            or (
                proposed_action
                .rollback_action_type
                != "unblock_ip"
            )
            or (
                proposed_action
                .rollback_parameters
                != {}
            )
        ):
            raise ValueError(
                "block_ip rollback "
                "contract is invalid."
            )

        return duration_minutes

    def execute(
        self,
        proposed_action: (
            ProposedActionRecord
        ),
    ) -> StructuredExecutorResult:
        if (
            proposed_action.action_type
            != "block_ip"
        ):
            raise ValueError(
                "Cortex responder for "
                f"{proposed_action.action_type} "
                "is not configured."
            )

        duration_minutes = (
            self._validate_block_ip(
                proposed_action
            )
        )

        cortex_result = (
            self.client.run_responder(
                action="block_ip",
                target=(
                    proposed_action.target
                ),
            )
        )

        message = (
            cortex_result.get(
                "full",
                {},
            ).get(
                "message"
            )
        )

        if (
            not isinstance(
                message,
                str,
            )
            or not message.strip()
        ):
            message = (
                "Cortex completed "
                "block_ip for "
                f"{proposed_action.target}."
            )

        return StructuredExecutorResult(
            message=message,
            details={
                "action_type": (
                    proposed_action
                    .action_type
                ),
                "target_type": (
                    proposed_action
                    .target_type
                ),
                "target": (
                    proposed_action
                    .target
                ),
                "parameters": {
                    "duration_minutes": (
                        duration_minutes
                    ),
                },
                "responder_id": (
                    self.client
                    .responder_id
                ),
                "cortex_result": (
                    cortex_result
                ),
            },
        )

class CortexStructuredRollbackExecutor:
    def __init__(
        self,
        *,
        client: CortexBlockIpClient,
    ):
        self.client = client

    def rollback(
        self,
        proposed_action: (
            ProposedActionRecord
        ),
    ) -> StructuredExecutorResult:
        if (
            proposed_action.action_type
            != "block_ip"
            or not proposed_action.reversible
            or proposed_action
            .rollback_action_type
            != "unblock_ip"
            or proposed_action
            .rollback_parameters
            != {}
        ):
            raise ValueError(
                "block_ip rollback "
                "contract is invalid."
            )

        if (
            proposed_action.target_type
            != "ip"
        ):
            raise ValueError(
                "Rollback target_type "
                "must be ip."
            )

        try:
            ipaddress.ip_address(
                proposed_action.target
            )

        except ValueError as exc:
            raise ValueError(
                "Rollback target must "
                "be a valid IP address."
            ) from exc

        cortex_result = (
            self.client.run_responder(
                action="unblock_ip",
                target=(
                    proposed_action.target
                ),
            )
        )

        message = (
            cortex_result.get(
                "full",
                {},
            ).get(
                "message"
            )
        )

        if (
            not isinstance(
                message,
                str,
            )
            or not message.strip()
        ):
            message = (
                "Cortex completed "
                "unblock_ip for "
                f"{proposed_action.target}."
            )

        return StructuredExecutorResult(
            message=message,
            details={
                "action_type": (
                    "unblock_ip"
                ),
                "target": (
                    proposed_action.target
                ),
                "responder_id": (
                    self.client
                    .responder_id
                ),
                "cortex_result": (
                    cortex_result
                ),
            },
        )
