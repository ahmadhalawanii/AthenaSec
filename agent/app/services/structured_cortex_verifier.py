import ipaddress
from typing import Protocol

from app.schemas import (
    ActionExecutionResultRecord,
    ProposedActionRecord,
)
from app.services.action_verification import (
    StructuredVerificationObservation,
)


class CortexVerificationClient(
    Protocol
):
    responder_id: str

    def run_responder(
        self,
        action: str,
        target: str,
    ) -> dict:
        ...


class CortexBlockIpStateVerifier:
    def __init__(
        self,
        *,
        client: CortexVerificationClient,
    ):
        self.client = client

    def verify(
        self,
        proposed_action: (
            ProposedActionRecord
        ),
        action_result: (
            ActionExecutionResultRecord
        ),
    ) -> (
        StructuredVerificationObservation
    ):
        if (
            proposed_action.action_type
            != "block_ip"
        ):
            raise ValueError(
                "Cortex block verifier "
                "only supports block_ip."
            )

        if (
            proposed_action.target_type
            != "ip"
        ):
            raise ValueError(
                "block_ip verification "
                "target_type must be ip."
            )

        try:
            ipaddress.ip_address(
                proposed_action.target
            )

        except ValueError as exc:
            raise ValueError(
                "block_ip verification "
                "target must be a valid "
                "IP address."
            ) from exc

        payload = (
            self.client.run_responder(
                action="verify_block_ip",
                target=(
                    proposed_action.target
                ),
            )
        )

        full = payload.get(
            "full"
        )

        if not isinstance(
            full,
            dict,
        ):
            raise RuntimeError(
                "Cortex verification "
                "response is missing "
                "structured full data."
            )

        reported_target = (
            full.get(
                "target"
            )
        )

        if (
            reported_target
            != proposed_action.target
        ):
            raise RuntimeError(
                "Cortex verification "
                "target does not match "
                "the authorized target."
            )

        blocked = full.get(
            "blocked"
        )

        if not isinstance(
            blocked,
            bool,
        ):
            raise RuntimeError(
                "Cortex verification "
                "response must contain "
                "a boolean blocked state."
            )

        if blocked:
            status = "SUCCESS"

            message = (
                "The authorized IP block "
                "was independently verified."
            )

        else:
            status = "FAILED"

            message = (
                "The authorized IP block "
                "was not present during "
                "post-action verification."
            )

        return (
            StructuredVerificationObservation(
                status=status,
                message=message,
                details={
                    "target": (
                        proposed_action.target
                    ),
                    "blocked": blocked,
                    "responder_id": (
                        self.client
                        .responder_id
                    ),
                    "action_result_id": (
                        action_result
                        .action_result_id
                    ),
                    "verification_source": (
                        "cortex_read_only_responder"
                    ),
                },
            )
        )

    def verify_unblocked(
        self,
        target: str,
    ) -> StructuredVerificationObservation:
        if (
            not isinstance(target, str)
            or target != target.strip()
        ):
            raise ValueError(
                "Unblock verification target "
                "must be a valid IP address."
            )

        try:
            ipaddress.ip_address(target)

        except ValueError as exc:
            raise ValueError(
                "Unblock verification target "
                "must be a valid IP address."
            ) from exc

        payload = self.client.run_responder(
            action="verify_block_ip",
            target=target,
        )

        if (
            not isinstance(payload, dict)
            or payload.get("success") is not True
        ):
            raise RuntimeError(
                "Cortex unblock verification "
                "responder reported failure."
            )

        full = payload.get("full")

        if not isinstance(full, dict):
            raise RuntimeError(
                "Cortex unblock verification "
                "is missing structured full data."
            )

        if full.get("target") != target:
            raise RuntimeError(
                "Cortex unblock verification "
                "target does not match."
            )

        blocked = full.get("blocked")

        if not isinstance(blocked, bool):
            raise RuntimeError(
                "Cortex unblock verification "
                "requires a boolean blocked state."
            )

        if blocked:
            return StructuredVerificationObservation(
                status="FAILED",
                message=(
                    "The temporary IP block "
                    "is still present."
                ),
                details={
                    "target": target,
                    "blocked": True,
                    "verification_source": (
                        "cortex_read_only_responder"
                    ),
                },
            )

        return StructuredVerificationObservation(
            status="SUCCESS",
            message=(
                "The temporary IP block "
                "is confirmed absent."
            ),
            details={
                "target": target,
                "blocked": False,
                "verification_source": (
                    "cortex_read_only_responder"
                ),
            },
        )
