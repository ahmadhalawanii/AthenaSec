from dataclasses import dataclass
from typing import Literal


ResponseMode = Literal[
    "SHADOW",
    "SUPERVISED",
    "AUTONOMOUS",
]


VALID_RESPONSE_MODES = {
    "SHADOW",
    "SUPERVISED",
    "AUTONOMOUS",
}


@dataclass(
    frozen=True,
)
class ResponseModeDecision:
    mode: ResponseMode

    cortex_execution_allowed: bool

    reason: str


def normalize_response_mode(
    value: str | None,
) -> ResponseMode:
    if value is None:
        return "SUPERVISED"

    normalized = (
        value.strip().upper()
    )

    if normalized not in (
        VALID_RESPONSE_MODES
    ):
        raise ValueError(
            "AthenaSec response mode "
            "must be SHADOW, SUPERVISED, "
            "or AUTONOMOUS."
        )

    return normalized


def evaluate_response_mode(
    mode: ResponseMode,
) -> ResponseModeDecision:
    if mode == "SHADOW":
        return ResponseModeDecision(
            mode=mode,
            cortex_execution_allowed=False,
            reason=(
                "SHADOW mode records the "
                "deterministic response "
                "decision but does not "
                "execute Cortex actions."
            ),
        )

    return ResponseModeDecision(
        mode=mode,
        cortex_execution_allowed=True,
        reason=(
            "The configured runtime mode "
            "permits Cortex execution when "
            "deterministic policy and the "
            "global kill switch authorize it."
        ),
    )