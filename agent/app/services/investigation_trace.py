from typing import Any

from app.graph.state import (
    InvestigationState,
)
from app.schemas import (
    InvestigationStepType,
    InvestigationTraceStep,
)


def append_investigation_trace(
    state: InvestigationState,
    *,
    step_type: InvestigationStepType,
    status: str,
    details: dict[str, Any],
) -> list[InvestigationTraceStep]:
    existing = list(
        state.get(
            "investigation_trace",
            [],
        )
    )

    step = InvestigationTraceStep(
        sequence=(
            len(existing) + 1
        ),
        step_type=step_type,
        status=status,
        details=details,
    )

    return [
        *existing,
        step,
    ]