from collections.abc import Callable

from app.graph.state import (
    InvestigationState,
)
from app.schemas import (
    StructuredResponseProposal,
)
from app.services.response_proposal import (
    validate_response_proposal,
)


ResponseProposer = Callable[
    [str],
    StructuredResponseProposal,
]


def build_response_proposal_context(
    state: InvestigationState,
) -> str:
    analysis = state["analysis"]

    risk = state[
        "risk_assessment"
    ]

    alert = state["alert"]

    lines = [
        "VERIFIED ANALYSIS",
        (
            "classification="
            f"{analysis.classification}"
        ),
        (
            "confidence="
            f"{analysis.confidence}"
        ),
        (
            "summary="
            f"{analysis.summary}"
        ),
        "",
        "INCIDENT RISK",
        (
            "score="
            f"{risk.score}"
        ),
        (
            "band="
            f"{risk.band}"
        ),
        "",
        "GROUNDABLE ALERT METADATA",
    ]

    for key in (
        "source_ip",
        "target_user",
        "agent_id",
        "agent_name",
    ):
        value = alert.metadata.get(
            key
        )

        if value is not None:
            lines.append(
                f"{key}={value}"
            )

    lines.extend(
        [
            "",
            "AVAILABLE EVIDENCE RECORDS",
        ]
    )

    for record in state.get(
        "evidence_records",
        [],
    ):
        lines.append(
            (
                f"[{record.evidence_id}] "
                f"type={record.evidence_type}; "
                f"source={record.source}; "
                f"content={record.content}"
            )
        )

    return "\n".join(
        lines
    )


def make_response_proposal_node(
    proposer: ResponseProposer,
):
    def propose_response(
        state: InvestigationState,
    ) -> InvestigationState:
        verification = state.get(
            "analysis_verification"
        )

        if (
            verification is None
            or not verification.verified
        ):
            return {
                "response_proposal": (
                    StructuredResponseProposal(
                        summary=(
                            "No response action was "
                            "proposed because the "
                            "analysis was not verified."
                        ),
                        actions=[],
                    )
                ),
                "status": (
                    "response_proposal_blocked"
                ),
            }

        context = (
            build_response_proposal_context(
                state
            )
        )

        proposal = proposer(
            context
        )

        validate_response_proposal(
            proposal=proposal,
            state=state,
        )

        return {
            "response_proposal": proposal,
            "status": "response_proposed",
        }

    return propose_response