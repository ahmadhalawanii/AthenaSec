from uuid import (
    NAMESPACE_URL,
    uuid5,
)

from app.schemas import (
    CaseRecord,
    InvestigationResponse,
)


def _build_case_id(
    alert_id: str,
) -> str:
    case_uuid = uuid5(
        NAMESPACE_URL,
        f"athenasec-case:{alert_id}",
    )

    return (
        "CASE-"
        f"{str(case_uuid).upper()}"
    )


def create_case_record(
    investigation: InvestigationResponse,
) -> CaseRecord:
    response_plan = investigation.response_plan

    if (
        response_plan.response_allowed
        or response_plan.status != "create_case"
    ):
        raise ValueError(
            "Investigation does not require case creation."
        )

    return CaseRecord(
        case_id=_build_case_id(
            investigation.alert_id
        ),
        alert_id=investigation.alert_id,
        policy_id=(
            investigation.policy_decision.policy_id
        ),
        classification=(
            investigation.analysis.classification
        ),
        risk_score=(
            investigation.risk_assessment.score
        ),
        risk_band=(
            investigation.risk_assessment.band
        ),
        status="open",
        reason=response_plan.reason,
    )