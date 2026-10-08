from dataclasses import dataclass
from datetime import (
    datetime,
    timezone,
)
from uuid import (
    NAMESPACE_URL,
    uuid5,
)

from app.schemas import (
    ActionRiskAssessmentRecord,
    IncidentRiskAssessmentRecord,
    InvestigationResponse,
    ProposedActionRecord,
)
from app.services.incident_response_store import (
    IncidentResponseStore,
)


@dataclass(
    frozen=True,
)
class PersistedResponseRiskLifecycle:
    incident_risk: (
        IncidentRiskAssessmentRecord
    )

    proposed_actions: list[
        ProposedActionRecord
    ]

    action_risks: list[
        ActionRiskAssessmentRecord
    ]


def _incident_risk_id(
    *,
    incident_id: str,
    investigation_id: str,
) -> str:
    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-incident-risk:"
            f"{incident_id}:"
            f"{investigation_id}"
        ),
    )

    return (
        "IRISK-"
        f"{str(value).upper()}"
    )


def persist_response_risk_lifecycle(
    *,
    store: IncidentResponseStore,
    investigation: InvestigationResponse,
    assessed_at: datetime | None = None,
) -> (
    PersistedResponseRiskLifecycle
    | None
):
    if (
        investigation.incident_id
        is None
        or investigation.investigation_id
        is None
        or investigation.response_proposal
        is None
    ):
        return None

    if assessed_at is None:
        assessed_at = datetime.now(
            timezone.utc
        )

    incident_id = (
        investigation.incident_id
    )

    investigation_id = (
        investigation.investigation_id
    )

    proposed_actions = list(
        investigation.proposed_actions
    )

    action_risks = list(
        investigation
        .action_risk_assessments
    )

    for action in proposed_actions:
        if (
            action.incident_id
            != incident_id
            or action.investigation_id
            != investigation_id
        ):
            raise ValueError(
                "Proposed action identity "
                "does not match the "
                "investigation."
            )

    proposed_action_ids = {
        action.proposed_action_id
        for action in proposed_actions
    }

    for action_risk in (
        action_risks
    ):
        if (
            action_risk
            .proposed_action_id
            not in proposed_action_ids
        ):
            raise ValueError(
                "Action-risk assessment "
                "references an unknown "
                "proposed action."
            )

    incident_risk = (
        IncidentRiskAssessmentRecord(
            risk_assessment_id=(
                _incident_risk_id(
                    incident_id=(
                        incident_id
                    ),
                    investigation_id=(
                        investigation_id
                    ),
                )
            ),
            incident_id=incident_id,
            investigation_id=(
                investigation_id
            ),
            score=(
                investigation
                .risk_assessment
                .score
            ),
            band=(
                investigation
                .risk_assessment
                .band
            ),
            factors=list(
                investigation
                .risk_assessment
                .factors
            ),
            assessed_at=(
                assessed_at
            ),
        )
    )

    store.save_incident_risk(
        incident_risk
    )

    for action in proposed_actions:
        store.save_proposed_action(
            action
        )

    for action_risk in (
        action_risks
    ):
        store.save_action_risk(
            action_risk
        )

    return (
        PersistedResponseRiskLifecycle(
            incident_risk=(
                incident_risk
            ),
            proposed_actions=(
                proposed_actions
            ),
            action_risks=(
                action_risks
            ),
        )
    )