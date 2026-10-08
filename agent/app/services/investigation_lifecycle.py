from datetime import (
    datetime,
    timezone,
)
from uuid import (
    NAMESPACE_URL,
    uuid5,
)

from app.schemas import (
    IncidentInvestigationRecord,
    InvestigationEvidenceRecord,
    InvestigationResponse,
    InvestigationStepRecord,
)
from app.services.investigation_store import (
    InvestigationStore,
)


def build_investigation_id(
    *,
    incident_id: str,
    alert_id: str,
) -> str:
    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-investigation:"
            f"{incident_id}:"
            f"{alert_id}"
        ),
    )

    return (
        "INV-"
        f"{str(value).upper()}"
    )


def _build_step_id(
    *,
    investigation_id: str,
    sequence: int,
) -> str:
    value = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-investigation-step:"
            f"{investigation_id}:"
            f"{sequence}"
        ),
    )

    return (
        "STEP-"
        f"{str(value).upper()}"
    )


def persist_investigation_lifecycle(
    *,
    store: InvestigationStore,
    investigation: InvestigationResponse,
    completed_at: datetime | None = None,
) -> IncidentInvestigationRecord | None:
    incident_id = (
        investigation.incident_id
    )

    if incident_id is None:
        return None

    if completed_at is None:
        completed_at = datetime.now(
            timezone.utc
        )

    investigation_id = (
        build_investigation_id(
            incident_id=incident_id,
            alert_id=(
                investigation.alert_id
            ),
        )
    )

    trace = list(
        investigation.investigation_trace
    )

    if trace:
        started_at = min(
            step.recorded_at
            for step in trace
        )

    else:
        started_at = completed_at

    sufficiency = (
        investigation.evidence_sufficiency
    )

    verification = (
        investigation.analysis_verification
    )

    record = IncidentInvestigationRecord(
        investigation_id=(
            investigation_id
        ),
        incident_id=incident_id,
        primary_alert_id=(
            investigation.alert_id
        ),
        status=(
            "complete"
            if (
                investigation.status
                == "complete"
            )
            else "failed"
        ),
        started_at=started_at,
        updated_at=completed_at,
        completed_at=completed_at,
        iteration_count=(
            investigation
            .investigation_iteration
        ),
        budget_exhausted=(
            investigation
            .investigation_budget_exhausted
        ),
        evidence_sufficient=(
            sufficiency.sufficient
            if sufficiency is not None
            else None
        ),
        analysis_verified=(
            verification.verified
            if verification is not None
            else None
        ),
    )

    store.save_incident_investigation(
        record
    )

    for evidence in (
        investigation.evidence_records
    ):
        store.save_investigation_evidence(
            InvestigationEvidenceRecord(
                investigation_id=(
                    investigation_id
                ),
                evidence_id=(
                    evidence.evidence_id
                ),
                source=evidence.source,
                evidence_type=(
                    evidence.evidence_type
                ),
                content=evidence.content,
                captured_at=completed_at,
            )
        )

    for trace_step in trace:
        store.save_investigation_step(
            InvestigationStepRecord(
                investigation_id=(
                    investigation_id
                ),
                step_id=_build_step_id(
                    investigation_id=(
                        investigation_id
                    ),
                    sequence=(
                        trace_step.sequence
                    ),
                ),
                sequence=(
                    trace_step.sequence
                ),
                step_type=(
                    trace_step.step_type
                ),
                status=(
                    trace_step.status
                ),
                details=dict(
                    trace_step.details
                ),
                recorded_at=(
                    trace_step.recorded_at
                ),
            )
        )

    return record