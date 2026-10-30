"""Builds the website's Case from an incident_cases row.

Nothing is copied into storage. Summary, evidence, endpoint, source IP, MITRE ids, the
agent timeline and the default recommended actions are read from the investigation at
request time; only analyst state (assignee, notes, curated actions) comes from the case
workflow tables. A case whose investigation cannot be found still renders, with those
derived fields empty.
"""

from app.schemas import (
    Case,
    CaseAction,
    CaseEvidence,
    CaseTimelineEntry,
    IncidentCaseRecord,
    InvestigationResponse,
)

_FAILED_STATUSES = ("fail", "error")


def _investigation_for(case: IncidentCaseRecord, investigation_store):
    if case.investigation_id:
        return investigation_store.get_incident_investigation(
            case.investigation_id
        )

    candidates = investigation_store.list_incident_investigations(
        case.incident_id
    )

    return max(
        candidates,
        key=lambda record: (record.started_at, record.investigation_id),
        default=None,
    )


def _text(value) -> str | None:
    return value if isinstance(value, str) and value.strip() else None


def _derived_actions(response: InvestigationResponse | None) -> list[CaseAction]:
    if response is None:
        return []

    approvals = {
        approval.proposed_action_id: approval.approval_id
        for approval in response.approval_requests
    }

    return [
        CaseAction(
            position=index,
            label=f"{action.action_type} {action.target}",
            done=False,
            proposed_action_id=action.proposed_action_id,
            approval_id=approvals.get(action.proposed_action_id),
        )
        for index, action in enumerate(response.proposed_actions)
    ]


def _timeline(response, notes) -> list[CaseTimelineEntry]:
    entries = []

    for step in (response.investigation_trace if response is not None else []):
        entries.append(
            (
                step.recorded_at,
                CaseTimelineEntry(
                    seq=0,
                    occurred_at=step.recorded_at,
                    title=step.step_type.replace("_", " ").capitalize(),
                    description=step.status,
                    failed=any(
                        marker in step.status.lower()
                        for marker in _FAILED_STATUSES
                    ),
                    source="agent",
                ),
            )
        )

    for note in notes:
        entries.append(
            (
                note.occurred_at,
                CaseTimelineEntry(
                    seq=0,
                    occurred_at=note.occurred_at,
                    title=note.title,
                    description=note.description,
                    failed=note.failed,
                    source="analyst",
                    author=note.author,
                ),
            )
        )

    entries.sort(key=lambda pair: (pair[0].timestamp(), pair[1].source))

    return [
        entry.model_copy(update={"seq": number})
        for number, (_, entry) in enumerate(entries, start=1)
    ]


def build_case(
    case: IncidentCaseRecord,
    *,
    investigation_store,
    workflow_store,
) -> Case:
    workflow = workflow_store.get_workflow(case.case_id)
    investigation = _investigation_for(case, investigation_store)
    response = (
        investigation_store.get(investigation.primary_alert_id)
        if investigation is not None
        else None
    )
    profile = investigation_store.get_correlation_profile(case.incident_id)
    metadata = response.alert_metadata if response is not None else {}

    mitre_ids = list(profile.mitre_ids) if profile is not None else []

    if not mitre_ids and isinstance(metadata.get("mitre_ids"), list):
        mitre_ids = [m for m in metadata["mitre_ids"] if isinstance(m, str)]

    source_ip = _text(metadata.get("source_ip")) or (
        profile.source_ips[0] if profile is not None and profile.source_ips else None
    )

    stored_actions = workflow_store.list_actions(case.case_id)
    summary = (workflow.summary if workflow is not None else None) or (
        response.analysis.summary if response is not None else None
    )

    return Case(
        case_id=case.case_id,
        incident_id=case.incident_id,
        investigation_id=(
            case.investigation_id
            or (investigation.investigation_id if investigation is not None else None)
        ),
        alert_id=investigation.primary_alert_id if investigation is not None else None,
        policy_id=response.policy_decision.policy_id if response is not None else None,
        classification=response.analysis.classification if response is not None else None,
        risk_score=response.risk_assessment.score if response is not None else None,
        risk_band=response.risk_assessment.band if response is not None else None,
        status=case.status,
        reason=case.reason,
        assigned_analyst=workflow.assigned_analyst if workflow is not None else None,
        summary=summary,
        endpoint=_text(metadata.get("agent_name")) or _text(metadata.get("agent_ip")),
        source_ip=source_ip,
        evidence=[
            CaseEvidence(
                evidence_id=record.evidence_id,
                source=record.source,
                evidence_type=record.evidence_type,
                content=record.content,
            )
            for record in (response.evidence_records if response is not None else [])
        ],
        recommended_actions=(
            [
                CaseAction(
                    position=action.position,
                    label=action.label,
                    done=action.done,
                    proposed_action_id=action.proposed_action_id,
                    approval_id=action.approval_id,
                )
                for action in stored_actions
            ]
            if stored_actions
            else _derived_actions(response)
        ),
        mitre_ids=mitre_ids,
        timeline=_timeline(response, workflow_store.list_notes(case.case_id)),
        version=workflow.version if workflow is not None else 1,
        created_at=case.created_at,
        updated_at=(
            max(case.updated_at, workflow.updated_at)
            if workflow is not None
            else case.updated_at
        ),
        closed_at=workflow.closed_at if workflow is not None else None,
    )


def case_matches(
    case: Case,
    *,
    assigned_analyst: str | None,
    alert_id: str | None,
    q: str | None,
) -> bool:
    if assigned_analyst is not None and case.assigned_analyst != assigned_analyst:
        return False

    if alert_id is not None and case.alert_id != alert_id:
        return False

    if q:
        needle = q.strip().casefold()
        haystack = (
            case.case_id,
            case.reason,
            case.summary or "",
            case.endpoint or "",
            case.source_ip or "",
        )

        if not any(needle in part.casefold() for part in haystack):
            return False

    return True
