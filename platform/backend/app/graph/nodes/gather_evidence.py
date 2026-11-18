from collections.abc import Callable

from app.graph.state import (
    InvestigationState,
)
from app.schemas import (
    EvidenceObservation,
    EvidenceRecord,
    EvidenceRequest,
    SecurityAlertInput,
)
from app.services.investigations.investigation_trace import (
    append_investigation_trace,
)


EvidenceProvider = Callable[
    [
        SecurityAlertInput,
        list[EvidenceRequest],
    ],
    list[EvidenceObservation],
]


DEFAULT_WAZUH_EVIDENCE: dict[
    str,
    list[EvidenceRequest],
] = {
    "brute_force": [
        "authentication_history",
        "source_endpoint_context",
        "related_security_events",
    ],
    "privilege_misuse": [
        "privilege_activity",
        "authentication_history",
        "related_security_events",
    ],
    "privilege_escalation": [
        "privilege_activity",
        "authentication_history",
        "related_security_events",
    ],
    "unknown": [
        "related_security_events",
    ],
}


def _privilege_related_alert(alert: SecurityAlertInput) -> bool:
    # Retrieval hint only, never a classifier or action authorization.
    import re
    text = str(getattr(alert, 'event_text', '') or '') + ' ' + str(getattr(alert, 'metadata', {}) or {})
    return bool(re.search(
        r'\b(?:sudo|gpasswd|groupadd|useradd|privilege|privileged|'
        r'administrative|administrator|uid\s*=\s*0)\b',
        text, re.IGNORECASE,
    ))


def _augment_privilege_requests(state: InvestigationState, requests: list[EvidenceRequest]) -> list[EvidenceRequest]:
    # Unknown privilege-related alerts must not default to unrelated evidence alone.
    alert = state['alert']
    analysis = state['analysis']
    if analysis.classification != 'unknown' or not _privilege_related_alert(alert):
        return requests
    already = {record.evidence_type for record in state.get('evidence_records', [])}
    result: list[EvidenceRequest] = []
    for requested in ['privilege_activity', *requests, 'related_security_events']:
        if requested not in already and requested not in result:
            result.append(requested)
        if len(result) == 2:
            break
    return result


def _resolve_evidence_requests(
    state: InvestigationState,
) -> list[EvidenceRequest]:
    analysis = state["analysis"]
    alert = state["alert"]
    assessment = state.get("evidence_sufficiency")

    existing = {
        record.evidence_type
        for record in state.get("evidence_records", [])
        if record.evidence_type is not None
    }

    requested = []

    event_text = alert.event_text.lower()
    privilege_terms = (
        "sudo group",
        "gpasswd",
        "privilege",
        "wheel group",
        "administrative group",
    )

    if (
        alert.source == "wazuh"
        and analysis.classification == "unknown"
        and any(term in event_text for term in privilege_terms)
    ):
        requested.append("privilege_activity")

    if alert.source == "wazuh" and assessment is not None:
        requested.extend(assessment.missing_evidence)
        if (
            analysis.classification == "brute_force"
            and "source_endpoint_context" in assessment.missing_evidence
        ):
            requested.append("source_network_context")


    requested.extend(analysis.requested_evidence)

    if not requested and alert.source == "wazuh":
        if assessment is None or not assessment.sufficient:
            requested.extend(
                DEFAULT_WAZUH_EVIDENCE.get(
                    analysis.classification, []
                )
            )

    return list(dict.fromkeys(
        item for item in requested if item not in existing
    ))


def make_gather_evidence_node(
    evidence_provider: EvidenceProvider,
):
    def gather_evidence(
        state: InvestigationState,
    ) -> InvestigationState:
        requests = (
            _resolve_evidence_requests(
                state
            )
        )

        observations = evidence_provider(
            state["alert"],
            requests,
        )

        existing_records = state.get(
            "evidence_records",
            [],
        )

        next_number = (
            len(existing_records) + 1
        )

        new_records: list[
            EvidenceRecord
        ] = []

        for observation in observations:
            record = EvidenceRecord(
                evidence_id=(
                    f"E{next_number:03d}"
                ),
                source=(
                    observation.source
                ),
                evidence_type=(
                    observation.evidence_type
                ),
                content=(
                    observation.content
                ),
            )

            new_records.append(
                record
            )

            next_number += 1

        iteration = state.get(
            "investigation_iteration",
            0,
        )

        trace = (
            append_investigation_trace(
                state,
                step_type=(
                    "evidence_gathering"
                ),
                status="evidence_gathered",
                details={
                    "requested_evidence": list(
                        requests
                    ),
                    "new_evidence_ids": [
                        record.evidence_id
                        for record
                        in new_records
                    ],
                    "observation_count": len(
                        new_records
                    ),
                    "iteration": (
                        iteration + 1
                    ),
                },
            )
        )

        return {
            "evidence_records": (
                existing_records
                + new_records
            ),
            "investigation_iteration": (
                iteration + 1
            ),
            "investigation_trace": trace,
            "status": (
                "evidence_gathered"
            ),
        }

    return gather_evidence