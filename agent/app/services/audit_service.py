from uuid import uuid4

from app.schemas import (
    AuditEventType,
    AuditRecord,
    IncidentAuditEntityType,
    IncidentAuditRecord,
)


def _build_audit_id() -> str:
    return (
        "AUD-"
        f"{str(uuid4()).upper()}"
    )


def create_audit_record(
    alert_id: str,
    event_type: AuditEventType,
    message: str,
    details: dict[str, object],
) -> AuditRecord:
    return AuditRecord(
        audit_id=_build_audit_id(),
        alert_id=alert_id,
        event_type=event_type,
        message=message,
        details=details,
    )


def create_incident_audit_record(
    *,
    incident_id: str,
    event_type: str,
    entity_type: IncidentAuditEntityType,
    entity_id: str,
    message: str,
    details: dict[str, object],
) -> IncidentAuditRecord:
    return IncidentAuditRecord(
        audit_id=_build_audit_id(),
        incident_id=incident_id,
        event_type=event_type,
        entity_type=entity_type,
        entity_id=entity_id,
        message=message,
        details=details,
    )