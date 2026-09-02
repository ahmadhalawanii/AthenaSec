from uuid import uuid4

from app.schemas import (
    AuditEventType,
    AuditRecord,
)


def create_audit_record(
    alert_id: str,
    event_type: AuditEventType,
    message: str,
    details: dict[str, object],
) -> AuditRecord:
    audit_id = (
        "AUD-"
        f"{str(uuid4()).upper()}"
    )

    return AuditRecord(
        audit_id=audit_id,
        alert_id=alert_id,
        event_type=event_type,
        message=message,
        details=details,
    )