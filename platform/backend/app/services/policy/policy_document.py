"""Builds the response-policy document returned by /api/v1/policies.

STORED DOCUMENT ONLY. The whitelist and blacklist here are never read by the agent, so the
response always says enforced=false. protected_targets is different: it is a read-only view
of the agent's real target-protection state (the never-block / never-isolate list that
risk and policy do enforce), shown beside the document and not editable through it.
"""

from app.schemas import PolicyDocument, PolicyProtectedTarget, PolicyVersionRecord

ENFORCEMENT_NOTE = (
    "Stored document only. The agent does not read the whitelist or blacklist, so saving "
    "a policy changes no agent behaviour. protected_targets is the agent's own "
    "target-protection state, shown read-only."
)

_PROTECTED_FIELDS = (
    ("protected_ips", "ip"),
    ("protected_accounts", "account"),
    ("protected_endpoints", "endpoint"),
)


def read_protected_targets(registry) -> list[PolicyProtectedTarget]:
    """Read the enforced protected targets without altering the registry."""

    store = getattr(registry, "store", None)

    if store is not None:
        snapshot = store.get_snapshot()
    else:
        snapshot = getattr(registry, "_snapshot", None)

    if snapshot is None:
        return []

    return [
        PolicyProtectedTarget(value=value, type=kind)
        for field, kind in _PROTECTED_FIELDS
        for value in getattr(snapshot, field, ())
    ]


def build_policy_document(
    record: PolicyVersionRecord | None,
    *,
    protected_targets: list[PolicyProtectedTarget],
) -> PolicyDocument:
    if record is None:
        return PolicyDocument(
            version=0,
            protected_targets=protected_targets,
            enforcement_note=ENFORCEMENT_NOTE,
        )

    return PolicyDocument(
        version=record.version,
        whitelist=record.whitelist,
        blacklist=record.blacklist,
        protected_targets=protected_targets,
        enforcement_note=ENFORCEMENT_NOTE,
        created_at=record.created_at,
        created_by=record.created_by,
        reason=record.reason,
    )
