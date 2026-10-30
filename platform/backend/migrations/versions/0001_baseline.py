"""Baseline of the schema the stores create on startup.

Every statement below is copied verbatim from the store constructors (captured by
running each Postgres store against a recording connection) and is idempotent
(IF NOT EXISTS). It creates no tables on a database that already has them.

On an existing database run `alembic stamp 0001` instead of `upgrade`.
On an empty database `alembic upgrade head` builds the full schema.

No rows are inserted.

Revision ID: 0001
Revises:
"""
from alembic import op

revision = "0001"
down_revision = None
branch_labels = None
depends_on = None

STATEMENTS = [
    # PostgresInvestigationStore
    """
CREATE TABLE IF NOT EXISTS incidents (
    incident_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL
)
    """,
    """
CREATE TABLE IF NOT EXISTS incident_alerts (
    alert_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    observed_at TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (incident_id)
        REFERENCES incidents(incident_id)
        ON DELETE CASCADE
)
    """,
    """
CREATE TABLE IF NOT EXISTS incident_investigations (
    investigation_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    primary_alert_id TEXT NOT NULL,
    started_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (incident_id)
        REFERENCES incidents(incident_id)
        ON DELETE CASCADE,
    FOREIGN KEY (primary_alert_id)
        REFERENCES incident_alerts(alert_id)
)
    """,
    """
CREATE INDEX IF NOT EXISTS
idx_incident_investigations_incident_id
ON incident_investigations(incident_id)
    """,
    """
CREATE INDEX IF NOT EXISTS
idx_incident_investigations_started_at
ON incident_investigations(started_at)
    """,
    """
CREATE TABLE IF NOT EXISTS investigation_evidence (
    investigation_id TEXT NOT NULL,
    evidence_id TEXT NOT NULL,
    captured_at TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (
        investigation_id,
        evidence_id
    ),
    FOREIGN KEY (investigation_id)
        REFERENCES incident_investigations(
            investigation_id
        )
        ON DELETE CASCADE
)
    """,
    """
CREATE TABLE IF NOT EXISTS investigation_steps (
    step_id TEXT PRIMARY KEY,
    investigation_id TEXT NOT NULL,
    sequence INTEGER NOT NULL,
    step_type TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL,
    UNIQUE (
        investigation_id,
        sequence
    ),
    FOREIGN KEY (investigation_id)
        REFERENCES incident_investigations(
            investigation_id
        )
        ON DELETE CASCADE
)
    """,
    """
CREATE INDEX IF NOT EXISTS
idx_investigation_steps_investigation_id
ON investigation_steps(
    investigation_id
)
    """,
    """
CREATE INDEX IF NOT EXISTS
idx_investigation_evidence_captured_at
ON investigation_evidence(captured_at)
    """,
    """
CREATE INDEX IF NOT EXISTS
idx_incident_alerts_incident_id
ON incident_alerts(incident_id)
    """,
    """
CREATE INDEX IF NOT EXISTS
idx_incident_alerts_observed_at
ON incident_alerts(observed_at)
    """,
    """
CREATE TABLE IF NOT EXISTS investigations (
    alert_id TEXT PRIMARY KEY,
    payload TEXT NOT NULL
)
    """,
    """
CREATE TABLE IF NOT EXISTS cases (
    case_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL UNIQUE,
    payload TEXT NOT NULL
)
    """,
    """
CREATE TABLE IF NOT EXISTS
incident_correlation_profiles (
    incident_id TEXT PRIMARY KEY,
    classification TEXT NOT NULL,
    first_seen TIMESTAMPTZ NOT NULL,
    last_seen TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL,
    FOREIGN KEY (incident_id)
        REFERENCES incidents(incident_id)
        ON DELETE CASCADE
)
    """,
    """
CREATE INDEX IF NOT EXISTS
idx_incident_correlation_profiles_lookup
ON incident_correlation_profiles(
    classification,
    last_seen,
    first_seen
)
    """,
    # PostgresIncidentResponseStore
    """
CREATE TABLE IF NOT EXISTS incident_risk_assessments (
    risk_assessment_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    investigation_id TEXT NOT NULL,
    assessed_at TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL
)
    """,
    """
CREATE TABLE IF NOT EXISTS incident_cases (
    case_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    investigation_id TEXT,
    policy_decision_id TEXT,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL
)
    """,
    """
CREATE TABLE IF NOT EXISTS proposed_actions (
    proposed_action_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    investigation_id TEXT NOT NULL,
    proposed_at TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL
)
    """,
    """
CREATE TABLE IF NOT EXISTS action_risk_assessments (
    action_risk_id TEXT PRIMARY KEY,
    proposed_action_id TEXT NOT NULL,
    assessed_at TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL
)
    """,
    """
CREATE TABLE IF NOT EXISTS incident_policy_decisions (
    decision_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    proposed_action_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    decided_at TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL
)
    """,
    """
CREATE TABLE IF NOT EXISTS approval_requests (
    approval_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    proposed_action_id TEXT NOT NULL,
    policy_decision_id TEXT NOT NULL,
    action_fingerprint TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_at TIMESTAMPTZ NOT NULL,
    expires_at TIMESTAMPTZ,
    payload TEXT NOT NULL
)
    """,
    """
CREATE TABLE IF NOT EXISTS response_actions (
    response_action_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    proposed_action_id TEXT NOT NULL,
    approval_id TEXT,
    status TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL
)
    """,
    """
CREATE TABLE IF NOT EXISTS action_results (
    action_result_id TEXT PRIMARY KEY,
    response_action_id TEXT NOT NULL,
    status TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL
)
    """,
    """
CREATE TABLE IF NOT EXISTS action_verifications (
    verification_id TEXT PRIMARY KEY,
    response_action_id TEXT NOT NULL,
    proposed_action_id TEXT NOT NULL,
    status TEXT NOT NULL,
    verified_at TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL
)
    """,
    """
CREATE TABLE IF NOT EXISTS action_rollbacks (
    rollback_id TEXT PRIMARY KEY,
    response_action_id TEXT NOT NULL,
    proposed_action_id TEXT NOT NULL,
    verification_id TEXT NOT NULL,
    status TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL
)
    """,
    # PostgresAuditStore
    """
CREATE TABLE IF NOT EXISTS audit_records (
    audit_id TEXT PRIMARY KEY,
    alert_id TEXT NOT NULL,
    timestamp TEXT NOT NULL,
    payload TEXT NOT NULL
)
    """,
    """
CREATE TABLE IF NOT EXISTS incident_audit_events (
    audit_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    event_type TEXT NOT NULL,
    entity_type TEXT NOT NULL,
    entity_id TEXT NOT NULL,
    timestamp TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL
)
    """,
    """
CREATE INDEX IF NOT EXISTS
idx_incident_audit_events_incident_id
ON incident_audit_events(incident_id)
    """,
    """
CREATE INDEX IF NOT EXISTS
idx_incident_audit_events_timestamp
ON incident_audit_events(timestamp)
    """,
    """
CREATE INDEX IF NOT EXISTS
idx_audit_records_alert_id
ON audit_records(alert_id)
    """,
    """
CREATE INDEX IF NOT EXISTS
idx_audit_records_timestamp
ON audit_records(timestamp)
    """,
    # PostgresRuntimeControlStore
    """
CREATE TABLE IF NOT EXISTS runtime_control_state (
    control_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL
)
    """,
    """
CREATE TABLE IF NOT EXISTS runtime_control_changes (
    change_id TEXT PRIMARY KEY,
    control_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL
)
    """,
    """
CREATE INDEX IF NOT EXISTS
idx_runtime_control_changes_version
ON runtime_control_changes (
    version
)
    """,
    # PostgresTargetProtectionStore
    """
CREATE TABLE IF NOT EXISTS
target_protection_state (
    control_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    payload TEXT NOT NULL
)
    """,
    """
CREATE TABLE IF NOT EXISTS
target_protection_changes (
    change_id TEXT PRIMARY KEY,
    version INTEGER NOT NULL,
    changed_at TIMESTAMPTZ NOT NULL,
    changed_by TEXT NOT NULL,
    reason TEXT NOT NULL,
    payload TEXT NOT NULL
)
    """,
    """
CREATE INDEX IF NOT EXISTS
idx_target_protection_changes_version
ON target_protection_changes (
    version
)
    """,
    # PostgresContainmentExpiryStore
    """
CREATE TABLE IF NOT EXISTS
containment_expiries (
    expiry_id TEXT PRIMARY KEY,
    incident_id TEXT NOT NULL,
    proposed_action_id TEXT NOT NULL,
    response_action_id TEXT NOT NULL,
    status TEXT NOT NULL,
    due_at TIMESTAMPTZ NOT NULL,
    payload TEXT NOT NULL
)
    """,
    """
CREATE INDEX IF NOT EXISTS
idx_containment_expiries_due
ON containment_expiries (
    status,
    due_at
)
    """,
    # PostgresOperatorIdentityStore
    """
CREATE TABLE IF NOT EXISTS athenasec_operator_identities (
    operator_id TEXT PRIMARY KEY,
    can_read_approvals BOOLEAN NOT NULL,
    can_decide_approvals BOOLEAN NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE
)
    """,
    """
CREATE TABLE IF NOT EXISTS athenasec_operator_credentials (
    token_digest TEXT PRIMARY KEY,
    operator_id TEXT NOT NULL REFERENCES athenasec_operator_identities(operator_id),
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE
)
    """,
    # PostgresBrowserAuthStore
    """
CREATE TABLE IF NOT EXISTS athenasec_web_users (
    user_id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL CHECK (role IN ('Analyst','Administrator')),
    password_salt BYTEA NOT NULL,
    password_digest BYTEA NOT NULL,
    active BOOLEAN NOT NULL DEFAULT TRUE,
    can_read_approvals BOOLEAN NOT NULL DEFAULT FALSE,
    can_decide_approvals BOOLEAN NOT NULL DEFAULT FALSE,
    failures INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    last_totp_counter BIGINT NOT NULL DEFAULT -1
)
    """,
    """
CREATE TABLE IF NOT EXISTS athenasec_web_challenges (
    challenge_digest TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES athenasec_web_users(user_id),
    expires_at TIMESTAMPTZ NOT NULL,
    attempts INTEGER NOT NULL DEFAULT 0
)
    """,
    """
CREATE TABLE IF NOT EXISTS athenasec_web_sessions (
    session_digest TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES athenasec_web_users(user_id),
    csrf_token TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked BOOLEAN NOT NULL DEFAULT FALSE
)
    """,
    """
CREATE TABLE IF NOT EXISTS athenasec_web_auth_events (
    event_id BIGSERIAL PRIMARY KEY,
    user_id TEXT,
    event_type TEXT NOT NULL,
    recorded_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
)
    """,
]


def upgrade() -> None:
    for statement in STATEMENTS:
        op.execute(statement)


def downgrade() -> None:
    # The baseline is never dropped: the stores own these tables and hold data.
    raise NotImplementedError("The baseline revision cannot be downgraded.")
