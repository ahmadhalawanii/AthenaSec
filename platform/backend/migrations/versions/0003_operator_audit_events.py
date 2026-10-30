"""Create operator_audit_events: the append-only, hash-chained operator audit log.

Creates an empty table. No rows are inserted.

- seq orders the chain; row_hash = sha256(prev_hash + canonical row JSON), see
  app/services/audit/operator_audit_store.py.
- detail and source_ip are TEXT (canonical JSON / normalised address) rather than
  JSONB / INET, so the bytes that were hashed are the bytes that are read back.
- Triggers reject UPDATE, DELETE and TRUNCATE for every role. A superuser can still drop
  them, so also deny UPDATE/DELETE to the application role.

Revision ID: 0003
Revises: 0002
"""
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS operator_audit_events (
            seq BIGSERIAL PRIMARY KEY,
            event_id TEXT NOT NULL UNIQUE,
            occurred_at TIMESTAMPTZ NOT NULL,
            actor_id TEXT NOT NULL,
            actor_role TEXT NOT NULL
                CHECK (actor_role IN ('Analyst','Administrator','System')),
            category TEXT NOT NULL,
            action TEXT NOT NULL,
            target TEXT NOT NULL,
            result TEXT NOT NULL CHECK (result IN ('Success','Failed','Denied')),
            source_ip TEXT,
            event_type TEXT,
            detail TEXT NOT NULL DEFAULT '{}',
            prev_hash TEXT NOT NULL,
            row_hash TEXT NOT NULL UNIQUE
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_operator_audit_events_occurred_at
        ON operator_audit_events(occurred_at)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_operator_audit_events_actor_id
        ON operator_audit_events(actor_id)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_operator_audit_events_category
        ON operator_audit_events(category)
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION operator_audit_events_append_only()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'operator_audit_events is append-only';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        "DROP TRIGGER IF EXISTS operator_audit_events_no_change ON operator_audit_events"
    )
    op.execute(
        """
        CREATE TRIGGER operator_audit_events_no_change
        BEFORE UPDATE OR DELETE ON operator_audit_events
        FOR EACH ROW EXECUTE FUNCTION operator_audit_events_append_only()
        """
    )
    op.execute(
        "DROP TRIGGER IF EXISTS operator_audit_events_no_truncate ON operator_audit_events"
    )
    op.execute(
        """
        CREATE TRIGGER operator_audit_events_no_truncate
        BEFORE TRUNCATE ON operator_audit_events
        FOR EACH STATEMENT EXECUTE FUNCTION operator_audit_events_append_only()
        """
    )


def downgrade() -> None:
    # An audit log is never dropped by a migration.
    raise NotImplementedError("operator_audit_events cannot be downgraded.")
