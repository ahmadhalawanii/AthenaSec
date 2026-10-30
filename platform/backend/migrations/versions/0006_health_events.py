"""Create health_events: one row per observed change of a service's status.

Creates an empty table; no rows are inserted. Live status is probed per request and is
never stored. Rows are written only when GET /api/v1/system/health sees a status differ
from the last recorded one for that service.

Differs from the first sketch by adding a status column, which change detection needs.
It is an operational log, not an audit log, so there are no append-only triggers.

Revision ID: 0006
Revises: 0005
"""
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS health_events (
            event_id BIGSERIAL PRIMARY KEY,
            occurred_at TIMESTAMPTZ NOT NULL,
            severity TEXT NOT NULL CHECK (severity IN ('Info','Warning','Critical')),
            source TEXT NOT NULL,
            status TEXT NOT NULL
                CHECK (status IN ('up','degraded','down','starting','unconfigured')),
            message TEXT NOT NULL
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_health_events_time
        ON health_events(occurred_at DESC)
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_health_events_source
        ON health_events(source, event_id DESC)
        """
    )


def downgrade() -> None:
    # Observed history is not dropped by a migration.
    raise NotImplementedError("health_events cannot be downgraded.")
