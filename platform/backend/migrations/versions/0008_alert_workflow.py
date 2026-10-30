"""Create alert_workflow: the analyst's handling of each alert (open/closed, assignee).

One row per alert, written when an analyst closes, reopens or takes an alert on the
website. Alerts without a row are open and unassigned, so the table starts empty.

Revision ID: 0008
Revises: 0007
"""
from alembic import op

revision = "0008"
down_revision = "0007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS alert_workflow (
            alert_id TEXT PRIMARY KEY,
            status TEXT NOT NULL CHECK (status IN ('open', 'closed')),
            assigned_analyst TEXT,
            updated_at TIMESTAMPTZ NOT NULL,
            updated_by TEXT NOT NULL
        )
        """
    )


def downgrade() -> None:
    # Analyst work is never dropped by a migration.
    raise NotImplementedError("alert_workflow cannot be downgraded.")
