"""Create the case workflow tables beside incident_cases. All three are created empty.

- case_workflow: assignee, summary override, close time and a version for later
  optimistic updates. A case with no row reads as unassigned.
- case_actions: analyst-curated recommended actions (done flag). When a case has none,
  the API derives its list from the investigation's proposed actions.
- case_timeline: analyst notes. Agent steps are derived from the investigation at read
  time, not copied here.

No rows are inserted; incident_cases is not altered. assigned_analyst holds a
athenasec_web_users.user_id but has no foreign key, so the tables work wherever the
users table does not exist; writes will validate it later.

Revision ID: 0004
Revises: 0003
"""
from alembic import op

revision = "0004"
down_revision = "0003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS case_workflow (
            case_id TEXT PRIMARY KEY REFERENCES incident_cases(case_id),
            assigned_analyst TEXT,
            summary TEXT,
            closed_at TIMESTAMPTZ,
            updated_at TIMESTAMPTZ NOT NULL,
            version INTEGER NOT NULL DEFAULT 1 CHECK (version >= 1)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS case_actions (
            case_id TEXT NOT NULL REFERENCES incident_cases(case_id),
            position INTEGER NOT NULL CHECK (position >= 0),
            label TEXT NOT NULL,
            proposed_action_id TEXT,
            approval_id TEXT,
            done BOOLEAN NOT NULL DEFAULT FALSE,
            PRIMARY KEY (case_id, position)
        )
        """
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS case_timeline (
            case_id TEXT NOT NULL REFERENCES incident_cases(case_id),
            seq INTEGER NOT NULL CHECK (seq >= 1),
            occurred_at TIMESTAMPTZ NOT NULL,
            title TEXT NOT NULL,
            description TEXT NOT NULL,
            failed BOOLEAN NOT NULL DEFAULT FALSE,
            author TEXT,
            PRIMARY KEY (case_id, seq)
        )
        """
    )
    op.execute(
        """
        CREATE INDEX IF NOT EXISTS idx_case_workflow_assigned_analyst
        ON case_workflow(assigned_analyst)
        """
    )


def downgrade() -> None:
    # Analyst notes and assignments are user data; a migration does not drop them.
    raise NotImplementedError("The case workflow tables cannot be downgraded.")
