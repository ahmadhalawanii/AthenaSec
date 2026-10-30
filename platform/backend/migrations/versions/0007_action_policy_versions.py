"""Create action_policy_versions: append-only versions of the action policy.

The action policy is the administrator's whitelist and blacklist of agent actions. The
agent enforces the newest version; with no rows, the built-in default applies.

- version is the primary key and each save is version = previous + 1.
- document is canonical JSON text (whitelist, blacklist, never_block, never_isolate),
  matching the SQLite store.
- Triggers reject UPDATE, DELETE and TRUNCATE, as for response_policy_versions.

Revision ID: 0007
Revises: 0006
"""
from alembic import op

revision = "0007"
down_revision = "0006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS action_policy_versions (
            version INTEGER PRIMARY KEY CHECK (version >= 1),
            document TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            created_by TEXT NOT NULL,
            reason TEXT NOT NULL
        )
        """
    )
    op.execute(
        """
        CREATE OR REPLACE FUNCTION action_policy_versions_append_only()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'action_policy_versions is append-only';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute("DROP TRIGGER IF EXISTS action_policy_versions_no_change ON action_policy_versions")
    op.execute(
        """
        CREATE TRIGGER action_policy_versions_no_change
        BEFORE UPDATE OR DELETE ON action_policy_versions
        FOR EACH ROW EXECUTE FUNCTION action_policy_versions_append_only()
        """
    )
    op.execute("DROP TRIGGER IF EXISTS action_policy_versions_no_truncate ON action_policy_versions")
    op.execute(
        """
        CREATE TRIGGER action_policy_versions_no_truncate
        BEFORE TRUNCATE ON action_policy_versions
        FOR EACH STATEMENT EXECUTE FUNCTION action_policy_versions_append_only()
        """
    )


def downgrade() -> None:
    # Policy history is never dropped by a migration.
    raise NotImplementedError("action_policy_versions cannot be downgraded.")
