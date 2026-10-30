"""Create response_policy_versions: append-only versions of the response policy DOCUMENT.

Creates an empty table; no rows are inserted. Storage only: nothing in the agent reads
it, so a saved policy changes no agent behaviour.

- version is the primary key and each save is version = previous + 1.
- document is canonical JSON text ({"whitelist": [...], "blacklist": [...]}), matching
  the SQLite store.
- Triggers reject UPDATE, DELETE and TRUNCATE for every role. A superuser can still drop
  them, so also deny UPDATE/DELETE to the application role.

Revision ID: 0005
Revises: 0004
"""
from alembic import op

revision = "0005"
down_revision = "0004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS response_policy_versions (
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
        CREATE OR REPLACE FUNCTION response_policy_versions_append_only()
        RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'response_policy_versions is append-only';
        END;
        $$ LANGUAGE plpgsql
        """
    )
    op.execute(
        "DROP TRIGGER IF EXISTS response_policy_versions_no_change ON response_policy_versions"
    )
    op.execute(
        """
        CREATE TRIGGER response_policy_versions_no_change
        BEFORE UPDATE OR DELETE ON response_policy_versions
        FOR EACH ROW EXECUTE FUNCTION response_policy_versions_append_only()
        """
    )
    op.execute(
        "DROP TRIGGER IF EXISTS response_policy_versions_no_truncate ON response_policy_versions"
    )
    op.execute(
        """
        CREATE TRIGGER response_policy_versions_no_truncate
        BEFORE TRUNCATE ON response_policy_versions
        FOR EACH STATEMENT EXECUTE FUNCTION response_policy_versions_append_only()
        """
    )


def downgrade() -> None:
    # Policy history is never dropped by a migration.
    raise NotImplementedError("response_policy_versions cannot be downgraded.")
