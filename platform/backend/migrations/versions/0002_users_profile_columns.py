"""Add profile columns to athenasec_web_users for the read-only Users page.

Additive only; no rows are inserted or rewritten.

- department, phone: constant default, so Postgres 11+ adds them without a table rewrite.
- created_at: nullable with no backfill. Existing rows stay NULL (the API falls back to
  the user_created auth event) and a default applies to rows created from now on.
- last_login_at: nullable. Nothing writes it yet; the API falls back to the latest
  mfa_verified_session_started auth event.

Requires the table to exist (0001 on a new database, or the app's startup on an old one).

Revision ID: 0002
Revises: 0001
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE athenasec_web_users
            ADD COLUMN IF NOT EXISTS department TEXT NOT NULL DEFAULT '',
            ADD COLUMN IF NOT EXISTS phone TEXT NOT NULL DEFAULT '',
            ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ,
            ADD COLUMN IF NOT EXISTS last_login_at TIMESTAMPTZ
        """
    )
    op.execute(
        """
        ALTER TABLE athenasec_web_users
            ALTER COLUMN created_at SET DEFAULT now()
        """
    )


def downgrade() -> None:
    op.execute(
        """
        ALTER TABLE athenasec_web_users
            DROP COLUMN IF EXISTS last_login_at,
            DROP COLUMN IF EXISTS created_at,
            DROP COLUMN IF EXISTS phone,
            DROP COLUMN IF EXISTS department
        """
    )
