"""Account recovery columns on athenasec_web_users.

- must_change_password: set when an administrator issues a temporary password (new
  account or reset); the user must choose their own before using the console.
- totp_epoch: bumped when an administrator resets someone's two-factor, which gives the
  account a new authenticator secret. 0 keeps every existing secret unchanged.

Additive only: constant defaults, no rewrite, no rows changed.

Revision ID: 0010
Revises: 0009
"""
from alembic import op

revision = "0010"
down_revision = "0009"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE athenasec_web_users
            ADD COLUMN IF NOT EXISTS must_change_password BOOLEAN NOT NULL DEFAULT FALSE,
            ADD COLUMN IF NOT EXISTS totp_epoch INTEGER NOT NULL DEFAULT 0
        """
    )


def downgrade() -> None:
    raise NotImplementedError("Account recovery columns cannot be downgraded.")
