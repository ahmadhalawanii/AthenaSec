"""Self-service two-factor setup on first sign-in.

- mfa_enrolled: FALSE for an account created on the website until its owner scans
  their own QR code and confirms a code. Existing accounts stay TRUE, so nothing
  changes for them.
- totp_nonce: random value mixed into the account's authenticator secret, new for every
  enrolment (first setup or an administrator's reset). Two accounts, or the same
  account id created again later, never get the same QR code. NULL keeps the
  original secret of accounts made before this revision.
- pending_totp_nonce: the QR code on screen during setup, not active until a code
  from it is confirmed.

Additive only: constant defaults, no rewrite, no rows changed.

Revision ID: 0011
Revises: 0010
"""
from alembic import op

revision = "0011"
down_revision = "0010"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        ALTER TABLE athenasec_web_users
            ADD COLUMN IF NOT EXISTS mfa_enrolled BOOLEAN NOT NULL DEFAULT TRUE,
            ADD COLUMN IF NOT EXISTS totp_nonce TEXT,
            ADD COLUMN IF NOT EXISTS pending_totp_nonce TEXT
        """
    )


def downgrade() -> None:
    raise NotImplementedError("Two-factor setup columns cannot be downgraded.")
