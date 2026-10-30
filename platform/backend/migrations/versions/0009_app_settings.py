"""Create app_settings: the system configuration and each user's settings (JSON documents).

Keys are "configuration" and "user-settings:<user_id>". The table starts empty; until a
document is saved the built-in defaults apply.

Revision ID: 0009
Revises: 0008
"""
from alembic import op

revision = "0009"
down_revision = "0008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS app_settings (
            key TEXT PRIMARY KEY,
            document TEXT NOT NULL,
            version INTEGER NOT NULL CHECK (version >= 1),
            updated_at TIMESTAMPTZ NOT NULL,
            updated_by TEXT NOT NULL
        )
        """
    )


def downgrade() -> None:
    # Saved settings are never dropped by a migration.
    raise NotImplementedError("app_settings cannot be downgraded.")
