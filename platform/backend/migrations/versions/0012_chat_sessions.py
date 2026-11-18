"""Create the Security Copilot chat tables. Both are created empty.

- chat_sessions: one row per conversation, owned by the operator who started it.
- chat_feedback: a user's note that an answer was confusing or wrong. It never edits the
  answer or any incident record; it is only read by whoever reviews feedback.
- chat_messages: the user and assistant turns. meta holds the tools used, the evidence
  references and the data status of each answer, so an answer can be audited later.

Revision ID: 0012
Revises: 0011
"""
from alembic import op

revision = "0012"
down_revision = "0011"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS chat_sessions (
            session_id TEXT PRIMARY KEY,
            owner_id TEXT NOT NULL,
            presentation TEXT NOT NULL CHECK (presentation IN ('simple', 'technical')),
            created_at TIMESTAMPTZ NOT NULL
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS chat_sessions_owner ON chat_sessions (owner_id, created_at DESC)")
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS chat_messages (
            message_id TEXT PRIMARY KEY,
            session_id TEXT NOT NULL REFERENCES chat_sessions(session_id),
            role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
            content TEXT NOT NULL,
            meta JSONB NOT NULL DEFAULT '{}'::jsonb,
            created_at TIMESTAMPTZ NOT NULL
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS chat_messages_session ON chat_messages (session_id, created_at)")
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS chat_feedback (
            feedback_id TEXT PRIMARY KEY,
            message_id TEXT NOT NULL REFERENCES chat_messages(message_id),
            owner_id TEXT NOT NULL,
            category TEXT NOT NULL CHECK (category IN ('confusing', 'wrong_source', 'incorrect', 'other')),
            note TEXT CHECK (note IS NULL OR char_length(note) <= 500),
            created_at TIMESTAMPTZ NOT NULL
        )
        """
    )


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS chat_feedback")
    op.execute("DROP TABLE IF EXISTS chat_messages")
    op.execute("DROP TABLE IF EXISTS chat_sessions")
