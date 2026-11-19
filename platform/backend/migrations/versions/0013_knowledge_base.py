"""Create the Security Copilot knowledge base: approved documents and their searchable chunks.

- knowledge_documents: one row per version of a document. Only status 'approved' rows are ever
  used in answers. At most one version of a slug is approved at a time (a partial unique index),
  so approving a new version cannot leave two live ones. allowed_roles limits who may read it.
- knowledge_chunks: the document split by heading. terms holds the tokens produced by the app's
  own tokenizer (stemmed, filler removed) and tsv indexes them with the 'simple' configuration, so
  a question is read exactly as the text was indexed.

Both tables are created empty.

Revision ID: 0013
Revises: 0012
"""
from alembic import op

revision = "0013"
down_revision = "0012"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS knowledge_documents (
            doc_id TEXT PRIMARY KEY,
            slug TEXT NOT NULL,
            version INTEGER NOT NULL CHECK (version >= 1),
            title TEXT NOT NULL,
            status TEXT NOT NULL
                CHECK (status IN ('draft', 'approved', 'quarantined', 'revoked', 'superseded')),
            allowed_roles TEXT[] NOT NULL CHECK (cardinality(allowed_roles) >= 1),
            body TEXT NOT NULL,
            content_hash TEXT NOT NULL,
            quarantine_reason TEXT,
            created_by TEXT NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            approved_by TEXT,
            approved_at TIMESTAMPTZ,
            revoked_at TIMESTAMPTZ,
            UNIQUE (slug, version)
        )
        """
    )
    op.execute(
        "CREATE UNIQUE INDEX IF NOT EXISTS knowledge_one_approved_per_slug "
        "ON knowledge_documents (slug) WHERE status = 'approved'"
    )
    op.execute(
        """
        CREATE TABLE IF NOT EXISTS knowledge_chunks (
            chunk_id TEXT PRIMARY KEY,
            doc_id TEXT NOT NULL REFERENCES knowledge_documents(doc_id) ON DELETE CASCADE,
            ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
            heading TEXT NOT NULL,
            body TEXT NOT NULL,
            terms TEXT NOT NULL,
            tsv tsvector GENERATED ALWAYS AS (to_tsvector('simple', terms)) STORED
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS knowledge_chunks_tsv ON knowledge_chunks USING GIN (tsv)")
    op.execute("CREATE INDEX IF NOT EXISTS knowledge_chunks_doc ON knowledge_chunks (doc_id, ordinal)")


def downgrade() -> None:
    op.execute("DROP TABLE IF EXISTS knowledge_chunks")
    op.execute("DROP TABLE IF EXISTS knowledge_documents")
