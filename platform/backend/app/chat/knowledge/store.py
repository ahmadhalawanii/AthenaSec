"""Storage for the approved knowledge base, in memory and in PostgreSQL.

Both stores answer `candidates` the same way: approved documents the role may read, whose chunks
share at least one term with the question. The service then ranks them, so ranking is identical
whichever store is used. Tables are created by Alembic migration 0013.
"""

import os
import threading
from datetime import datetime
from typing import Any, Protocol

import psycopg

DOC_FIELDS = (
    "doc_id, slug, version, title, status, allowed_roles, body, content_hash, quarantine_reason, "
    "created_by, created_at, approved_by, approved_at, revoked_at"
)
DOC_KEYS = [name.strip() for name in DOC_FIELDS.split(",")]


class KnowledgeStore(Protocol):
    def next_version(self, slug: str) -> int: ...

    def add_document(self, doc: dict[str, Any], chunks: list[dict[str, Any]]) -> dict[str, Any]: ...

    def get_document(self, doc_id: str) -> dict[str, Any] | None: ...

    def list_documents(self) -> list[dict[str, Any]]: ...

    def approve(self, doc_id: str, approver: str, when: datetime) -> dict[str, Any]: ...

    def revoke(self, doc_id: str, when: datetime) -> dict[str, Any]: ...

    def has_slug(self, slug: str) -> bool: ...

    def candidates(self, query_terms: list[str], role: str, limit: int) -> list[dict[str, Any]]: ...


class InMemoryKnowledgeStore:
    def __init__(self):
        self._lock = threading.Lock()
        self._docs: dict[str, dict[str, Any]] = {}
        self._chunks: dict[str, list[dict[str, Any]]] = {}

    def next_version(self, slug):
        with self._lock:
            return 1 + max((d["version"] for d in self._docs.values() if d["slug"] == slug), default=0)

    def add_document(self, doc, chunks):
        with self._lock:
            self._docs[doc["doc_id"]] = dict(doc)
            self._chunks[doc["doc_id"]] = [dict(c) for c in chunks]
        return dict(doc)

    def get_document(self, doc_id):
        with self._lock:
            doc = self._docs.get(doc_id)
        return dict(doc) if doc else None

    def list_documents(self):
        with self._lock:
            docs = [dict(d) for d in self._docs.values()]
        return sorted(docs, key=lambda d: (d["created_at"], d["doc_id"]), reverse=True)

    def has_slug(self, slug):
        with self._lock:
            return any(d["slug"] == slug for d in self._docs.values())

    def approve(self, doc_id, approver, when):
        with self._lock:
            doc = self._docs[doc_id]
            for other in self._docs.values():  # one live version per slug
                if other["slug"] == doc["slug"] and other["status"] == "approved":
                    other["status"] = "superseded"
            doc.update(status="approved", approved_by=approver, approved_at=when)
            return dict(doc)

    def revoke(self, doc_id, when):
        with self._lock:
            doc = self._docs[doc_id]
            doc.update(status="revoked", revoked_at=when)
            return dict(doc)

    def candidates(self, query_terms, role, limit):
        wanted = set(query_terms)
        found = []
        with self._lock:
            for doc in self._docs.values():
                if doc["status"] != "approved" or role not in doc["allowed_roles"]:
                    continue
                for chunk in self._chunks[doc["doc_id"]]:
                    overlap = len(wanted & set(chunk["terms"].split()))
                    if overlap:
                        found.append((overlap, {**_summary(doc), "heading": chunk["heading"],
                                                "text": chunk["body"], "terms": chunk["terms"]}))
        found.sort(key=lambda pair: -pair[0])
        return [item for _, item in found[:limit]]


def _summary(doc):
    return {k: doc[k] for k in ("doc_id", "slug", "title", "version", "approved_at")}


class PostgresKnowledgeStore:
    def __init__(self, database_url: str):
        self._url = database_url

    def _connect(self):
        return psycopg.connect(self._url)

    @staticmethod
    def _doc(row):
        return dict(zip(DOC_KEYS, row))

    def next_version(self, slug):
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COALESCE(MAX(version), 0) + 1 FROM knowledge_documents WHERE slug = %s", (slug,)
            ).fetchone()
        return row[0]

    def add_document(self, doc, chunks):
        with self._connect() as conn:
            conn.execute(
                f"INSERT INTO knowledge_documents ({DOC_FIELDS}) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)",
                [doc[key] for key in DOC_KEYS],
            )
            for chunk in chunks:
                conn.execute(
                    "INSERT INTO knowledge_chunks (chunk_id, doc_id, ordinal, heading, body, terms) "
                    "VALUES (%s, %s, %s, %s, %s, %s)",
                    (chunk["chunk_id"], doc["doc_id"], chunk["ordinal"], chunk["heading"],
                     chunk["body"], chunk["terms"]),
                )
        return dict(doc)

    def get_document(self, doc_id):
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT {DOC_FIELDS} FROM knowledge_documents WHERE doc_id = %s", (doc_id,)
            ).fetchone()
        return self._doc(row) if row else None

    def list_documents(self):
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT {DOC_FIELDS} FROM knowledge_documents ORDER BY created_at DESC, doc_id DESC"
            ).fetchall()
        return [self._doc(r) for r in rows]

    def has_slug(self, slug):
        with self._connect() as conn:
            return conn.execute(
                "SELECT 1 FROM knowledge_documents WHERE slug = %s LIMIT 1", (slug,)
            ).fetchone() is not None

    def approve(self, doc_id, approver, when):
        with self._connect() as conn:  # one transaction: the old version goes before the new one is live
            conn.execute(
                "UPDATE knowledge_documents SET status = 'superseded' "
                "WHERE status = 'approved' AND slug = (SELECT slug FROM knowledge_documents WHERE doc_id = %s)",
                (doc_id,),
            )
            row = conn.execute(
                "UPDATE knowledge_documents SET status = 'approved', approved_by = %s, approved_at = %s "
                f"WHERE doc_id = %s RETURNING {DOC_FIELDS}",
                (approver, when, doc_id),
            ).fetchone()
        return self._doc(row)

    def revoke(self, doc_id, when):
        with self._connect() as conn:
            row = conn.execute(
                "UPDATE knowledge_documents SET status = 'revoked', revoked_at = %s "
                f"WHERE doc_id = %s RETURNING {DOC_FIELDS}",
                (when, doc_id),
            ).fetchone()
        return self._doc(row)

    def candidates(self, query_terms, role, limit):
        query = " | ".join(sorted(set(query_terms)))  # tokens are [a-z0-9]+ only
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT d.doc_id, d.slug, d.title, d.version, d.approved_at, c.heading, c.body, c.terms "
                "FROM knowledge_chunks c JOIN knowledge_documents d USING (doc_id) "
                "WHERE d.status = 'approved' AND %s = ANY(d.allowed_roles) "
                "AND c.tsv @@ to_tsquery('simple', %s) "
                "ORDER BY ts_rank_cd(c.tsv, to_tsquery('simple', %s)) DESC LIMIT %s",
                (role, query, query, limit),
            ).fetchall()
        keys = ["doc_id", "slug", "title", "version", "approved_at", "heading", "text", "terms"]
        return [dict(zip(keys, row)) for row in rows]


def build_knowledge_store_from_env() -> KnowledgeStore:
    backend = os.getenv("ATHENASEC_PERSISTENCE_BACKEND", "postgres").strip().lower()

    if backend == "sqlite":
        # ponytail: dev SQLite mode keeps the knowledge base in memory; add a SQLite store if needed
        return InMemoryKnowledgeStore()

    if backend != "postgres":
        raise ValueError(f"Unsupported ATHENASEC_PERSISTENCE_BACKEND: {backend}")

    database_url = os.getenv("ATHENASEC_DATABASE_URL")

    if not database_url:
        raise ValueError("ATHENASEC_DATABASE_URL is required.")

    return PostgresKnowledgeStore(database_url)
