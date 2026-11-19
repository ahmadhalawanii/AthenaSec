"""The approved knowledge base: ingestion, approval, role-aware search and source lookup.

Rules (from the design): a document is a draft until an administrator approves it; text that
tries to instruct the assistant is quarantined and cannot be approved; only approved documents
the asker's role may read are searched; approving a new version replaces the old one; revoking
removes a document at once. Search ranks with one tokenizer shared by both stores.
"""

import hashlib
import json
import re
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from app.chat.knowledge.store import KnowledgeStore
from app.chat.knowledge.text import chunk, injection_reason, normalize, terms

ROLES = ("Analyst", "Administrator")
SLUG = re.compile(r"^[a-z0-9][a-z0-9-]{1,63}$")
SEED_DIR = Path(__file__).parent / "seed"
MIN_COVERAGE = 0.5


class KnowledgeError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _now() -> datetime:
    return datetime.now(timezone.utc)


class KnowledgeBase:
    def __init__(self, store: KnowledgeStore, now: Callable[[], datetime] = _now):
        self._store = store
        self._now = now

    def ingest(self, *, slug: str, title: str, body: str, allowed_roles: list[str],
               created_by: str) -> dict[str, Any]:
        if not SLUG.match(slug or ""):
            raise ValueError("The slug must be 2-64 lowercase letters, digits or hyphens.")
        if not title or not title.strip() or len(title) > 200:
            raise ValueError("A title of up to 200 characters is required.")
        if not allowed_roles or not set(allowed_roles) <= set(ROLES):
            raise ValueError("allowed_roles must be a non-empty subset of Analyst, Administrator.")

        text = normalize(body)
        reason = injection_reason(f"{title}\n{text}")
        version = self._store.next_version(slug)
        doc_id = f"doc-{slug}-v{version}"
        doc = {
            "doc_id": doc_id, "slug": slug, "version": version, "title": title.strip(),
            "status": "quarantined" if reason else "draft",
            "allowed_roles": sorted(set(allowed_roles)), "body": text,
            "content_hash": hashlib.sha256(text.encode()).hexdigest(),
            "quarantine_reason": reason, "created_by": created_by, "created_at": self._now(),
            "approved_by": None, "approved_at": None, "revoked_at": None,
        }
        chunks = [
            {"chunk_id": f"{doc_id}#{i}", "ordinal": i, "heading": c.heading, "body": c.text,
             "terms": " ".join(terms(f"{doc['title']} {c.heading} {c.text}"))}
            for i, c in enumerate(chunk(text))
        ]
        return _public(self._store.add_document(doc, chunks))

    def approve(self, doc_id: str, approver: str) -> dict[str, Any]:
        doc = self._require(doc_id)

        if doc["status"] != "draft":
            raise KnowledgeError(409, f"A document that is {doc['status']} cannot be approved.")

        return _public(self._store.approve(doc_id, approver, self._now()))

    def revoke(self, doc_id: str, actor: str) -> dict[str, Any]:
        doc = self._require(doc_id)

        if doc["status"] == "revoked":
            raise KnowledgeError(409, "The document is already revoked.")

        return _public(self._store.revoke(doc_id, self._now()))

    def list_documents(self) -> list[dict[str, Any]]:
        return [_public(d) for d in self._store.list_documents()]

    def search(self, query: str, role: str | None, limit: int = 3) -> list[dict[str, Any]]:
        role = role if role in ROLES else "Analyst"  # an unknown role gets the minimum
        wanted = list(dict.fromkeys(terms(query)))

        if not wanted:
            return []

        best: dict[str, dict[str, Any]] = {}

        for cand in self._store.candidates(wanted, role, limit=60):
            have = set(cand["terms"].split())
            matched = [t for t in wanted if t in have]
            coverage = len(matched) / len(wanted)

            # Enough of the question must be in the passage; one stray word is not a match
            if len(matched) < min(2, len(wanted)) or coverage < MIN_COVERAGE:
                continue

            in_heading = len(set(terms(cand["heading"])) & set(wanted))
            score = round(coverage + 0.15 * in_heading / len(wanted), 4)
            hit = {k: cand[k] for k in ("doc_id", "slug", "title", "version", "heading", "approved_at")}
            hit.update(text=cand["text"], score=score)

            if cand["doc_id"] not in best or score > best[cand["doc_id"]]["score"]:
                best[cand["doc_id"]] = hit

        return sorted(best.values(), key=lambda h: -h["score"])[:limit]

    def source(self, source_id: str, role: str | None) -> dict[str, Any] | None:
        doc = self._store.get_document(source_id)

        if doc is None:
            return None

        # Administrators may read any status (to review drafts); everyone else only live documents
        if role != "Administrator" and not (
            doc["status"] == "approved" and (role if role in ROLES else "Analyst") in doc["allowed_roles"]
        ):
            return None

        out = _public(doc)
        out["source_id"] = doc["doc_id"]
        out["text"] = doc["body"]
        return out

    def import_seed(self, created_by: str) -> list[dict[str, Any]]:
        """Add the starter documents as drafts. Anything already present is left alone."""
        created = []

        for entry in json.loads((SEED_DIR / "manifest.json").read_text()):
            if self._store.has_slug(entry["slug"]):
                continue

            created.append(self.ingest(
                slug=entry["slug"], title=entry["title"], allowed_roles=entry["allowed_roles"],
                body=(SEED_DIR / entry["file"]).read_text(), created_by=created_by,
            ))

        return created

    def _require(self, doc_id: str) -> dict[str, Any]:
        doc = self._store.get_document(doc_id)

        if doc is None:
            raise KnowledgeError(404, f"Document {doc_id} was not found.")

        return doc


def _public(doc: dict[str, Any]) -> dict[str, Any]:
    """A document without its full text."""
    return {k: v for k, v in doc.items() if k != "body"}
