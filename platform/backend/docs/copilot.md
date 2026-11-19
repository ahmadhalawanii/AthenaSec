# Security Copilot

A read-only chat assistant over what AthenaSec has already recorded. It explains alerts, cases,
approvals and system status in plain language, quotes approved guidance documents, and shows
where each answer came from. It cannot block, approve, isolate or run anything.

## What it answers

| Ask about | Source it reads |
|---|---|
| Recent alerts ("any urgent problems?") | stored investigations |
| One alert or case by ID (`ALT-1`, `CASE-1`) | stored alert / case records |
| Pending approvals, or one by ID (`APR-1`) | approval requests and the policy decision behind them |
| Response mode, kill switch state | runtime status |
| "Is monitoring working?" | system health checks |
| Audit log (administrators only) | operator and incident audit events |
| How-to questions ("how should we respond to a brute force attack?") | approved knowledge documents, quoted from the matching section |
| Security terms ("what does brute force mean?") | built-in glossary |

Every answer carries its sources, a data status (stored, live or unavailable) and a "Checked"
time. When a source is down it says so and does not guess. Asking it to block, approve or run
something is refused and points to the Approvals page. Simple view changes the wording only;
**permissions never depend on the view.**

## Who can use it

- Every chat route uses the app's own sign-in and CSRF checks, and needs the same read
  permission as the Approvals page.
- Administrators additionally: audit-log questions, the Knowledge base page, and reading
  feedback. Analysts see only approved documents whose roles include Analyst.
- A conversation is private to the person who started it.

## Knowledge base

Documents are versioned and go through: **draft -> approved** (by an administrator). Approving a
new version of a document replaces the old one; revoking removes it from answers at once.

- Text that tries to instruct the assistant ("ignore previous instructions", "run the shell...")
  is **quarantined** on upload and cannot be approved.
- HTML and invisible characters are stripped on upload.
- Each document lists which roles may read it.
- Seven generic starter guides ship in `app/chat/knowledge/seed/`. They are **drafts written as
  a starting point**, not your organisation's procedures. An administrator must read and approve
  them (Knowledge base page, "Import starter documents"), or replace them with real ones.

Search is PostgreSQL full-text search over text split by heading. On a fixed set of 16
questions the right document is in the top 3 for 15, and 0 of 4 unrelated questions get a
document (`tests/test_chat_knowledge_base.py`).

## Settings

None are required. One optional setting exists and should stay off:

- `ATHENASEC_CHAT_QWEN` (default off). Rewording answers with `qwen3:4b` was unreliable in
  testing (it leaked its reasoning and dropped numbers), so answers are built from records
  without a language model. A guard in `app/chat/phrasing.py` makes it safe if enabled, but it
  is slow with thinking on and still rejects most replies.

## Database

Two migrations, both create new tables only and change nothing existing:

- `0012_chat_sessions`: `chat_sessions`, `chat_messages`, `chat_feedback`
- `0013_knowledge_base`: `knowledge_documents`, `knowledge_chunks`

`docker compose up -d --build` runs `alembic upgrade head` automatically (the `migrate`
service in `compose.yaml`). Roll back with `alembic downgrade 0011`, which drops only these
tables. Back up first (`pg_dump`, see `platform/SERVER_RUNBOOK.md`).

## Audit

Each answer writes one operator audit event: category `Copilot`, action `chat.answer`, with the
tools used and the data status. **The question and answer text are not stored in the audit
event.** If the audit write fails, the read-only answer is still returned. Adding, approving and revoking documents are audited the same way
(`knowledge.ingest`, `knowledge.approve`, `knowledge.revoke`).

## Try it locally (fake data)

Needs Python 3.14 with `requirements.txt` installed, and Node.

```bash
cd platform/backend && python tools/copilot_demo.py
cd platform/frontend && npm run dev
```

Open `http://localhost:8000/demo/login/analyst` (or `/demo/login/admin`). All data is made up,
there is no real sign-in, and the script refuses to start if `ATHENASEC_DATABASE_URL` is set.

## Tests

```bash
cd platform/backend
python -m pytest tests/test_chat_api.py tests/test_chat_knowledge_api.py \
  tests/test_chat_history_feedback.py tests/test_chat_phrasing.py \
  tests/test_chat_knowledge_base.py tests/test_chat_knowledge_text.py -q
```

`tests/test_chat_postgres.py` and the PostgreSQL variants of the knowledge tests run only when
`ATHENASEC_TEST_PG_URL` points at a migrated **throwaway** database. **They empty the knowledge
tables. Never point that variable at a real database.**

## Known limits

- It does not remember earlier messages in a conversation; each question is answered alone.
- Alert and case questions only; no incident-level summary by incident ID yet.
- No similar-case search, threat hunting, timelines or reports, and no way to propose a
  response from chat.
- No rate limit on chat requests.
- One administrator can approve a document they added themselves.
- It has been tested on fixtures and a local PostgreSQL, not on a deployed server's live data.
- No formal accessibility audit or usability test has been done.

## Where the code is

- `app/chat/service.py`: routing and answers. `app/chat/api.py`: routes.
- `app/chat/store.py`: sessions, messages, feedback (memory and PostgreSQL).
- `app/chat/knowledge/`: documents, ingestion, search, starter guides.
- `platform/frontend/src/components/CopilotChat.tsx`, `CopilotLauncher.tsx`,
  `pages/CopilotPage.tsx`, `pages/KnowledgePage.tsx`.
