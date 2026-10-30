# Backend: the AthenaSec agent

Python 3.14 · FastAPI · LangGraph · Ollama · SQLite or Postgres.

Receives Wazuh alerts, investigates them with a LangGraph pipeline, scores risk, checks the admin's response policy, asks a person to approve risky actions, runs approved actions through Cortex, then verifies them and undoes them when they expire.

## Folders

| Folder / file | What it is |
| --- | --- |
| `app/main.py` | The API: every HTTP route the frontend and Wazuh call. `GET /api/v1/approvals/{id}/action` returns what an approval asks for. |
| `app/schemas.py` | Every data shape: alerts, investigations, approvals, cases, etc. |
| `app/llm.py` | Connection to the local language model (Ollama). |
| `app/graph/` | The investigation pipeline. `graph.py` wires the steps; `nodes/` holds one file per step. |
| `app/services/` | The business logic, grouped by topic (table below). |
| `app/ml/` | Loads and runs the trained alert classifier. |
| `app/tools/` | Reading alerts from Wazuh (real indexer or mock). |
| `training/` | Training the ML classifier. `adapters/` converts each public dataset. |
| `models/` | The trained classifier file used at runtime. |
| `data/` | Local SQLite database and training data (created when you run it). |
| `migrations/` | Postgres database schema changes (Alembic). |
| `integrations/custom-athenasec.py` | Script installed into Wazuh that forwards alerts to this API. |
| `tests/` | 1,463 automated tests. Run `python -m pytest -q`. |
| `demos/` | Small end-to-end scripts. Run `python -m demos.demo_graph` from this folder. |
| `docs/` | Design notes: backend plan, database plan, API ID mapping, test matrix. |
| `tools/regroup_services.py` | The script that grouped `app/services/` (see "For teammates"). |
| `Dockerfile`, `compose.yaml` | Run the backend and Postgres in Docker. |
| `.env.example` | Settings template. Copy to `.env`; the API, `alembic` and the account command all read it. |

## Investigation pipeline (`app/graph/nodes/`)

The main path, as wired in `graph.py`: `normalize` → `classify_ml` → `misp_enrichment` → `analyze` → `evidence_sufficiency` → `verify_analysis` → `risk` → `propose_response` → `assess_action_risk` → `policy` → `response_plan` → `finalize`.

If the evidence is not enough, the agent loops: `gather_evidence` → back to `analyze`. Some steps are skipped depending on settings (for example when ML or MISP is turned off). The routing rules are in `app/graph/routing.py`.

## Services (`app/services/`)

| Group | What it does |
| --- | --- |
| `investigations/` | Turns alerts into investigations: correlation into incidents, evidence checks, analysis checks, the investigation database. |
| `risk/` | Risk scores for incidents and for each proposed action. |
| `policy/` | The action policy the agent enforces (see below), plus the older target lists (`/api/v1/policies`, stored only). |
| `response/` | Plans and runs a response: proposals, autonomous mode, the structured runtime. |
| `approvals/` | Human approval: ties an approval to the exact action and records the decision. |
| `execution/` | Carries out approved actions, verifies them, rolls them back. Protects targets that must never be touched. |
| `containment/` | Time-limited blocks: tracks expiry and undoes them automatically. |
| `cortex/` | Talks to Cortex to run and check actions. |
| `misp/` | Threat intelligence lookups in MISP. |
| `cases/` | Incident cases and the case workflow. |
| `audit/` | Audit trail of what the agent and each operator did. |
| `auth/` | Web console sign-in and operator identities. |
| `health/` | Checks each service is up and records outages. |
| `runtime/` | Admin switches that apply at runtime, such as pausing the agent. |
| `dashboard/` | Dashboard numbers and shared list paging. |
| `storage/` | Picks the database (memory, SQLite, Postgres) and holds the main response-record store. |

## Merged from the team's `semi-main` branch (Daniel)

- **Evidence-bound analysis:** the live model may only cite this investigation's evidence IDs (`analyze_security_event_with_evidence` in `app/llm.py`).
- **Operational events:** a Wazuh manager startup (rule 502) is recorded without ML or the agent and never leads to a response (`app/ml/operational_events.py`).
- **Evidence sufficiency:** the alert itself no longer counts as corroborating evidence.
- **Classifier v3** (`models/athenasec-classifier-v3.pkl`) is the default; v1 stays for comparison.
- Phase 0 contracts and gates: `docs/phase0/`.

## Submitting an alert by hand

`POST /api/v1/analyze` starts an investigation, so it needs a signed-in operator: a browser session plus the `X-AthenaSec-CSRF` header, or an operator token for scripts (`Authorization: Bearer <token>`, made with `python -m app.services.auth.operator_identity provision <operator_id>`). Without one it answers 401. Wazuh does not use this route: it sends alerts to `/api/v1/integrations/wazuh/alerts` with its own ingest key.

If Ollama is not running (or does not have the model), both routes answer **503** with the reason, for example "Is Ollama running?" or "Run: ollama pull qwen3:4b", and the alert is not investigated. For Wazuh alerts an `investigation_failed` event is added to the incident's audit trail. Start Ollama and send the alert again.

## The action policy (whitelist and blacklist)

The administrator decides which actions the agent may use, on the website's Response Policies page. The agent reads the newest saved version for every investigation; until one is saved, the built-in default applies (`policy/action_catalogue.py`).

- **Tier 1** (get_logs, monitor, create_ticket, capture_telemetry, ...): may run automatically.
- **Tier 2** (block_ip, isolate_host, ...): always wait for a person's approval, within caps the admin cannot raise: longest duration, time to decide, who approves, minimum incident risk. There is no automatic block any more.
- **Tier 3** (delete_logs, permanent blocks, changing its own policy, ...): always blacklisted.
- Anything on neither list is denied. Never-block and never-isolate lists protect targets; the internal ranges cannot be removed.

The decision for each proposed action, in order: blacklisted → denied; not whitelisted → denied; protected target → denied; longer than allowed → denied; incident risk under the minimum → held back; otherwise sent for approval with the admin's decision window.

| Route | Who | What |
| --- | --- | --- |
| `GET /api/v1/policies/actions` | any signed-in user | The policy in force (version 0 = the default) |
| `GET /api/v1/policies/actions/versions` | admin | Every saved version, newest first |
| `PUT /api/v1/policies/actions` | admin + CSRF | Save a new version. 422 lists every rule broken; 409 if someone saved first. Audited as `action_policy_updated`. |

Storage is append-only (`action_policy_versions`, created by migration `0007`). After pulling, run `alembic upgrade head`.

## Website routes (live mode)

Browser routes need a signed-in session; every change also needs the `X-AthenaSec-CSRF` header and writes an operator audit event.

| Route | Who | What |
| --- | --- | --- |
| `POST /api/v1/alerts/{id}/status`, `POST /api/v1/alerts/{id}/assign` | signed in | Close/reopen an alert, assign it to yourself (`alert_workflow`, migration `0008`) |
| `POST /api/v1/cases/{id}/status`, `POST /api/v1/cases/{id}/assign`, `PUT /api/v1/cases/{id}/actions/{position}` | signed in | Close/reopen, assign, tick a recommended action (actions waiting on an approval cannot be ticked) |
| `GET /api/v1/responses` | signed in | Executed actions with approval, result, verification and rollback |
| `POST /api/v1/users`, `PUT /api/v1/users/{id}`, `POST /api/v1/users/{id}/status`, `DELETE /api/v1/users/{id}`, `POST /api/v1/users/{id}/reset-password` | admin | Account administration. Create and reset return a temporary password once. You cannot suspend, delete or change the role of your own account, and AthenaSec always keeps one active administrator. |
| `POST /api/v1/users/{id}/reset-mfa` | admin | Lost phone: a new authenticator secret (returned once as an `otpauth://` link). The old codes stop working and the user is signed out. |
| `GET/PUT /api/v1/configuration` | read: signed in, save: admin | System configuration (`app_settings`, migration `0009`). `correlation_window_minutes` is used when Wazuh alerts are grouped into incidents; the other values are recorded and shown. |
| `GET/PUT /api/v1/me/settings`, `GET/PUT /api/v1/me/profile`, `POST /api/v1/me/password`, `GET /api/v1/me/activity` | yourself | Personal settings, profile, password change, your own sign-in history |

**Temporary passwords:** an account created by an administrator, or whose password was reset, must choose its own password at the next sign-in. Until then every route except `/auth/me`, `/auth/logout` and `/me/password` answers 403, and `/auth/me` reports `must_change_password: true` (migration `0010`).

After pulling, run `alembic upgrade head` (adds `0008` to `0010`).

## For teammates: imports changed

Files in `app/services/` moved into the groups above, so imports changed, for example:

```
from app.services.approvals.action_approval import build_action_fingerprint
→ from app.services.approvals.action_approval import build_action_fingerprint
```

If you have unmerged work that still uses the old paths, run this once from `backend/` after pulling:

```
python tools/regroup_services.py --imports
```

It only rewrites import lines; it does not change any logic.
