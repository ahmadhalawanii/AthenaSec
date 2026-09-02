# AthenaSec Codebase Technical Guide

## 1. What AthenaSec is right now

AthenaSec currently has two major codebases:

1. **`agent/`** — the working Python/FastAPI/LangGraph cybersecurity investigation backend.
2. **`website/frontend/`** — a high-fidelity React + TypeScript SOC frontend prototype that is currently driven by local/mock data and is **not yet connected to the Python backend**.

The backend has already proven a real Wazuh-to-AthenaSec path. The frontend is currently a UI prototype. MISP, trained ML models, real Cortex execution, fully relational case management, and complete audit logging are **planned target architecture**, not current functionality.

### Current backend flow

```text
Wazuh alert / manual alert
        |
        v
FastAPI
        |
        v
LangGraph investigation
  normalize_alert
        |
        v
  analyze_alert --> Qwen through Ollama
        |
        +---- if Qwen requests evidence ----+
        |                                   |
        |                             gather_evidence
        |                                   |
        +<----------------------------------+
        |
        v
  calculate_risk
        |
        v
  evaluate_policy
        |
        v
  create_response_plan
        |
        v
  finalize_investigation
        |
        v
SQLite persistence
```

### Intended final flow agreed by the team

```text
Endpoint -> Wazuh Agent -> Wazuh Manager -> Wazuh Indexer
                                          |
                                          v
                                     AthenaSec API
                                          |
                                          v
                                 trained ML classification
                                          |
                         +----------------+----------------+
                         |                                 |
                         v                                 v
                    Wazuh evidence                      MISP
                         |                                 |
                         +---------------+-----------------+
                                         v
                               LangGraph + Qwen investigation
                                         |
                                         v
                              deterministic risk engine
                                         |
                                         v
                              deterministic policy engine
                                         |
                          +--------------+--------------+
                          |                             |
                    NOT ALLOWED                     ALLOWED
                          |                             |
                          v                             v
                  create DB case                  Cortex action
                          |                             |
                          +-------------+---------------+
                                        v
                         PostgreSQL + complete audit log
                                        |
                                        v
                                  React dashboard
```

**Important:** the final design is fully autonomous. The existing analyst-approval code is legacy/current prototype logic and is expected to be removed or refactored. The autonomous system should still use deterministic policy boundaries; the LLM itself should not be the component that grants its own unrestricted execution authority.

## 2. Repository map

```text
AthenaSec/
├── agent/                         Python backend / investigation agent
│   ├── app/
│   │   ├── graph/                 LangGraph orchestration
│   │   ├── services/              deterministic business logic + persistence
│   │   ├── tools/                 Wazuh/evidence adapters
│   │   ├── llm.py                 Qwen/Ollama adapter and prompt
│   │   ├── main.py                FastAPI application
│   │   └── schemas.py             central Pydantic contracts
│   ├── integrations/              Wazuh manager-side forwarder
│   ├── tests/                     backend automated tests
│   ├── data/                      local SQLite state
│   ├── Dockerfile
│   └── compose.yaml
├── ollama/                        helper shell script for Ollama
└── website/
    ├── frontend/                  Vite + React + TypeScript frontend
    ├── prototype/                 older static HTML/CSS/JS prototype
    └── docs/                      frontend migration/logic documentation
```

## 3. Backend: central data contracts — `agent/app/schemas.py`

This is the most important contract file in the backend. Almost every graph node and service imports models from here. If a field is changed here, tests, graph state, API responses, storage, policies, and frontend API contracts may also need to change.

### `SecurityAlertInput`

| Field | Meaning |
|---|---|
| `alert_id: str` | AthenaSec's unique identifier for the incoming alert. |
| `source` | One of `manual`, `mock`, `wazuh`, `dataset`. |
| `event_text` | Human-readable/raw security event text; must be non-empty. |
| `metadata: dict[str, Any]` | Structured facts used by deterministic logic, e.g. failed attempts, source IP, asset criticality. |

### Classification and severity literals

- `AttackClassification`: `brute_force`, `privilege_escalation`, `privilege_misuse`, `benign`, `unknown`.
- `SeverityAssessment`: `low`, `medium`, `high`, `critical`.
- `RiskBand`: `low`, `medium`, `high`, `critical`.
- `AssetCriticality`: `low`, `medium`, `high`, `critical`.

### Evidence contracts

- `EvidenceRequest`: `authentication_history`, `source_endpoint_context`, `privilege_activity`, `related_security_events`.
- `EvidenceSource`: currently allows `alert`, `mock_wazuh`, `wazuh`, `opensearch`, `cortex`, `thehive`, `dataset`. The `opensearch` and `thehive` names reflect the older architecture and should eventually be updated for the final Wazuh Indexer + DB-case design.
- `EvidenceReference` is a plain string because Ollama's structured JSON grammar works better this way.
- `validate_evidence_reference()` enforces the local `E001`, `E002`, ... format.
- `EvidenceObservation` is a raw observation returned by a tool before AthenaSec gives it an immutable evidence ID.
- `EvidenceRecord` is frozen (`frozen=True`) and rejects extra fields. This is the immutable evidence object used inside the graph.

### `AlertAnalysis`

This is the structured object Qwen must produce. Its important fields are:

- `classification`
- `confidence` from `0.0` to `1.0`
- `severity_assessment`
- `summary`
- `evidence_refs` — at least one valid `E###` reference
- `uncertainties`
- `recommended_investigation_steps`
- `recommended_response_actions`
- `requested_evidence` — max two evidence types
- `needs_more_evidence`

### Risk contracts

`RiskContext` contains deterministic facts consumed by the Python risk engine:

- `failed_attempts`
- `privileged_target`
- `successful_authentication`
- `privilege_change_observed`
- `policy_violation_observed`
- `asset_criticality`

`RiskFactor` records one point contribution (`name`, `points`, `reason`). `RiskAssessment` stores final `score`, `band`, and the factor list.

### Current response/approval contracts

These are current implementation contracts but conflict with the newly agreed fully autonomous final architecture:

- `AllowedAction`: `block_ip`, `lock_account`, `notify_administrator`, `create_case`, `capture_telemetry`, `record_response`.
- `ApprovalType`: `none`, `analyst`, `automatic`.
- `ExecutionMode`: currently only `dry_run`.
- `PolicyDecision`: policy match + approval mode + actions.
- `ResponsePlan`: converted policy result with a workflow status.
- `AnalystDecision`: approve/reject with analyst identity and reason.
- `DryRunExecutionResult`: simulated execution only.

### `InvestigationResponse`

This is the FastAPI response and the exact object persisted to SQLite. It contains the alert identity, normalized event, Qwen analysis, evidence, deterministic risk, policy decision, response plan, optional execution result, and investigation iteration.

## 4. Backend: LLM layer — `agent/app/llm.py`

Purpose: configure Qwen through Ollama and force it to return `AlertAnalysis`.

### Environment variables

- `OLLAMA_BASE_URL` — defaults to `http://localhost:11434`.
- `OLLAMA_MODEL` — code default is `qwen3:8b`; `.env.example` currently suggests `qwen3:4b`.

### Key variables/functions

- `SYSTEM_PROMPT` — defines grounding rules, allowed evidence requests, response limitations, and current attack scope.
- `create_analysis_model()` — creates `ChatOllama(temperature=0, reasoning=False, keep_alive='30m')` and wraps it with `with_structured_output(AlertAnalysis)`.
- `analyze_security_event(event)` — sends the system prompt plus the supplied evidence context to the model.

The LLM currently performs classification itself. In the agreed final Option-A architecture, a trained ML classifier will be inserted before the agentic investigation, and Qwen should become primarily an investigator/reasoner rather than the authoritative first classifier.

## 5. Backend: LangGraph state and orchestration

### `agent/app/graph/state.py`

Defines `InvestigationStatus` and `InvestigationState`. `InvestigationState` is a `TypedDict` shared by every node. Keys include:

`alert`, `normalized_event`, `evidence_records`, `analysis`, `risk_context`, `risk_assessment`, `policy_decision`, `response_plan`, `investigation_iteration`, `status`.

### `agent/app/graph/graph.py`

`build_investigation_graph()` wires the workflow. It accepts injectable `analyzer` and `evidence_provider` callables so tests can replace real Ollama/Wazuh dependencies. Default analyzer is `analyze_security_event`; default evidence provider comes from `create_evidence_provider()`.

Graph edges:

```text
START -> normalize_alert -> analyze_alert
                         |
                         + conditional route
                         |
             +-----------+-----------+
             |                       |
             v                       v
      gather_evidence           calculate_risk
             |                       |
             +-> analyze_alert       v
                               evaluate_policy
                                      |
                                      v
                              create_response_plan
                                      |
                                      v
                              finalize_investigation
                                      |
                                      v
                                     END
```

### `agent/app/graph/routing.py`

- `MAX_INVESTIGATION_ITERATIONS = 1` limits evidence re-analysis loops.
- `route_after_analysis(state)` sends the graph to `gather_evidence` only when Qwen sets both `needs_more_evidence=True` and a non-empty `requested_evidence`, and the max iteration count has not been reached. Otherwise it goes straight to risk.

This is a known design weakness for the final architecture: currently the LLM decides whether evidence gathering happens. The planned design should deterministically gather required Wazuh/MISP evidence for relevant attack classes before or alongside Qwen.

## 6. Backend: graph node files

### `agent/app/graph/nodes/normalize.py`

`normalize_alert(state)` collapses whitespace in `alert.event_text`, creates immutable evidence `E001` with `source='alert'`, initializes `investigation_iteration=0`, and changes status to `normalized`.

### `agent/app/graph/nodes/analyze.py`

`build_analysis_context()` serializes immutable evidence records into the prompt. `validate_evidence_references()` rejects Qwen references to IDs that do not exist. `make_analyze_alert_node(analyzer)` creates the graph node that invokes Qwen/test analyzer and returns `analysis`.

### `agent/app/graph/nodes/gather_evidence.py`

`make_gather_evidence_node(evidence_provider)` calls the configured provider with Qwen's requested evidence types, converts returned `EvidenceObservation`s into sequential immutable IDs (`E002`, `E003`, ...), appends them, increments `investigation_iteration`, and returns to analysis.

### `agent/app/graph/nodes/risk.py`

`build_risk_context()` pulls deterministic risk facts out of `alert.metadata`. `calculate_investigation_risk()` calls the Python risk engine and writes both `risk_context` and `risk_assessment`.

### `agent/app/graph/nodes/policy.py`

`evaluate_investigation_policy()` passes Qwen classification + deterministic risk score into `evaluate_policy()` and stores `policy_decision`.

### `agent/app/graph/nodes/response_plan.py`

`create_investigation_response_plan()` converts a `PolicyDecision` into a `ResponsePlan` by calling `create_response_plan()`.

### `agent/app/graph/nodes/finalize.py`

`finalize_investigation()` only changes the graph status to `complete`.

### `agent/app/graph/nodes/__init__.py`

Package marker; currently no executable logic.

### `agent/app/graph/__init__.py`

Package marker; currently no executable logic.

## 7. Backend: deterministic services

### `agent/app/services/risk_engine.py`

This is the deterministic scoring authority. Qwen supplies classification/confidence; Python supplies the actual numerical score.

`BASE_RISK`: brute force `30`, privilege escalation `45`, privilege misuse `40`, benign `0`, unknown `10`.

`ASSET_POINTS`: low `0`, medium `5`, high `10`, critical `15`.

Additional rules:

- non-unknown classification: `round(confidence * 10)` points
- privileged target: `+15`
- brute force failed attempts: `>=5 +5`, `>=20 +10`, `>=100 +15`
- successful authentication during suspicious activity: `+20`
- observed privilege change for escalation/misuse: `+20`
- confirmed privilege-policy violation for privilege misuse: `+15`
- score capped at `100`

`determine_risk_band()`: critical `>=90`, high `>=70`, medium `>=40`, else low.

### `agent/app/services/policy_engine.py`

Current policy implementation:

- benign -> no policy
- brute force risk `>=90` -> `POL-BF-CRITICAL`, current `automatic`, dry-run actions include block IP, notify admin, create case, record response
- brute force risk `>=70` -> `POL-BF-HIGH`, current analyst approval
- privilege misuse risk `>=80` -> `POL-PM-HIGH`, current analyst approval
- otherwise -> `NONE`

This file is a major planned refactor because final AthenaSec has **no approvals**. The desired output should become an autonomous `ALLOWED`/`NOT_ALLOWED` policy decision: `NOT_ALLOWED -> DB case`; `ALLOWED -> Cortex action`, with both paths fully logged.

### `agent/app/services/response_planner.py`

Current adapter from `PolicyDecision` to workflow state. Unmatched policies become `no_action`; analyst policies become `pending_approval`; automatic policies become `ready_for_dry_run`. This is legacy workflow logic for the final autonomous design.

### `agent/app/services/approval_service.py`

Current legacy approval implementation. `apply_analyst_decision()` only accepts plans in `pending_approval`, validates analyst-mode approval, then moves to `approved` or `rejected` and appends the analyst identity/reason to the response-plan reason. **Planned to remove/refactor** because final AthenaSec self-authorizes through policy.

### `agent/app/services/dry_run_executor.py`

Current safe executor. It only accepts response plans with status `approved` or `ready_for_dry_run`, requires `execution_mode='dry_run'`, and returns one simulated `ActionExecutionResult` per action. It never performs a real block/lock/isolation action. The final executor boundary will call Cortex for policy-allowed actions.

### `agent/app/services/investigation_store.py`

Defines a storage protocol and two implementations:

- `InvestigationStore` protocol — `save`, `get`, `update_response_plan`, `update_execution_result`.
- `InMemoryInvestigationStore` — dictionary-backed store used in tests/dev injection.
- `SQLiteInvestigationStore` — creates `investigations(alert_id TEXT PRIMARY KEY, payload TEXT NOT NULL)` and persists the entire `InvestigationResponse` as one JSON string.

This is enough for the prototype but not the final requirement that every decision/action/case/MISP/Cortex event is independently queryable and auditable. Final storage should become relational PostgreSQL with normalized investigation/audit/case/action tables.

### `agent/app/services/__init__.py`

Empty package marker.

## 8. Backend: Wazuh and evidence tools

### `agent/app/tools/evidence_provider.py`

Factory that chooses the evidence backend based on `ATHENASEC_EVIDENCE_PROVIDER`:

- `mock` -> `mock_wazuh.gather_requested_evidence`
- `wazuh` -> constructs a `WazuhIndexerClient` using `WAZUH_INDEXER_URL`, `WAZUH_INDEXER_USERNAME`, `WAZUH_INDEXER_PASSWORD`, `WAZUH_VERIFY_SSL`, wraps it in `WazuhEvidenceProvider`, and returns `provider.gather`.

`_as_bool()` parses `1/true/yes/on`.

### `agent/app/tools/mock_wazuh.py`

Fake evidence provider used to exercise agentic evidence loops without a live Wazuh stack. `TOOL_REGISTRY` maps each `EvidenceRequest` to one mock function. It returns canned SSH/endpoint/privilege/security-event observations and should never be confused with production evidence.

### `agent/app/tools/wazuh_alert_parser.py`

Converts either a raw Wazuh alert or Wazuh Indexer hit (`_source`) into `SecurityAlertInput`.

Important behavior:

- accepts `_source` wrapper or raw payload
- uses Indexer document `_id` when present; otherwise Wazuh alert `id`
- creates AthenaSec IDs as `index:_id` for Indexer hits or `wazuh:<id>` for raw alerts
- event text uses `full_log`, then `rule.description`, then fallback text
- current metadata preserves `wazuh_alert_id`, document/index IDs, timestamp, `rule_id`, `rule_level`, `rule_groups`, agent fields, source/target user/IP/port fields, and location

Known current gap: it does **not** yet preserve enough correlation context such as `rule.description`, `rule.frequency`, `previous_output`, decoder/MITRE fields, or derive deterministic `failed_attempts`. That is why the real Wazuh brute-force alert scored lower than the equivalent manually enriched alert.

### `agent/app/tools/wazuh_indexer.py`

This is the real Wazuh Indexer search adapter.

Key pieces:

- `WazuhSearchClient` protocol — testable search interface.
- `WazuhIndexerClient` — HTTP Basic Auth client using `requests`; `search_alerts()` POSTs to `wazuh-alerts*/_search`; `health()` GETs `_cluster/health`.
- `_get_alert_scope()` derives `source_ip`, `target_user`, `agent_id` from AthenaSec alert metadata.
- `_base_query()` creates a size-20, newest-first query.
- `build_wazuh_query()` builds evidence-specific queries.
- `_nested()` safely reads nested dictionaries.
- `format_wazuh_hit()` converts a Wazuh hit into a grounded semicolon-separated text record.
- `WazuhEvidenceProvider.gather()` deduplicates requested evidence types, searches, formats hits, and returns `EvidenceObservation(source='wazuh', ...)`.

Current query logic:

- authentication history -> rule groups `authentication_failed` or `authentication_success` plus alert scope
- endpoint context -> scope-only search
- privilege activity -> scope search (currently broad; it does not yet strongly constrain to privilege-specific Wazuh rules)
- related events -> scope + `rule.level >= 7`

### `agent/app/tools/__init__.py`

Empty package marker.

## 9. Backend: FastAPI — `agent/app/main.py`

`create_app()` is the backend composition root. It injects or creates the investigation graph, investigation store, and Wazuh ingest key.

### Startup dependencies

- graph: injected test graph or `build_investigation_graph()`
- store: injected store or `SQLiteInvestigationStore(ATHENASEC_DB_PATH)`
- Wazuh ingest key: function argument or `ATHENASEC_WAZUH_INGEST_KEY`

### Internal `run_investigation(alert)`

Calls `graph.invoke({'alert': alert, 'status':'received'})`, converts graph state into `InvestigationResponse`, saves it, and returns it.

### Current endpoints

| Method | Endpoint | What it does |
|---|---|---|
| GET | `/health` | returns basic API health only |
| POST | `/api/v1/analyze` | accepts `SecurityAlertInput`, runs full graph, persists result |
| POST | `/api/v1/integrations/wazuh/alerts` | protected Wazuh ingress; validates integration key with constant-time `secrets.compare_digest`, parses Wazuh payload, runs graph |
| GET | `/api/v1/investigations/{alert_id}` | loads persisted investigation |
| POST | `/api/v1/investigations/{alert_id}/decision` | current analyst approve/reject endpoint; legacy for final design |
| POST | `/api/v1/investigations/{alert_id}/execute` | idempotent dry-run execution; returns stored result on repeats |

The module-level `app = create_app()` is what Uvicorn imports.

## 10. Wazuh Manager integration — `agent/integrations/custom-athenasec.py`

This file is copied into `/var/ossec/integrations/custom-athenasec.py` on the Wazuh Manager.

- Linux shebang: `#!/var/ossec/framework/python/bin/python3`
- `TIMEOUT_SECONDS = 30`
- `INTEGRATION_HEADER = 'X-AthenaSec-Integration-Key'`
- `load_alert(path)` reads Wazuh's temporary JSON alert file
- `build_request()` creates an HTTP POST with JSON and integration secret header
- `send_alert()` performs the HTTP request and requires a 2xx JSON-object response
- `main()` expects Wazuh argument order `<alert_file> <api_key> <hook_url>`, returns conventional exit codes, and prints errors to stderr

**Line-ending requirement:** this script must use LF, not CRLF, because the Wazuh Manager runs Linux and the shebang fails if `\r` is present. Both root and agent `.gitattributes` currently enforce LF for this path.

Known architecture issue: this forwarder waits synchronously for the full investigation, so Qwen latency can approach/exceed its 30-second timeout. The final system should acknowledge/store the alert quickly and run investigation asynchronously in a worker.

## 11. Backend runtime/config files

### `agent/.env.example`

Safe template of environment variable names. It configures Ollama, SQLite path, evidence-provider mode, Wazuh Indexer credentials/SSL mode, and Wazuh ingest key placeholder. Never put real secrets here.

### `agent/.env`

Local runtime secret/config file. Present in the uploaded ZIP but intentionally not documented value-by-value. It is ignored by Git and should not be shared.

### `agent/Dockerfile`

Builds from `python:3.14-slim`, installs `requirements.txt`, copies only `app/`, creates `/app/data`, exposes 8000, and starts Uvicorn with `app.main:app`. Notice that `integrations/` and tests are not copied into the API image.

### `agent/compose.yaml`

Simple standalone AthenaSec service definition. Maps port 8000, points Ollama to `host.docker.internal:11434`, mounts local `./data`, and restarts unless stopped. It does not currently define Wazuh, MISP, Cortex, PostgreSQL, or a worker.

### `agent/.dockerignore`

Excludes virtualenv, caches, Git data, `.env`, tests, demos, and database files from Docker build context.

### `agent/requirements.txt`

Pinned Python dependency snapshot including FastAPI, Pydantic, LangGraph, LangChain Ollama, requests, pytest, etc. The uploaded file is encoded with a UTF-16 BOM; team members should be aware of this if editing with tools that assume UTF-8.

### `agent/pytest.ini`

Sets pytest configuration; currently very small.

### `agent/.gitattributes`

Enforces LF for `integrations/custom-athenasec.py`.

### `agent/data/athenasec.db`

Local SQLite runtime database; not source code and should not be committed/shared as canonical state.

### `.gitattributes`

Root-level LF rule for the Wazuh forwarder.

### `.gitignore`

Ignores Python caches, virtualenvs, `.env`, IDE/OS files, pytest coverage, logs, and SQLite database artifacts.

### `README.md`

Root README currently contains only the project title; it is not yet useful onboarding documentation.

### `ollama/start.sh`

Linux helper that points `OLLAMA_MODELS` at a local `models` directory, binds Ollama to `127.0.0.1:11434`, and executes the bundled Ollama server binary.

## 12. Demo scripts

- `agent/demo_ollama.py` — direct raw ChatOllama experiment against a hard-coded SSH brute-force prompt. Bypasses LangGraph and structured AthenaSec services.
- `agent/demo_structured_analysis.py` — calls `analyze_security_event()` and prints structured `AlertAnalysis` fields.
- `agent/demo_graph.py` — invokes the full LangGraph with a sample alert and prints analysis, evidence references, risk factors, policy decision, and final state. Useful as a developer smoke test, not production.

## 13. Backend tests: what each test file protects

### `agent/tests/test_analysis_schema.py`

Pydantic model constraints, evidence ID validation, immutability, requested-evidence validation, confidence bounds.

Tests: `test_valid_alert_analysis`, `test_confidence_cannot_exceed_one`, `test_analysis_accepts_requested_evidence`, `test_analysis_rejects_unknown_evidence_type`, `test_evidence_reference_requires_valid_id`, `test_evidence_record_is_immutable`, `test_analysis_rejects_empty_evidence_refs`.

### `agent/tests/test_analyze_node.py`

Prompt context is built from evidence and Qwen/test analyzer cannot cite nonexistent or empty evidence references.

Tests: `test_analyze_node_uses_evidence_records`, `test_analyze_node_rejects_nonexistent_reference`, `test_analyze_node_rejects_empty_evidence_refs`.

### `agent/tests/test_api.py`

FastAPI health/analyze/retrieve/decision/execute flows, idempotent execution, error status behavior, and SQLite persistence across app restart.

Tests: `test_health_endpoint`, `test_analyze_endpoint_returns_investigation`, `test_analyzed_investigation_can_be_retrieved`, `test_analyst_can_approve_investigation`, `test_missing_investigation_returns_404`, `test_second_analyst_decision_is_rejected`, `test_approved_investigation_can_execute_dry_run`, `test_pending_investigation_cannot_execute`, `test_missing_investigation_cannot_execute`, `test_repeated_execute_returns_saved_result`, `test_sqlite_investigation_survives_app_restart`.

### `agent/tests/test_approval_service.py`

Current legacy analyst approve/reject workflow.

Tests: `test_analyst_can_approve_pending_plan`, `test_analyst_can_reject_pending_plan`, `test_cannot_approve_plan_that_is_not_pending`.

### `agent/tests/test_dry_run_executor.py`

Only eligible plans can execute and all actions remain simulation-only.

Tests: `test_pending_plan_cannot_execute`, `test_approved_plan_executes_as_simulation`, `test_automatic_policy_can_execute_dry_run`.

### `agent/tests/test_finalize_node.py`

Final graph status becomes `complete`.

Tests: `test_finalize_marks_investigation_complete`.

### `agent/tests/test_gather_evidence_node.py`

Evidence observations receive sequential immutable E-IDs.

Tests: `test_gather_evidence_assigns_immutable_ids`.

### `agent/tests/test_graph_state.py`

Typed graph state accepts a security alert.

Tests: `test_investigation_state_accepts_security_alert`.

### `agent/tests/test_investigation_graph.py`

Integrated graph creates the expected response plan with fake analyzer/evidence provider.

Tests: `test_graph_creates_pending_response_plan`.

### `agent/tests/test_investigation_store.py`

In-memory and SQLite save/get/update/persistence behavior.

Tests: `test_store_saves_and_retrieves_investigation`, `test_store_updates_response_plan`, `test_updating_missing_investigation_fails`, `test_store_updates_execution_result`, `test_sqlite_store_persists_across_instances`, `test_sqlite_store_persists_response_plan_update`, `test_sqlite_store_persists_execution_result`.

### `agent/tests/test_mock_wazuh.py`

Mock evidence registry returns only requested evidence types.

Tests: `test_gathers_only_requested_authentication_evidence`, `test_gathers_endpoint_context_when_requested`, `test_gathers_multiple_requested_evidence_types`.

### `agent/tests/test_normalize_node.py`

Whitespace normalization and creation of initial `E001` evidence.

Tests: `test_normalize_alert_creates_initial_evidence`.

### `agent/tests/test_policy_engine.py`

Risk/classification-to-policy thresholds and benign/no-policy behavior.

Tests: `test_high_brute_force_requires_analyst_approval`, `test_critical_brute_force_matches_critical_policy`, `test_high_privilege_misuse_requires_approval`, `test_low_risk_does_not_match_response_policy`, `test_benign_event_never_matches_response_policy`.

### `agent/tests/test_policy_node.py`

Graph policy node calls policy engine correctly.

Tests: `test_policy_node_evaluates_high_brute_force`.

### `agent/tests/test_response_plan.py`

Policy decision -> response plan status mapping.

Tests: `test_analyst_policy_creates_pending_plan`, `test_automatic_policy_is_ready_for_dry_run`, `test_unmatched_policy_creates_no_action_plan`.

### `agent/tests/test_response_plan_node.py`

Graph response-plan node integration.

Tests: `test_response_plan_node_creates_pending_approval`.

### `agent/tests/test_risk_engine.py`

Deterministic risk rules, critical/high examples, benign zero, and score cap.

Tests: `test_brute_force_against_privileged_account_is_high`, `test_successful_authentication_makes_case_critical`, `test_confirmed_privilege_misuse_can_be_critical`, `test_benign_event_has_zero_risk`, `test_risk_score_never_exceeds_100`.

### `agent/tests/test_risk_node.py`

Alert metadata -> `RiskContext` -> risk calculation integration.

Tests: `test_risk_node_calculates_risk_from_alert_metadata`.

### `agent/tests/test_routing.py`

Evidence-loop routing and max-iteration behavior.

Tests: `test_routes_to_evidence_when_requested`, `test_routes_to_risk_when_evidence_not_needed`, `test_routes_to_risk_when_no_tool_requested`, `test_routes_to_risk_after_max_iterations`.

### `agent/tests/test_wazuh_alert_parser.py`

Raw Wazuh and Indexer-hit parsing, fallback event text, invalid ID rejection.

Tests: `test_parses_raw_wazuh_alert`, `test_parses_wazuh_indexer_hit`, `test_rule_description_is_used_when_full_log_missing`, `test_alert_without_identifier_is_rejected`.

### `agent/tests/test_wazuh_forwarder.py`

Manager-side forwarder file loading, request header/body, Wazuh argv order, missing args.

Tests: `test_load_alert_reads_wazuh_json`, `test_build_request_uses_key_and_json`, `test_main_uses_wazuh_argument_order`, `test_main_rejects_missing_arguments`.

### `agent/tests/test_wazuh_indexer.py`

Wazuh query construction, provider formatting, HTTP search call, and health endpoint.

Tests: `test_authentication_query_uses_alert_scope`, `test_endpoint_query_uses_source_ip`, `test_related_events_query_requires_high_level`, `test_provider_returns_grounded_wazuh_evidence`, `test_indexer_client_calls_wazuh_search`, `test_indexer_client_checks_cluster_health`.

### `agent/tests/test_wazuh_ingestion.py`

Protected Wazuh FastAPI endpoint: missing/wrong keys, valid ingestion, invalid alert, disabled config.

Tests: `test_wazuh_ingestion_requires_key`, `test_wazuh_ingestion_rejects_wrong_key`, `test_wazuh_ingestion_creates_investigation`, `test_wazuh_ingestion_rejects_invalid_alert`, `test_wazuh_ingestion_disabled_without_key`.

`agent/tests/__init__.py` is an empty package marker.

## 14. Frontend architecture

Current frontend flow:

```text
index.html
   -> src/main.tsx
      -> <App />
         -> LoginPage -> MfaPage
         -> AppLayout
            -> TopBar
            -> Sidebar
            -> selected Page component
```

There is no real backend/API layer in the frontend yet. Data files under `src/data/` contain mock records. State mutations are browser-local and often disappear when a page unmounts/reloads. `localStorage` currently persists only demo authentication and selected page.

## 15. Frontend root and shared components

### `website/frontend/src/main.tsx`

React entry point. Imports the CSS files in override order, finds `#root`, and renders `<App />` inside `StrictMode`.

### `website/frontend/src/App.tsx`

Top-level controller. State: `currentUser`, `appView`, `currentPage`, `pendingUser`, `logoutConfirmationOpen`. Functions include `readStoredUser`, `readStoredPage`, `handleLogin`, `handleMfaVerify`, `navigate`, `logout`, `requestLogout`, `renderCurrentPage`. It enforces browser-side Analyst/Admin page allowlists and uses `localStorage`; it does not use real server authentication.

### `website/frontend/src/components/AppLayout.tsx`

Authenticated shell that composes `TopBar`, `Sidebar`, and the current page via `children`.

### `website/frontend/src/components/Sidebar.tsx`

Role-specific navigation. `pageClass()` marks the active page. Analyst and Administrator menus are hard-coded.

### `website/frontend/src/components/TopBar.tsx`

Top bar with static health indicator, visual-only global search, hard-coded notifications, and user menu. Local state: `notificationOpen`, `userMenuOpen`.

### `website/frontend/src/components/ConfirmModal.tsx`

Reusable confirmation modal rendered with `createPortal`; closes on backdrop or Escape and delegates confirm/cancel callbacks.

## 16. Frontend type files

### `website/frontend/src/types/adminDashboardTypes.ts`

`AdminDashboardPageProps`, integration status/record, admin activity record.

### `website/frontend/src/types/alertsTypes.ts`

`RiskBand`, `AlertStatus`, and `AlertRecord` fields used by the analyst alerts table/detail drawer.

### `website/frontend/src/types/analystDashboardTypes.ts`

Dashboard alert severity and summary record.

### `website/frontend/src/types/appTypes.ts`

Global prototype `Role`, `AppView`, `DemoAccount`, `AuthenticatedUser`.

### `website/frontend/src/types/auditLogsTypes.ts`

Audit result/category and detailed `AuditLogRecord` including user, source IP, changes, metadata.

### `website/frontend/src/types/casesTypes.ts`

Case severity/status, timeline items, and current UI `CaseRecord` with evidence/actions/MITRE/timeline.

### `website/frontend/src/types/configurationTypes.ts`

Configuration state and editable configuration values.

### `website/frontend/src/types/confirmModalTypes.ts`

Confirmation modal tone/content/props contracts.

### `website/frontend/src/types/detectionRulesTypes.ts`

Detection rule category/status/model, editable form state, and modal mode.

### `website/frontend/src/types/incidentResponseTypes.ts`

Execution result, current approval type, action type, timeline, and response execution record.

### `website/frontend/src/types/integrationsTypes.ts`

Integration connection status and integration record.

### `website/frontend/src/types/loginTypes.ts`

Login page callback contract.

### `website/frontend/src/types/mfaTypes.ts`

MFA page callback contract.

### `website/frontend/src/types/profileTypes.ts`

Profile role/state/value props.

### `website/frontend/src/types/responsePoliciesTypes.ts`

Current UI policy status, approval mode, action vocabulary, response policy, form state, modal mode. Approval-related types are legacy relative to the new autonomous target.

### `website/frontend/src/types/settingsTypes.ts`

Theme/language/session choices and settings object.

### `website/frontend/src/types/systemHealthTypes.ts`

Metric/service/event health contracts.

### `website/frontend/src/types/userManagementTypes.ts`

UI user role/status, user record, editable form, modal modes.

## 17. Frontend data files

### `website/frontend/src/data/adminDashboardData.ts`

Mock integration summary and recent administrative activity.

### `website/frontend/src/data/alertsData.ts`

Exports `initialAlerts`, the analyst Alerts page's local starting records.

### `website/frontend/src/data/analystDashboardData.ts`

Exports `dashboardAlerts`; this is a separate mock copy from Alerts page data, so changes do not synchronize.

### `website/frontend/src/data/appData.ts`

Exports `AUTH_STORAGE_KEY`, `PAGE_STORAGE_KEY`, `analystPages`, and `adminPages`. These drive browser-local auth/page restoration and navigation allowlists.

### `website/frontend/src/data/auditLogsData.ts`

Hard-coded audit log history displayed/exported by the Audit Logs page; not generated by real backend actions.

### `website/frontend/src/data/casesData.ts`

Exports `initialCases` including evidence, recommended actions, MITRE strings, and timelines.

### `website/frontend/src/data/configurationData.ts`

Default saved configuration object for the Configuration page.

### `website/frontend/src/data/confirmModalData.ts`

Reusable logout confirmation copy.

### `website/frontend/src/data/detectionRulesData.ts`

`initialRules` plus `emptyRuleForm` defaults for local simulated rule CRUD.

### `website/frontend/src/data/incidentResponseData.ts`

Hard-coded response execution/activity records and timelines.

### `website/frontend/src/data/integrationsData.ts`

Hard-coded integration cards/rows and their simulated status.

### `website/frontend/src/data/loginData.ts`

Exports `DEMO_ACCOUNTS`; credentials are hard-coded demo data and are not secure authentication.

### `website/frontend/src/data/profileData.ts`

Timezone option list for profile editing.

### `website/frontend/src/data/responsePoliciesData.ts`

`initialPolicies`, `emptyPolicyForm`, `allowedActions`; local simulated policy CRUD.

### `website/frontend/src/data/settingsData.ts`

Initial local Settings page values.

### `website/frontend/src/data/systemHealthData.ts`

Initial metrics, services, and health events used for simulated checks.

### `website/frontend/src/data/userManagementData.ts`

`initialUsers` and `emptyUserForm`; not connected to login accounts.

## 18. Frontend pages: file-by-file behavior

### `website/frontend/src/pages/AdminDashboardPage.tsx`

Displays mock metrics/integration/activity summaries and uses `onNavigate` to jump to admin pages.

Named helper functions visible in this file include: `integrationStatusClass`.

### `website/frontend/src/pages/AlertsPage.tsx`

State `alerts`, `attackFilter`, `riskFilter`, `riskSort`, `selectedAlert`; local filtering/sorting/detail drawer and `toggleAlertStatus`. No API persistence.

Major state variables: `alerts` / `setAlerts`, `attackFilter` / `setAttackFilter`, `riskFilter` / `setRiskFilter`, `riskSort` / `setRiskSort`, `selectedAlert` / `setSelectedAlert`.

Named helper functions visible in this file include: `severityClass`, `statusClass`, `toggleAlertStatus`.

### `website/frontend/src/pages/AnalystDashboardPage.tsx`

Local `search`, `severity`, `selectedAlert`; filters `dashboardAlerts` with memoization and opens local detail views. Metrics/data are mock.

Major state variables: `search` / `setSearch`, `severity` / `setSeverity`, `selectedAlert` / `setSelectedAlert`.

Named helper functions visible in this file include: `severityClass`.

### `website/frontend/src/pages/AuditLogsPage.tsx`

Filters hard-coded audit records, opens details, and can export visible records to CSV. Export is real client-side file generation; source logs are mock.

Major state variables: `searchQuery` / `setSearchQuery`, `categoryFilter` / `setCategoryFilter`, `resultFilter` / `setResultFilter`, `userFilter` / `setUserFilter`, `selectedLog` / `setSelectedLog`, `pageMessage` / `setPageMessage`.

Named helper functions visible in this file include: `resultClass`, `roleClass`, `escapeCsvValue`, `resetFilters`, `exportVisibleLogs`.

### `website/frontend/src/pages/CasesPage.tsx`

State `cases`, search/severity/status filters, `selectedCase`; local drawer and `toggleCaseStatus`. This is UI-only case management today.

Major state variables: `cases` / `setCases`, `searchQuery` / `setSearchQuery`, `severityFilter` / `setSeverityFilter`, `statusFilter` / `setStatusFilter`, `selectedCase` / `setSelectedCase`.

Named helper functions visible in this file include: `severityClass`, `statusClass`, `toggleCaseStatus`, `resetFilters`.

### `website/frontend/src/pages/ConfigurationPage.tsx`

Keeps editable `configuration` and `savedConfiguration`, state/error/messages; validates, saves/cancels/restores defaults only in component memory.

Major state variables: `configuration` / `setConfiguration`, `savedConfiguration` / `setSavedConfiguration`, `configurationState` / `setConfigurationState`, `validationError` / `setValidationError`, `pageMessage` / `setPageMessage`.

Named helper functions visible in this file include: `handleConfigurationChange`, `validateConfiguration`, `saveConfiguration`, `cancelChanges`, `restoreDefaults`, `stateClass`.

### `website/frontend/src/pages/DetectionRulesPage.tsx`

Large local CRUD simulation for detection rules. Owns rule list, filters, modal state, selected rule, form, validation. Add/edit/enable/delete are browser-only.

Major state variables: `rules` / `setRules`, `searchQuery` / `setSearchQuery`, `statusFilter` / `setStatusFilter`, `categoryFilter` / `setCategoryFilter`, `modalMode` / `setModalMode`, `selectedRule` / `setSelectedRule`, `ruleForm` / `setRuleForm`, `formError` / `setFormError`.

Named helper functions visible in this file include: `statusClass`, `severityClass`, `resetFilters`, `closeModal`, `openAddModal`, `openEditModal`, `openViewModal`, `openDeleteModal`, `handleFormChange`, `validateRuleForm`, `saveRule`, `toggleRuleStatus`, `deleteSelectedRule`.

### `website/frontend/src/pages/IncidentResponsePage.tsx`

Filters/display of hard-coded execution records. State includes search/action/result and `selectedExecution`. It does not execute Cortex or any real action.

Major state variables: `searchQuery` / `setSearchQuery`, `actionFilter` / `setActionFilter`, `resultFilter` / `setResultFilter`, `selectedExecution` / `setSelectedExecution`.

Named helper functions visible in this file include: `resultClass`, `approvalClass`, `actionClass`, `resetFilters`.

### `website/frontend/src/pages/IntegrationsPage.tsx`

Local integration search/status/detail state. Simulates connect/disconnect, sync, and connection tests with timers; no real Wazuh/MISP/Cortex/Ollama calls.

Major state variables: `integrations` / `setIntegrations`, `searchQuery` / `setSearchQuery`, `statusFilter` / `setStatusFilter`, `selectedIntegration` / `setSelectedIntegration`, `syncingIds` / `setSyncingIds`, `pageMessage` / `setPageMessage`.

Named helper functions visible in this file include: `statusClass`, `resetFilters`, `closeIntegrationDetails`, `toggleIntegrationStatus`, `syncIntegration`, `testAllConnections`.

### `website/frontend/src/pages/LoginPage.tsx`

Local state `email`, `password`, `error`. `handleSubmit()` calls the `onSignIn` callback from `App`; authentication is only a comparison against `DEMO_ACCOUNTS`.

Major state variables: `email` / `setEmail`, `password` / `setPassword`, `error` / `setError`.

Named helper functions visible in this file include: `handleSubmit`.

### `website/frontend/src/pages/MfaPage.tsx`

Local six-digit `digits` array and `error`; input navigation helpers; accepts the hard-coded prototype MFA code and calls `onVerify`.

Major state variables: `digits` / `setDigits`, `error` / `setError`.

Named helper functions visible in this file include: `updateDigit`, `handleKeyDown`, `handleSubmit`.

### `website/frontend/src/pages/ProfilePage.tsx`

Local editable profile copy based on App props. Saving does not update App's authenticated user or user management data.

Major state variables: `profile` / `setProfile`, `savedProfile` / `setSavedProfile`, `profileState` / `setProfileState`, `validationError` / `setValidationError`, `pageMessage` / `setPageMessage`.

Named helper functions visible in this file include: `profileStateClass`, `roleClass`, `handleProfileChange`, `validateProfile`, `saveProfile`, `cancelChanges`, `restoreOriginalProfile`.

### `website/frontend/src/pages/ResponsePoliciesPage.tsx`

Large local CRUD simulation for response policies. State includes policies, filters, selected policy, modal mode, form/error/messages. Current approval-mode UI conflicts with final autonomous design.

Major state variables: `policies` / `setPolicies`, `searchQuery` / `setSearchQuery`, `statusFilter` / `setStatusFilter`, `approvalFilter` / `setApprovalFilter`, `selectedPolicy` / `setSelectedPolicy`, `modalMode` / `setModalMode`, `policyForm` / `setPolicyForm`, `formError` / `setFormError`, `pageMessage` / `setPageMessage`.

Named helper functions visible in this file include: `statusClass`, `approvalClass`, `resetFilters`, `closeModal`, `openAddModal`, `openViewModal`, `openEditModal`, `openDeleteModal`, `handleFormChange`, `parseActions`, `validatePolicyForm`, `savePolicy`, `togglePolicyStatus`, `deleteSelectedPolicy`.

### `website/frontend/src/pages/SettingsPage.tsx`

Local saved/editable settings with validation and toggles. Does not persist to server or control global backend behavior.

Major state variables: `settings` / `setSettings`, `savedSettings` / `setSavedSettings`, `settingsState` / `setSettingsState`, `pageMessage` / `setPageMessage`, `validationError` / `setValidationError`.

Named helper functions visible in this file include: `settingsStateClass`, `updateSettingsState`, `handleFieldChange`, `validateSettings`, `saveSettings`, `cancelChanges`, `restoreDefaults`, `toggleGeneralNotifications`, `toggleMfa`.

### `website/frontend/src/pages/SystemHealthPage.tsx`

State for metrics/services/filter/search/details/refresh/check operations. Timers and generated values simulate health checks; no backend health API.

Major state variables: `metrics` / `setMetrics`, `services` / `setServices`, `statusFilter` / `setStatusFilter`, `searchQuery` / `setSearchQuery`, `selectedService` / `setSelectedService`, `refreshing` / `setRefreshing`, `checkingServiceIds` / `setCheckingServiceIds`, `lastRefresh` / `setLastRefresh`, `pageMessage` / `setPageMessage`.

Named helper functions visible in this file include: `metricLevel`, `metricDescription`, `donutClass`, `healthTagClass`, `serviceStatusClass`, `eventSeverityClass`, `refreshHealth`, `checkService`, `checkAllServices`, `resetFilters`.

### `website/frontend/src/pages/UserManagementPage.tsx`

Simulates user CRUD, suspend/reactivate, reset password, filters, forms/modals. These records are not tied to actual authentication.

Major state variables: `users` / `setUsers`, `searchQuery` / `setSearchQuery`, `roleFilter` / `setRoleFilter`, `statusFilter` / `setStatusFilter`, `selectedUser` / `setSelectedUser`, `modalMode` / `setModalMode`, `userForm` / `setUserForm`, `formError` / `setFormError`, `pageMessage` / `setPageMessage`.

Named helper functions visible in this file include: `statusClass`, `roleClass`, `resetFilters`, `closeModal`, `openAddModal`, `openViewModal`, `openEditModal`, `openDeleteModal`, `openResetPasswordModal`, `handleFormChange`, `validateUserForm`, `saveUser`, `toggleUserStatus`, `deleteSelectedUser`, `resetSelectedUserPassword`.

## 19. Frontend styling/build files

### `website/frontend/src/styles/athenasec.css`

Main design system and page styling: dark SOC theme, auth screens, shell, sidebar/topbar, cards, tables, pills, charts, forms, modals/drawers, responsive behavior.

### `website/frontend/src/styles/react-stability.css`

Overrides animation/layout behaviors that caused visual jumping during React rerenders/filtering.

### `website/frontend/src/styles/integrations-table-fix.css`

Targeted Integrations-table width/overflow/action-column fix.

### `website/frontend/src/styles/user-management-table-fix.css`

Targeted User Management table width/overflow/action-column fix.

### `website/frontend/index.html`

Vite HTML entry containing the root mounting element and app metadata.

### `website/frontend/package.json`

Frontend dependencies/scripts. Important scripts: `npm run dev`, `npm run build`, `npm run lint`, `npm run preview`. React Router is installed but current App navigation does not use browser routes.

### `website/frontend/package-lock.json`

Generated exact npm dependency lock. Commit it; normally do not hand-edit it.

### `website/frontend/vite.config.ts`

Minimal Vite config enabling the React plugin.

### `website/frontend/tsconfig.app.json`

Browser/React TypeScript compiler settings; strict unused checks, ES2023 target, bundler resolution, `noEmit`, React JSX.

### `website/frontend/tsconfig.json`

Root TypeScript project-reference/config file.

### `website/frontend/tsconfig.node.json`

TypeScript settings for Node-side config files such as Vite config.

### `website/frontend/eslint.config.js`

ESLint configuration for frontend source.

### `website/frontend/.gitignore`

Frontend-local generated/build ignore rules.

### `website/frontend/public/favicon.svg`

Static favicon asset.

### `website/frontend/public/icons.svg`

Static SVG icon asset/sprite used by the frontend.

### `website/frontend/README.md`

Mostly the default Vite React template README; not AthenaSec-specific onboarding.

## 20. Older static prototype

- `website/prototype/index.html` — original single-file page markup containing prototype screens.
- `website/prototype/app.js` — pre-React browser logic for hard-coded login/MFA, navigation, filtering, modal actions, and demo interactions.
- `website/prototype/styles.css` — pre-React visual design that became the basis of the React CSS.

These files are historical/reference code. New frontend work should be made in `website/frontend/src/` unless the team explicitly needs to compare against the prototype.

## 21. Documentation files already in the repository

- `website/docs/athenasec_dev.md` — long React migration/development history.
- `website/docs/website_logic.md` — accurate explanation of the current frontend's state ownership, mock data, pages, and limitations.
- `website/docs/Details.md`, `modifications.md`, `text.txt` — supporting prototype/design notes.
- `website/README.md` — old prototype structure and demo credentials.

These docs describe frontend history; this new guide should be considered the broader codebase-level onboarding document because it also covers the Python agent and Wazuh flow.

## 22. How a real Wazuh alert travels through the current code

1. Wazuh detects/correlates an alert.
2. Wazuh Integrator runs `custom-athenasec.py` with alert-file path, integration key, and hook URL.
3. The forwarder POSTs JSON to `/api/v1/integrations/wazuh/alerts` with `X-AthenaSec-Integration-Key`.
4. `main.py` verifies the key using `secrets.compare_digest`.
5. `parse_wazuh_alert()` converts Wazuh JSON into `SecurityAlertInput(source='wazuh')`.
6. `run_investigation()` invokes LangGraph with status `received`.
7. `normalize_alert()` creates `E001` from the event text.
8. `analyze_alert` builds the evidence-only prompt and calls Qwen.
9. Qwen returns `AlertAnalysis` and references evidence IDs.
10. `validate_evidence_references()` rejects unavailable evidence IDs.
11. If Qwen requests evidence, `gather_evidence` invokes the configured provider.
12. In Wazuh mode, `WazuhEvidenceProvider` searches `wazuh-alerts*` and creates additional immutable evidence.
13. Qwen re-analyzes once at most.
14. `risk.py` converts alert metadata into `RiskContext`; `risk_engine.py` calculates score/band.
15. `policy_engine.py` maps classification + risk to current response policy.
16. `response_planner.py` creates the current approval/dry-run plan.
17. Graph status becomes `complete`.
18. `main.py` converts graph state to `InvestigationResponse` and persists the entire object in SQLite.
19. API returns the investigation JSON to the Wazuh forwarder.

This synchronous API-return requirement is why the current forwarder can be vulnerable to LLM timeout delays.

## 23. Current environment variables

| Variable | Consumer | Purpose |
|---|---|---|
| `OLLAMA_BASE_URL` | `llm.py` | Ollama server URL |
| `OLLAMA_MODEL` | `llm.py` | Qwen model name |
| `ATHENASEC_DB_PATH` | `main.py` | SQLite database location |
| `ATHENASEC_EVIDENCE_PROVIDER` | `evidence_provider.py` | `mock` or `wazuh` |
| `WAZUH_INDEXER_URL` | evidence provider | Wazuh Indexer base URL |
| `WAZUH_INDEXER_USERNAME` | evidence provider | Indexer Basic Auth username |
| `WAZUH_INDEXER_PASSWORD` | evidence provider | Indexer Basic Auth password |
| `WAZUH_VERIFY_SSL` | evidence provider | whether `requests` verifies Indexer TLS |
| `ATHENASEC_WAZUH_INGEST_KEY` | `main.py` | shared secret protecting the Wazuh ingestion endpoint |

Future target will also need safe MISP, Cortex, PostgreSQL, model registry/path, autonomous-response kill-switch, and audit configuration variables.

## 24. Real vs mock vs legacy

| Area | Current status |
|---|---|
| FastAPI API | real |
| LangGraph orchestration | real |
| Ollama/Qwen structured analysis | real |
| Wazuh custom forwarder | real |
| Wazuh Indexer querying | real |
| Evidence IDs / grounding validation | real but incomplete entity grounding |
| Risk engine | real deterministic code |
| Policy engine | real deterministic code, but policy model needs autonomous redesign |
| Execution | dry-run simulation only |
| Storage | real SQLite, but single JSON-payload table |
| ML classifier | not implemented yet |
| MISP | not implemented yet |
| Cortex real actions | not implemented yet |
| DB case creation | not implemented as final relational workflow |
| Complete audit logging | not implemented |
| React UI interactions | real browser behavior |
| React alert/case/rule/integration data | mock/local |
| React authentication/RBAC | demo/browser-only |
| Analyst approval | current backend/UI legacy; final design removes it |

## 25. Important design boundaries the team should preserve

1. **Do not let Qwen directly execute actions.** The system may be autonomous, but authorization should remain deterministic in the policy engine.
2. **ML classification, LLM reasoning, risk, and policy should remain separate outputs.** Store all of them so disagreements are visible and auditable.
3. **Wazuh Indexer is the security telemetry store.** Do not duplicate all raw Wazuh telemetry into PostgreSQL.
4. **PostgreSQL should become AthenaSec's application/audit store.** Store alerts/investigation snapshots, ML results, evidence references, MISP enrichment, AI analysis, risk, policy, cases, Cortex requests/results, and audit events.
5. **Evidence must stay immutable.** Keep the `E###` concept when MISP is added.
6. **All autonomous actions need idempotency/correlation IDs.** A retried alert must not block the same target repeatedly or create duplicate cases.
7. **Keep a global autonomous-response kill switch.** This is not an approval workflow; it is an emergency safety control.
8. **Do not commit secrets, `.env`, databases, model training datasets, or runtime logs.**
9. **Keep `custom-athenasec.py` LF-only.**
10. **Run tests before every checkpoint commit.**

## 26. Known technical gaps before the final architecture

- Wazuh parser needs richer correlation fields and deterministic feature derivation.
- Evidence retrieval is currently initiated mainly by Qwen rather than policy/classification-driven evidence requirements.
- Entity grounding validates evidence IDs but does not yet validate every IP/user/host that Qwen mentions.
- A trained ML layer does not exist.
- MISP adapter/evidence source does not exist.
- Current response policy includes human approvals; final architecture must remove them.
- `create_case` is currently modeled as an action rather than a workflow branch.
- Cortex is listed in schema vocabulary but no real Cortex client exists.
- SQLite schema is not sufficient for complete auditability.
- Wazuh ingress is synchronous; the final worker/job design should acknowledge quickly.
- Frontend is not connected to FastAPI.
- Frontend policy/incident-response types still include approval concepts.
- Frontend data sets are duplicated and can disagree across pages.
- Frontend auth is not secure and must eventually become backend-issued authentication/RBAC.

## 27. Recommended future module boundaries

A clean target Python structure would eventually look roughly like:

```text
agent/app/
├── api/                    route modules
├── graph/                  LangGraph orchestration
├── ml/                     features, model loading, inference
├── integrations/
│   ├── wazuh/
│   ├── misp/
│   └── cortex/
├── services/
│   ├── risk_engine.py
│   ├── policy_engine.py
│   ├── case_service.py
│   ├── action_service.py
│   └── audit_service.py
├── db/
│   ├── models/
│   ├── repositories/
│   └── migrations/
├── schemas/
└── workers/
```

This is a future direction, not a command to refactor everything at once.

## 28. Developer runbook

### Backend local

```powershell
cd <repo>\agent
.\.venv\Scripts\Activate.ps1
python -m pytest -v
uvicorn app.main:app --host 0.0.0.0 --port 8000
```

Always confirm the prompt shows the virtual environment or explicitly use `.\.venv\Scripts\python.exe` for tests.

### Frontend

```powershell
cd <repo>\website\frontend
npm install
npm run dev
npm run build
```

### Useful backend checks

- `GET /health` — API only.
- `POST /api/v1/analyze` — manual investigation.
- `GET /api/v1/investigations/{alert_id}` — persisted investigation lookup.
- Wazuh evidence provider requires the relevant environment variables and a reachable Indexer.

## 29. File ownership / who should change what

- **AI/agent team:** `agent/app/graph`, `llm.py`, ML modules, evidence/grounding.
- **Backend/security integration team:** `main.py`, Wazuh/MISP/Cortex adapters, persistence, audit, case/action services.
- **Detection team:** Wazuh rules/configuration plus feature mapping into AthenaSec.
- **Frontend team:** `website/frontend/src`; replace `src/data` mock imports with API/query modules gradually.
- **Everyone:** `schemas.py` changes require coordination because they are shared contracts.

When a schema/API contract changes, update tests and frontend types/API clients in the same feature branch.

## 30. Final mental model

The most important thing for the team to understand is that AthenaSec is not 'just Qwen'. It is a composed autonomous security system:

```text
Wazuh            = sensors, detection, correlation, searchable telemetry
ML               = learned classification
MISP             = external threat intelligence
LangGraph        = investigation workflow/orchestration
Qwen             = evidence-grounded reasoning
Risk engine      = deterministic severity score
Policy engine    = deterministic autonomous authorization
Cortex           = execution engine for permitted actions
PostgreSQL       = cases + decisions + actions + complete audit trail
React            = SOC visibility/configuration interface
```

The current repository already implements the Wazuh/FastAPI/LangGraph/Qwen/risk/policy/SQLite foundation. The next changes should evolve that foundation toward the agreed autonomous architecture rather than replacing it.
