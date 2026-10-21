# AthenaSec Evidence Classification

**Phase 0 deliverable, owner: Ahmad (Agent).** Revision 3. Repo path: `agent/docs/phase0/evidence-classification.md`

**Purpose:** one shared vocabulary and one record format, so that the Phase 9 test report and the Moodle evidence bundle always say what a result proves, how it can be reproduced, and whether it is current or historical.

**Basis:** branch `feature/agentic-response-v2`, commit `7e87159d100614e709ca2b6ee0fb38523fc5e70a`. Section 7 draws on the 12 October file guide and the 19 October roadmap. **Nothing in this document was verified by running code.** Statements about the code in Section 6 come from reading the source at the commit above.

## 1. Two separate questions

Every piece of evidence answers two independent questions, and both must be written down.

1. **Tier:** what was real and what was replaced (Section 3).
2. **Verification status:** is this result current or historical (Section 4).

A result can be Isolated-live in tier and Historical in status. That is exactly the position of the 12 October lab runs.

## 2. Terminology: mock, unit test, simulated

These words are used loosely, so this document fixes their meaning.

- **Tier names describe what was real, not how big the test was.** "Mock", "Simulated", "Isolated-live" and "Production-live" say which parts were genuine and which were stand-ins.
- **"Unit test" and "integration test" describe test size.** They are not tiers. A unit test result is reported as Mock tier only when its collaborators are test doubles. Do not write "unit tested" as if it meant "verified".
- **"Mock" has three meanings in this repository. Never mix them.**
  1. A test double inside a test (for example `FailingMISPClient` and `FailingMLClassifier` in `tests/test_investigation_graph.py`).
  2. The runtime fake evidence provider, `app/tools/mock_wazuh.py`, selected through the evidence provider setting. Records it produces carry `source="mock_wazuh"`.
  3. Demo data in the website frontend. The fixtures, fixed MFA code and hardcoded CPU and RAM values come from the 19 Oct roadmap description. The frontend was not reviewed or tested for this document.
  Evidence from any of the three is Mock tier.
- **SQLite instead of PostgreSQL is a stand-in.** A persistence claim backed only by an in-memory or SQLite store is Simulated for PostgreSQL behavior, because the real database was replaced.
- **A skipped test proves nothing.** It is reported as skipped, with the missing prerequisite named. Example: the PostgreSQL live tests skip unless `ATHENASEC_TEST_DATABASE_URL` or `ATHENASEC_TEST_PG_URL` is set.

| Test style | Example | Tier it supports |
|---|---|---|
| Logic test with all collaborators replaced by doubles | `tests/test_action_policy_engine.py` | Mock |
| Real graph or route with injected fake ML, MISP or evidence provider | `FailingMISPClient` in `tests/test_investigation_graph.py` | Mock for the faked dependencies |
| Real components wired together with SQLite or in-memory stores and stub services | `test_sqlite_lifecycle_survives_restart` | Simulated for the replaced parts |
| Test that needs a real PostgreSQL | `tests/test_postgres_live.py` | Isolated-live only when it actually ran against an isolated database, otherwise skipped |
| Run against lab services with real credentials and TLS | 12 Oct lab runs | Isolated-live |

The per-file classification of the existing suite is a Phase 9 task. The table gives the rule and the examples already confirmed.

## 3. The four tiers

| Tier | What is real | What is replaced | What it can honestly claim | What it cannot claim |
|---|---|---|---|---|
| **Mock** | The AthenaSec function or class under test | Every collaborator is a test double, a runtime mock provider, or demo data | Logic is correct for the inputs chosen, and fail-closed branches behave as coded | That any real service, network, credential, TLS chain or database works |
| **Simulated** | Several real AthenaSec components wired through real entry points (API route, graph, store) | At least one external boundary is a stand-in: a stub HTTP service, scripted or replayed alert JSON, SQLite instead of PostgreSQL, a fake Cortex responder | Components integrate with each other and with the protocol shape the stand-in imitates | That the real external service behaves the same way |
| **Isolated-live** | The real services in the claimed path (Wazuh Indexer, PostgreSQL, Ollama, Cortex, MISP as applicable), with real authentication, network and TLS | Nothing in the claimed path, but the environment is isolated: lab data, `SHADOW` mode or disposable targets, no production credentials | The specific path exercised works against the real services in the lab | That it works at production scale, on production hosts or data, or that paths not exercised work |
| **Production-live** | The deployed system in the real SOC environment, real monitored endpoints, production secrets, formally authorized | Nothing | The deployed system behaves as observed in operation | Anything beyond what was observed. Needs the Phase 10 pilot and authorization review |

## 4. Verification status: historical versus current

| Status | Meaning | May be reported as |
|---|---|---|
| **Current** | Re-run by the team at the commit named in the report, with command, environment and output recorded | "Verified at `<sha>` on `<date>`" |
| **Historical** | Documented in an earlier run or document, at an earlier commit, and not re-run | "Previously observed on `<date>` at `<sha>`. Not re-verified" |
| **Unverified** | Code or a claim exists, but no run evidence was found | "Implemented, not verified" |

Rules:

1. A Historical result is never reported as Current. The 12 Oct lab results were produced at commit `bdbc4e3`. The reviewed head is `7e87159`, and a later commit can change behavior.
2. When a Historical result is re-run, the new run is a new record. The old record is kept, not overwritten.
3. If the commit, configuration hash or model artifact checksum differs from the original run, the re-run is a new result, not a confirmation of the old one.
4. Each Historical item in Section 7 names the roadmap task that re-verifies it.

## 5. Rules for assigning a tier

1. **Weakest link wins.** A claim gets the lowest tier of any component its conclusion depends on. If evidence retrieval is live but Cortex is a fake, a claim about end-to-end response is Mock or Simulated, and only the retrieval claim is Isolated-live.
2. **Label per component, not per project.** The Phase 9 report lists each component with its highest verified tier, its status, and the date, commit and environment.
3. **Replayed history is not live delivery.** Submitting a stored Wazuh alert to the API proves ingestion and processing. It does not prove Wazuh Manager forwards alerts continuously. The record states whether the alert was replayed by a script or delivered by Wazuh Manager.
4. **A prediction is not a label.** A model predicting `benign` on a live alert shows the pipeline ran. It does not show the event was benign or that the model is accurate.
5. **A passing test is not an integration result.** Pass, skip and fail counts are always reported with the commit and environment.
6. **Safety claims need a failing case.** "Fails closed" is evidenced only by a run where the dependency is actually missing, down or wrong, with the observed outcome shown.
7. **Isolation is part of the claim.** Isolated-live evidence states what was isolated (separate containers, port, database, no production data) and the response mode. Anything involving Cortex execution also names a disposable target and the non-production execution authorization.
8. **Demo UI is Mock.** Screens fed by fixtures, the fixed MFA code and hardcoded metrics are labeled as such in screenshots.

## 6. Provenance: what the code stores today, and its limits

These limits apply to any evidence cited from a persisted investigation. They are documentation of the current state, not requests to change it. Proposed changes are tracked in `test-matrix.md` (TM-13, TM-34, TM-37, TM-41, TM-42).

**What is available**

- The alert-level source IDs are kept in structured `alert_metadata`: Wazuh alert ID, Indexer document ID, rule ID, agent ID and the alert timestamp, as set by `app/tools/wazuh_alert_parser.py`.
- The AthenaSec `alert_id` is `{index}:{document _id}` when the Indexer hit supplies both, otherwise `wazuh:{identifier}`.
- Incident, investigation and action-chain IDs are deterministic. `INC-` is derived from the creating alert ID and `INV-` from the incident ID plus the alert ID. Approvals are bound to the exact action through an action fingerprint.
- **Case IDs come from a legacy derivation and several distinct V2 derivations that all render as `CASE-<UUID>`.** The legacy alert-derived case (`case_service`, created by the legacy response path) hashes `athenasec-case:{alert_id}`, so it is one stable ID per alert. V2 cases are not simply alert-derived: policy-denial cases hash `athenasec-policy-case:{incident_id}:{investigation_id}:{comma-joined sorted denied decision IDs}`, runtime cases hash `athenasec-runtime-case:{proposed_action_id}:{policy_decision_id}:{reason_code}`, `athenasec-approval-case:{approval_id}:{status}` and `athenasec-execution-case:{response_action_id}:{reason_code}`. One alert can therefore have several cases, and the prefix does not say which path created a case. Cite a case by its `case_id` and state which derivation made it.
- The persisted evidence record also carries `captured_at`, which is not the retrieval time (Limitation 2).
- Each Wazuh Indexer observation includes `wazuh_alert_id`, the event timestamp, rule, agent and source fields in its text.

**Limitations**

1. **No structured source reference on evidence records.** The in-flight `EvidenceRecord` stores only `evidence_id`, `source`, `evidence_type` and `content`. The persisted `InvestigationEvidenceRecord` adds `investigation_id` and `captured_at`. The Indexer document ID exists only as text inside `content`. The index name, the query or request type, a per-observation retrieval time and a content hash are not stored.
2. **`captured_at` is the investigation completion time, not the original retrieval time.** `persist_investigation_lifecycle` sets `captured_at` to its own `completed_at`, which defaults to the current UTC time when the finished investigation is saved. The one caller in `app/main.py` does not pass a value, so every evidence record of an investigation carries the same timestamp, taken after the graph has run. It does not show when the Indexer was queried or the Wazuh event time, it cannot prove how fresh the evidence was at analysis time, and listings that sort by it fall back to evidence ID order. Investigations without an incident identity may still be saved as `InvestigationResponse` by `store.save(investigation)`, but they do not create the incident-linked investigation/evidence rows with `captured_at`. The Wazuh event time is in the evidence `content` as `timestamp=...` and in the alert metadata.
3. **Evidence IDs are positional.** `E001` is the alert, and later records get the next number in the order observations arrive. They are scoped to one investigation, not content-derived, and can change if the order changes. Always cite them as `<investigation_id>/E003`, never as a bare `E003`.
4. **MISP results are not evidence records.** `EvidenceSource` has no MISP value, and enrichment is held in a separate field, so a MISP result has no evidence ID and cannot be cited like `E003`.
5. **A MISP outage is shown to the model as "no matches".** The failure is recorded in `misp_error` and the audit log, but the analysis prompt receives an empty match list and says "No MISP matches found."
6. **No environment, commit, configuration or replay marker.** Neither `EvidenceRecord` nor `InvestigationResponse` carries a commit, environment, configuration hash, or a flag saying whether the alert was replayed or delivered live. The person writing the evidence must record these (Section 8).
7. **No checksums for models or datasets.** SHA-256 appears in the code only for action fingerprints and credential handling. The model artifact checksum, feature schema and metrics manifest are an open Phase 4 task.
8. **Predicted-benign alerts retain alert evidence but skip additional evidence gathering.** `build_benign_investigation` creates `EvidenceRecord(evidence_id="E001", source="alert")`, and the fast path saves that `InvestigationResponse` and audit events without calling the investigation graph or Wazuh Indexer. `benign` is the model prediction, not ground truth.
9. **Mock records can sit beside real ones.** The `source` value distinguishes `mock_wazuh` from `wazuh` in the data, but nothing in the stored investigation states which environment produced it.
10. **Idle versus broken delivery is not distinguishable.** No heartbeat or last-alert record was found, so silence from Wazuh cannot be told apart from a broken forwarder. Alert silence is also not an idle Cortex, because the containment-expiry runner works independently of alert flow (test-matrix TM-42).

## 7. Current component status (Historical unless stated)

All rows come from the 12 October file guide or the 19 October roadmap. **None was re-run, reviewed or tested for this document, so no row is Current.**

| Component | Highest tier documented | Status | Basis | Re-verified by |
|---|---|---|---|---|
| Parser, risk, action risk, action policy, approval logic (unit tests) | Mock | Historical | 892 passed, 9 skipped at `bdbc4e3` on 12 Oct. Not re-run on `7e87159` | Ahmad, Phase 9 regression re-run |
| Wazuh alert parser and 15-feature extraction | Isolated-live | Historical | Implied by the ML predictions on the two real alerts (rules 5720 and 5716) on 12 Oct | Daniel, Phase 5 SHADOW investigation |
| ML artifact `athenasec-classifier-v1.pkl` load and classify | Isolated-live | Historical | Loaded in the lab container on 12 Oct | Ahmad, Phase 4 reproduction and integrity checks |
| Wazuh Indexer evidence retrieval (restricted reader, verified CA and hostname) | Isolated-live | Historical | Live brute-force case: 9 authentication observations, 0 source-endpoint observations | Daniel, Phase 5 reader identity and CA trust |
| Evidence sufficiency check and analysis verification | Isolated-live | Historical | Same live case returned sufficiency false and verification false | Ahmad, Phase 5 trace documentation |
| ML-predicted benign path | Isolated-live | Historical | Rule 5716 event, zero risk, no action. No ground-truth label | Daniel, Phase 5 SHADOW investigation |
| PostgreSQL investigation and audit persistence | Isolated-live | Historical | Retrieval verified for both 12 Oct cases | Ahmad, Phase 9 PostgreSQL-dependent tests |
| Wazuh Manager to ingest forwarding | Simulated | Historical | Historical alerts submitted by scripts, continuous delivery not shown | Daniel, Phase 5 continuous delivery |
| Qwen3:4B analysis through Ollama | Mock | Unverified live | The guide does not claim live calls were traced | Ahmad, Phase 5 Ollama discovery and limits |
| MISP enrichment | Mock | Unverified live | Earlier MISP API tests were in a different environment | Ahmad, Phase 5 and Phase 9 MISP tasks |
| Cortex execution, verification, rollback, containment expiry | Mock | Unverified live | No live Cortex execution shown. Kill switch off in the lab | Daniel, Phase 6 controlled action |
| Approval decision consumed by the runtime gate from the database | Mock | Unverified live | Live verification is an open Phase 6 task | Daniel, Phase 6 |
| Website frontend | Mock (demo), as described in the roadmap | Unverified | Description only (fixtures, demo credentials, fixed MFA code, per the 19 Oct roadmap). The frontend was not reviewed or tested for this document, so it is not marked Current | Website Frontend owner |

## 8. Minimum record for every piece of evidence

Copy this block into each evidence entry. A field that does not apply is written as `n/a` with the reason, never left out.

**Identity**
- Evidence entry ID, title, component or components covered
- Tier (Section 3) and verification status (Section 4)
- Who ran it and when

**Code state**
- Repository, branch, full commit SHA
- Working tree: clean, or the hash of the diff

**Environment and reproducibility**
- Host OS and architecture, Python version
- Dependency state: `agent/requirements.txt` is pinned (every line uses `==`), so record the commit. For containers, record the resolved image digest. The Dockerfile base is the tag `python:3.14-slim`, which is not a digest
- Model artifact: file name, SHA-256, and the `model_version` string. The code does not produce this checksum today, so compute it yourself
- Service versions: Wazuh, Cortex, MISP, Ollama and the model tag, PostgreSQL
- Which services were real and which were replaced
- Response mode and the value of `AUTONOMOUS_RESPONSE_ENABLED`
- Random seeds, if training or sampling was involved

**Configuration hash**
- SHA-256 of a canonical configuration snapshot: sorted `NAME=value` lines for non-secret settings, secret settings listed as name plus `set` or `unset` (never the value), plus the hash of each Compose file used
- Settings seen in the source include `ATHENASEC_PERSISTENCE_BACKEND`, `AUTONOMOUS_RESPONSE_ENABLED`, `WAZUH_VERIFY_SSL`, `WAZUH_INDEXER_CA_BUNDLE` (path only), `WAZUH_INDEXER_TLS_LEGACY_CA_COMPAT`, `OLLAMA_BASE_URL` and `OLLAMA_MODEL`
- The code does not generate this hash, so the evidence author computes it and states the method

**Source IDs and references**
- Wazuh alert ID and Indexer document ID and index for each alert used, plus rule ID and agent ID
- Whether the alert was delivered live by Wazuh Manager or replayed by a script
- AthenaSec IDs: `alert_id`, `incident_id`, `investigation_id`, evidence references written as `<investigation_id>/E00n`, `case_id` and which derivation made it (legacy alert-derived, or V2 policy denial, runtime, approval or execution), `approval_id` and action fingerprint, response action and result IDs, audit IDs
- Raw event bodies, tokens, CA private keys and personal data are redacted. IDs are kept

**Time**
- Record all times in UTC, ISO 8601 with a `Z` suffix. The audit store stamps UTC, and the Indexer client converts observed times to UTC
- Wazuh alert timestamps are kept as Wazuh emitted them, so state the offset shown
- Do not use the stored `captured_at` as the retrieval time. It is the investigation completion time (Section 6, Limitation 2). Record the retrieval time yourself from your run log, and take the event time from the evidence `timestamp=` field
- Convert local times first. The team works in Asia/Dubai (UTC+04:00)
- Record the clock source and whether the host clock was synchronized. The roadmap lists clock synchronization failures on the installer host, so a timestamp from an unsynchronized host is flagged

**Reproduction**
- Exact command or commands, run from which directory
- Expected result, observed result, and pass, fail and skip counts with the reason for each skip
- What a reader needs to repeat it: prerequisites, data used, and how to reset the lab afterward

## 9. Wording to use in reports

- Mock: "Unit tested with test doubles for X and Y. Mock tier, current at `<sha>`."
- Simulated: "Exercised through the real API and store with a stub for Z. Simulated tier."
- Isolated-live, current: "Verified against the lab Wazuh Indexer and PostgreSQL in `SHADOW` mode at `<sha>` on `<date>`."
- Isolated-live, historical: "Previously observed in the 12 Oct lab at `bdbc4e3`. Not re-verified."
- Production-live: reserved until the Phase 10 pilot and authorization review are complete.
- Never use "tested end to end", "production ready" or "verified accuracy" without the tier, status and scope behind it.
