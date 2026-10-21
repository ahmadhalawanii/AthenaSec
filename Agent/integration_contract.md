# AthenaSec — Phase 0 Integration and Identifier Contract

**Owner:** Daniel (Agent/ML). **Status:** Technical draft checked against source; **cross-team approval pending**.
**Roadmap requirement:** "Publish an end-to-end alert, evidence, case, action and approval schema contract across the detection-to-response pipeline." (`tasks.md`, Phase 0)
**Code baseline:** `ahmadhalawanii/AthenaSec`, `feature/agentic-response-v2`, `7e87159d100614e709ca2b6ee0fb38523fc5e70a` (remote checked 2026-10-20).
**Scope of verification:** Static repository review of the documented types and routes. No local, integration, or live tests were run to certify this contract. This document is a design/interface agreement, **not** proof of deployed connectivity or a newly implemented API.

## 1. System boundary and authority

```text
Wazuh (detection and raw events)
  -> AthenaSec backend (authenticated ingest, normalization/correlation)
  -> ML classification (15 Wazuh-derived features; prediction only)
  -> LangGraph investigation (Qwen3:4b + read-only Wazuh evidence retrieval,
                              optional MISP enrichment, sufficiency/verification)
  -> deterministic incident-risk assessment
  -> AI structured action proposal -> deterministic action-risk assessment
  -> deterministic Action Policy Engine
       AUTO_ALLOWED      -> authorized runtime safeguards -> Cortex
       APPROVAL_REQUIRED -> authenticated, unexpired, exact-action approval
                             -> recheck safeguards -> Cortex if approved
       NOT_ALLOWED       -> no Cortex -> internal case
  -> verification, rollback/expiry where applicable, PostgreSQL and audit
  -> Website (via authenticated AthenaSec backend APIs only)
```

The above is the **agreed target workflow**; some paths remain unverified or incomplete in the deployed system. The current graph includes both structured V2 nodes and compatibility policy/response-plan models; do not mistake their presence for two independent execution authorities. The legacy response path must not bypass V2 policy. TheHive is not part of AthenaSec.

- **Wazuh** owns detection and original event context; ML predictions are not ground-truth labels.
- **Qwen/LangGraph** may investigate and propose, never authorize execution.
- **Incident risk** assesses the incident; **action risk** assesses each proposed action. Only deterministic policy determines `AUTO_ALLOWED`, `APPROVAL_REQUIRED`, or `NOT_ALLOWED`.
- **Approval** is authenticated, time-limited, audited, and bound to the proposed action fingerprint; approval cannot override protected targets or other safety restrictions. Rejected/expired approvals lead to internal cases.
- **Cortex** is the permitted action executor; authorization, execution recording, independent verification, and rollback/expiry where applicable remain mandatory.
- **PostgreSQL** is the intended production system of record. SHADOW makes no Cortex calls. `AUTONOMOUS_RESPONSE_ENABLED=false` prevents Cortex execution while investigations/cases/audits continue where dependencies allow. SUPERVISED and AUTONOMOUS both preserve mandatory approvals.

## 2. Existing Python contracts at the reviewed commit

All names below are **existing Pydantic types in `agent/app/schemas.py`**; the table does **not** claim public CRUD routes already exist for them.

| Relationship/stage | Existing model(s) | Canonical identifiers and meaningful fields |
|---|---|---|
| Normalized alert | `SecurityAlertInput` | `alert_id`, `source`, `event_text`, `metadata` |
| ML prediction | `AttackPrediction` | `classification`, `confidence`, `model_version` |
| Incident and correlation | `IncidentRecord`, `IncidentAlertRecord`, `IncidentCorrelationDecision` | `incident_id`; `alert_id` + `incident_id`; `observed_at`, duplicate flag, match score/reasons |
| Investigation | `IncidentInvestigationRecord` | `investigation_id`, `incident_id`, `primary_alert_id`, status, timestamps, budget, sufficiency/verification flags |
| Evidence | `EvidenceRecord`, `InvestigationEvidenceRecord` | `evidence_id`, source, optional evidence type, content; persisted record additionally has `investigation_id`, `captured_at` |
| Trace | `InvestigationTraceStep`, `InvestigationStepRecord` | sequence/step type/status/time; persisted record additionally has `investigation_id`, `step_id` |
| Analysis and checks | `AlertAnalysis`, `EvidenceSufficiencyAssessment`, `AnalysisVerificationResult` | classification, cited evidence refs, required/missing types, `sufficient`, `verified`, blockers |
| Incident risk | `RiskAssessment`, `IncidentRiskAssessmentRecord` | score 0–100, risk band, factors; persisted version links incident/investigation and `risk_assessment_id` |
| LLM action and persisted proposal | `ResponseActionProposal`, `StructuredResponseProposal`, `ProposedActionRecord` | action type/target/reason/evidence refs; persisted `proposed_action_id`, `incident_id`, `investigation_id`, `parameters`, reversal metadata |
| Action risk | `ActionRiskAssessmentRecord` | `action_risk_id`, `proposed_action_id`, score/band, blast radius, protection flag, `requires_approval` |
| Deterministic action policy | `IncidentPolicyDecisionRecord` | `decision_id`, `incident_id`, `proposed_action_id`, `policy_id`, `outcome`, reason/time |
| Exact-action human approval | `ApprovalRequestRecord` | `approval_id`, `incident_id`, `proposed_action_id`, `policy_decision_id`, `action_fingerprint`, status, actors/times |
| Execution | `ResponseActionRecord`, `ActionExecutionResultRecord` | `response_action_id`, `proposed_action_id`, optional `approval_id`; `action_result_id`, status, details |
| Independent verification | `ActionVerificationRecord` | `verification_id`, `response_action_id`, `proposed_action_id`, status and verification time |
| Reversal/expiry | `ActionRollbackRecord`, `ContainmentExpiryRecord` | `rollback_id`/`expiry_id`, action linkage, target, status, expiry/lease fields |
| Internal incident case | `IncidentCaseRecord` | `case_id`, `incident_id`, optional `investigation_id`/`policy_decision_id`, reason/status/times |
| Incident audit | `IncidentAuditRecord` | `audit_id`, `incident_id`, `event_type`, `entity_type`, `entity_id`, details/time |

**Compatibility distinction:** The older `CaseRecord` and `AuditRecord` are **alert-based** (`alert_id`) and separate from `IncidentCaseRecord` and `IncidentAuditRecord`. `InvestigationResponse` is the current detailed investigation response model, not a complete incident/case listing contract. Website Backend must explicitly define any unified read model, rather than silently mapping legacy records onto V2 incident records.

## 3. Identifier rules and raw-source provenance

### 3.1 The actual Wazuh alert-ID conversion

`agent/app/tools/wazuh_alert_parser.py::parse_wazuh_alert` reads either `payload['_source']` or the top-level payload. It requires `_id` or raw Wazuh `id` and builds `SecurityAlertInput.alert_id` as follows:

- When `_id` **and** `_index` are present: `<_index>:<_id>`.
- Otherwise: `wazuh:<_id-or-raw-id>` (the chosen identifier prefers `_id`).
- It also retains raw references in `metadata`: `wazuh_alert_id`, `wazuh_document_id`, and `wazuh_index` where supplied.

**Consequence:** The normalized `alert_id` is not necessarily equal to the original Wazuh `id`. Do not strip prefixes, invent IDs in the frontend, or join raw alert IDs and normalized IDs without an explicit mapping. Cross-installation namespaces, data retention, and duplicate-collision guarantees still require integration review.

### 3.2 Logical join graph

```text
SecurityAlertInput.alert_id
   -> IncidentAlertRecord(alert_id, incident_id) -> IncidentRecord.incident_id
   -> IncidentInvestigationRecord(investigation_id, incident_id, primary_alert_id)
      -> InvestigationEvidenceRecord(investigation_id, evidence_id)
      -> InvestigationStepRecord(investigation_id, step_id)
      -> IncidentRiskAssessmentRecord(risk_assessment_id, incident_id, investigation_id)
      -> ProposedActionRecord(proposed_action_id, incident_id, investigation_id)
         -> ActionRiskAssessmentRecord(action_risk_id, proposed_action_id)
         -> IncidentPolicyDecisionRecord(decision_id, incident_id, proposed_action_id)
            -> ApprovalRequestRecord(approval_id, policy_decision_id,
                                     proposed_action_id, action_fingerprint)
         -> ResponseActionRecord(response_action_id, proposed_action_id, approval_id?)
            -> ActionExecutionResultRecord(action_result_id, response_action_id)
            -> ActionVerificationRecord(verification_id, response_action_id, proposed_action_id)
            -> ActionRollbackRecord(rollback_id, response_action_id, ...)
            -> ContainmentExpiryRecord(expiry_id, response_action_id, ...)
   -> IncidentCaseRecord(case_id, incident_id, investigation_id?, policy_decision_id?)
   -> IncidentAuditRecord(audit_id, incident_id, entity_type, entity_id)
```

This is a **logical relationship diagram**, not a certification that all SQL foreign-key constraints, transactions, migrations, or website joins have been verified. A single incident can correlate multiple alerts. Keep `alert_id`, `incident_id`, and `investigation_id` separate.

### 3.3 Evidence and exact-action rules

1. Evidence IDs are validated against `E\d{3,}` by current Pydantic validators. Treat them as **investigation-scoped**, using `(investigation_id, evidence_id)` when indexing persisted evidence; `E001` alone does not identify a global evidence record.
2. `EvidenceRecord` currently does **not** include raw Indexer `_index`/`_id`, Wazuh alert ID, time-window, provider identity, query, or a source checksum as first-class fields. `InvestigationEvidenceRecord` adds only the investigation link and capture timestamp. A future source-provenance/read-model extension needs approval; don't imply these fields already exist.
3. `action_fingerprint` is SHA-256 over the persisted action's ID, incident/investigation IDs, action/target and parameters, reversibility and rollback fields (`agent/app/services/action_approval.py`). The fingerprint **does not include the descriptive `reason` or `proposed_at` fields**. Authorization must additionally validate policy ID links, operator identity, status/expiry, protection and current kill switch at execution time. **Approval-scope decision:** Explicitly accept or change this exact set of fingerprint-covered fields before calling it an approved cross-team exact-action contract. A changed descriptive reason is not itself detected by the current action fingerprint.
4. Timestamps should be represented on the web/API as unambiguous timezone-aware ISO 8601 values. This is a **cross-team interface requirement**; do not claim every existing timestamp or legacy DTO has been validated for this property.
5. Never treat a matching LLM string, UI `APPROVED` badge, or ML confidence as execution permission; use the authenticated backend's persisted state and current deterministic checks.
6. Duplicate-alert processing is present in `app/main.py` and `app/services/incident_correlator.py`; comprehensive delivery/retry/idempotency acceptance remains Phase 5/6 work.

## 4. Verified route inventory versus requested APIs

The following routes **exist in `agent/app/main.py` at the reference commit**:

| Route | Current contract / important caveat |
|---|---|
| `POST /api/v1/integrations/wazuh/alerts` | Wazuh payload; configured `X-AthenaSec-Integration-Key` required; parses/correlates/investigates. Not a `SecurityAlertInput` JSON contract. |
| `POST /api/v1/analyze` | Accepts caller-supplied `SecurityAlertInput`; returns `InvestigationResponse` and invokes `run_investigation`. **No authentication dependency is declared on this route at the reviewed commit.** It is not proof of authenticated Wazuh forwarding and must not be assumed read-only or safe to expose to untrusted callers. |
| `GET /api/v1/investigations/{alert_id}` | Returns `InvestigationResponse` by alert ID, or 404. |
| `GET /api/v1/investigations/{alert_id}/case` | Returns **legacy** `CaseRecord` (if any), not a V2 incident-case listing. |
| `GET /api/v1/investigations/{alert_id}/audit` | Returns list of **legacy** `AuditRecord`, not guaranteed to include all incident-level audit events. |
| `GET /api/v1/approvals/{approval_id}` | Operator-authenticated approval read. |
| `POST /api/v1/approvals/{approval_id}/decision` | Authenticated and authorized decision; session-auth flow includes CSRF check. |

**Security review blocker before network exposure:** The reviewed `POST /api/v1/analyze` handler calls `run_investigation` without a route-level identity or integration-key check. The V2 structured-action builder requires incident/investigation context, which this entrypoint does not supply directly, but that does **not** establish a general no-side-effects or no-execution guarantee for future revisions. Require a documented exposure decision (disable, isolate, or authenticate/authorize), request-size/rate limits, and negative tests before allowing this endpoint on an untrusted network. This is a source-review observation, **not** an exploited vulnerability or a live security test.

**Not yet agreed/proven as website-facing contracts:** authenticated incident/case/action/approval list/detail endpoints, pagination/filtering, persisted evidence references and trace, verification/rollback/expiry timeline, and consistent frontend authorization. Other auth/runtime routes may exist; use the current source/OpenAPI for their exact request/response shapes. Do not fabricate endpoints in implementation based on this document.

**Website Backend action mapping:** The structured action proposal types in the source are `block_ip`, `lock_account`, and `capture_telemetry`. The legacy `AllowedAction` type also has `notify_administrator`, `create_case`, and `record_response`; these are **not** automatically executable Cortex action types. `SUPPORTED_ACTIONS` in `agent/app/services/action_policy_engine.py` is authoritative for structured V2 policy at this commit.

## 5. Concrete fixture examples (NOT observed live results)

### Normalized test input for `POST /api/v1/analyze`

```json
{
  "alert_id": "wazuh:example-0001",
  "source": "wazuh",
  "event_text": "Fixture: repeated failed SSH authentication",
  "metadata": {
    "rule_level": 8,
    "failed_attempts": 6,
    "source_ip": "192.0.2.10",
    "agent_id": "demo-agent-01",
    "target_user": "test-user"
  }
}
```

This is a **manually constructed `SecurityAlertInput` fixture** using a documentation IP address. It is not a raw Wazuh event, a ground-truth malicious label, or proof the parser generated these fields.

### Policy/approval illustration (joined fragments; NOT a current API response)

```json
{
  "proposed_action_id": "PACTION-demo",
  "decision_id": "PDEC-demo",
  "policy_id": "POL-ACTION-HUMAN-APPROVAL",
  "outcome": "APPROVAL_REQUIRED",
  "approval": {
    "approval_id": "APR-demo",
    "proposed_action_id": "PACTION-demo",
    "policy_decision_id": "PDEC-demo",
    "action_fingerprint": "example-not-a-real-hash",
    "status": "PENDING",
    "expires_at": "2026-10-20T16:00:00+00:00"
  }
}
```

Do not submit these demo IDs as live authorization fixtures or claim that a combined policy-plus-approval object is an existing route.

## 6. Required safe outcomes, and how strongly they are supported

| Condition | Required contract/safety outcome | Evidence state on reviewed branch |
|---|---|---|
| Missing/incorrect Wazuh key or malformed alert | Reject ingestion; no Cortex execution | Ingest code and matching unit tests present; tests **not run in this review** |
| ML loader failure or per-request exception | Explicit unavailable/unknown classification, record error, never treat failure as a benign label | `runtime_config.py` and `main.py` implement fallback; negative-path integration unverified |
| ML prediction `benign` | No-action fast path; retain prediction, not asserted ground truth | Implemented builder/route; risk of false-benign short circuit must be evaluated |
| Required Wazuh evidence absent/analysis unverified | No automatic Cortex action based on unverified analysis; persist limitations when possible | Evidence checks implemented; deployment and failure persistence not certified |
| MISP unavailable | Record `misp_error`, do not invent an IOC result; continue with verified mandatory evidence if independently sufficient | Node handles enrichment exceptions; **not** an automatic blanket authorization denial |
| Unsupported action, action-risk identity mismatch or protected target | `NOT_ALLOWED`, no Cortex, internal case per policy lifecycle | Deterministic policy code/structured case paths present; live end-to-end not certified |
| Action needs approval | Persist exact-action approval; require authorization, expiry and safety rechecks | Code/tests exist; live operator-to-Cortex boundary not certified |
| SHADOW or master kill switch disabled | Zero Cortex calls, continue non-execution processing as dependencies permit | Runtime safeguards/code/tests exist; production installation not certified |
| Cortex timeout or unexpected response | Treat as **unknown outcome** until independent target-state verification/reconciliation; never blindly retry or claim failure/success | Target requirement; live timeout/responder testing pending |
| Database outage during/before action | Do not silently authorize action without durability; audit/recover and reconcile any action that **may already have executed** | Recovery work pending Phase 3/6; zero-execution guarantee after an in-flight call cannot be assumed |
| Reversible action expires or verification fails | Safe rollback/expiry, protected-target checks, cases and audit for unresolved failure | Implemented service components; real target-state tests pending |

## 7. Open decisions requiring Phase 0 signatures

| Decision / gap | Required owner(s) | Follow-up |
|---|---|---|
| Confirm this identifier mapping, raw-source provenance requirements, and `EvidenceRecord` limitations | Daniel + Ahmad | Phase 0 agreement; Phase 5 verification/changes if approved |
| Approve normalized Wazuh ID handling across installations and Indexer index rotation | Agent + Scripts | Phase 0 interface; Phase 5 delivery/retry tests |
| Publish the website's actual DTO mapping and canonical list/detail routes, including legacy-to-V2 case/audit read semantics | Website Backend + Daniel | Phase 0 approval; Phase 3 implementation |
| Verify supported UI actions and exact action authorization, identity, and anti-CSRF mapping | Website Backend + Daniel | Phase 0 mapping; Phase 6 safety tests |
| Agree the access policy for unauthenticated `POST /api/v1/analyze`, plus test exposure/side-effect boundaries | Agent + Website Backend + Scripts | Phase 0 trust-boundary decision; Phase 3/5 implementation/testing |
| Confirm network/trust boundaries and production secrets/TLS ownership | Scripts + Daniel | Phase 0 approval; Phase 1–3 integration |
| Confirm PostgreSQL schema/migrations ownership and persisted ID integrity | Website Backend + Scripts + Agent | Phase 0 ownership; Phase 3 tests |
| Document evidence grades, required source references and positive/negative response scenarios | Ahmad + Daniel | Phase 0 docs; Phase 5/9 evidence |

**Phase 0 sign-off requirement:** Agent (Daniel and Ahmad), Website Backend and Scripts must approve this interface or record blocking disagreements. Website Frontend's related fixture/API mapping inventory is tracked in the overall phase gate. Unreviewed design prose is not final cross-team acceptance.
