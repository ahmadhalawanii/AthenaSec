# AthenaSec — Phase 0 Completion and Cross-Team Sign-Off

**Phase:** 0 — Research, Requirements & System Architecture (all teams).
**Roadmap baseline:** `tasks.md`, checkpoint 2026-10-19. **Target date:** 2026-10-20 (target, not a waiver of requirements).
**Agent source baseline:** `feature/agentic-response-v2` @ `7e87159d100614e709ca2b6ee0fb38523fc5e70a`.
**Status:** **OPEN — do not advance to Phase 1 until every required owner and acceptance gate has signed off.** This document is tracking, not a test report.

## 1. Agent Phase 0 requirements (original roadmap wording and current disposition)

| Owner | Roadmap Phase 0 task | Roadmap starting status | Evidence / review status |
|---|---|---|---|
| Daniel | ML dataset provenance, 15-feature design and training methodology | Done | Existing implementation/documentation; production claims not inferred |
| Daniel | Wazuh → ML → evidence → risk → authorization architecture | Done | Existing design; no additional end-to-end run conducted for this review |
| Daniel | LangGraph, Qwen3:4B and PostgreSQL backend design | Done | Existing design; deployed live connectivity not certified |
| Daniel | Incident risk versus action risk and human approval safety design | Done | Existing design/code separation; execution safety still requires later tests |
| Daniel | Publish an end-to-end alert, evidence, case, action and approval schema contract across the detection-to-response pipeline | Not started | `integration_contract.md` — **revised draft, checked against reviewed code; requires cross-team acceptance** |
| Daniel | Define ML acceptance thresholds for recall, false positives and representative test coverage | Not started | `ml_acceptance_gates.md` — **measurable proposal, pending numeric approval** |
| Ahmad | Write investigation and response test matrix with expected safe outcomes | Not started | `test-matrix.md` received and statically reviewed; **revisions requested, not signed off** |
| Ahmad | Define what evidence qualifies as mock, simulated, isolated-live and production-live | Not started | `evidence-classification.md` received and statically reviewed; **revisions requested, not signed off** |

Ahmad's two submissions are **not included** in Daniel's revision ZIP. On acceptance, place the approved versions under `agent/docs/phase0/` using the agreed filenames and verify they reference the same canonical code baseline. The prior `ahmad_work_order.md` was a private handoff/instruction file and is **not a required repository deliverable**.

## 2. Other team Phase 0 requirements still needing owner evidence

| Owner | Roadmap task | Roadmap checkpoint status |
|---|---|---|
| Scripts | Network/trust-boundary diagram across Wazuh, MISP, Cortex, Ollama, PostgreSQL, backend and browser | Not started |
| Scripts | MISP image/source/Compose version compatibility decision | Being worked on |
| Scripts | Host/ports/TLS/DNS/versions/resource deployment matrix | Not started |
| Scripts | Installer acceptance tests and expected failure outcomes | Not started |
| Website Backend | API mappings for alert, incident, investigation, evidence, action and approval IDs | Not started |
| Website Backend | Reconcile website action names with V2-supported actions | Started but postponed |
| Website Backend | Reconcile website policy UI with deterministic agent policy | Started but postponed |
| Website Backend | Agree health identifiers and frontend/backend response schema | Being worked on |
| Website Backend | Endpoint, identifier and authorization matrix for every page | Not started |
| Website Backend | Website API test matrix and representative fixtures | Not started |
| Website Frontend | Inventory hardcoded fixtures, demo identities, static metrics and placeholder endpoints | Not started |

These status labels are a **2026-10-19 roadmap snapshot**, not current verified completion claims. Request updated evidence from each owner before closure. Tasks already marked `Done` in the full roadmap remain part of Phase 0's overall historical completion baseline.

## 3. Phase 0 closure checklist — record evidence rather than assuming completion

- [ ] Daniel's `integration_contract.md` accepted by Agent/Ahmad, Website Backend and Scripts. Agree raw Wazuh IDs versus normalized IDs, legacy versus V2 case/audit DTOs, evidence provenance limitations, supported action names and trust boundaries. Include the `POST /api/v1/analyze` trust-boundary/access decision and the exact fields included in action approval fingerprints.
- [ ] Daniel's `ml_acceptance_gates.md` numeric thresholds/sampling rules approved by Daniel, Ahmad and team/security approver (or revised and then explicitly approved). **Definition** of gates is Phase 0; **achievement** is later evaluation. Confirm how independence is judged beyond unique feature vectors and that low-confidence/missing-signal runtime handling is marked unverified until tested.
- [ ] Ahmad's revised response/investigation matrix maps safe outcomes to existing tests or clearly marked gaps and separates source review from test execution.
- [ ] Ahmad's revised four-tier evidence document states provenance requirements and does not call simulated Cortex execution "live containment".
- [ ] Scripts' Phase 0 trust/ports/TLS/version/resource/installer-rejection requirements are documented and reviewed.
- [ ] Website Backend's Phase 0 API/action/policy/authorization mapping and representative fixtures are reviewed, with unresolved schema mismatches tracked.
- [ ] Website Frontend's demo/placeholder inventory reviewed and labeled for presentation/integration planning.
- [ ] Reviewed commit, working-tree status and non-secret diff recorded; no secrets, passwords, live tokens or private user data committed.
- [ ] Explicit Phase 0 agreement from **Agent, Scripts, Website Backend and Website Frontend** documented; blockers closed or accepted through a documented, authorized scope decision.

## 4. Evidence / approval record (fill with real links and dates)

| Approver | Name or team representative | Date/time (timezone) | Review commit / PR link | Decision / blockers |
|---|---|---|---|---|
| Agent — Daniel | Pending | Pending | Pending | Pending |
| Agent — Ahmad | Pending | Pending | Pending | Pending |
| Scripts | Pending | Pending | Pending | Pending |
| Website Backend | Pending | Pending | Pending | Pending |
| Website Frontend | Pending | Pending | Pending | Pending |

**Not required in Phase 0:** Running live Cortex responders, hitting future model performance targets, spinning up/rebuilding production Docker services, declaring successful end-to-end live operation, or merging unreviewed feature branches. A one-day target never converts `not-run` into `pass`.

**Phase transition decision as of this document:** **BLOCKED — Phase 0 remains OPEN.**
