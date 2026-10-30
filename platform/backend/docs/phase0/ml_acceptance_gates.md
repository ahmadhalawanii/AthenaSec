# AthenaSec — Phase 0 ML Acceptance Thresholds and Representative Coverage

**Owner:** Daniel (Agent/ML). **Status:** Quantitative acceptance **proposal**, reviewed for consistency; numeric approval pending.
**Roadmap requirement:** "Define ML acceptance thresholds for recall, false positives and representative test coverage." (`tasks.md`, Phase 0)
**Code baseline:** `ahmadhalawanii/AthenaSec`, `feature/agentic-response-v2`, `7e87159d100614e709ca2b6ee0fb38523fc5e70a`.
**Evidence distinction:** This file specifies the targets to use for Phase 4/10 model evaluation. **It does not claim that the model reaches them, that tests passed, or that production autonomy is authorized.**

## 1. Locked interface and ground truth

**Primary categories:** `benign`, `brute_force`, `privilege_misuse`. The runtime models additionally permit `privilege_escalation` and `unknown` where supported. Do **not** map these into primary labels silently; report their prediction/support separately.

**Exact 15-feature runtime order** (`agent/app/ml/feature_extractor.py`):

```text
rule_level, rule_frequency, failed_attempts, privileged_target,
source_port, destination_port, has_source_ip, has_target_user, has_agent,
mitre_id_count, rule_group_count, is_sudo_event,
is_account_change_event, is_privilege_group_change, has_command
```

Training/inference must use the same approved Wazuh parser and extractor. Correct provenance path: **external dataset behavior/label → adapter → deterministic BehaviorReplay → approved Wazuh scenario → actual Wazuh alert → parser → 15-feature extractor → labeled row**. Never fabricate Wazuh-derived feature values from raw external dataset columns. Preserve row IDs, dataset provenance and exact replay mapping. An ML prediction is an inference, not ground truth or a response authorization.

**Current runtime nuance:** `extract_ml_features()` maps missing optional alert metadata through numeric/flag/count defaults (often `0`); an incomplete *alert* is not universally rejected for absent feature values. By contrast, `model_loader.py` rejects artifacts whose **saved feature-name order** does not match the runtime 15-feature contract. Test and report both behaviors distinctly; missing metadata may lower classification reliability even when the model loads.

## 2. Proposed measurable thresholds

The thresholds below are **proposed acceptance criteria to be signed off by the team**, not requirements already stated numerically in `tasks.md`. They are intentionally stricter than the known small-sample results and may require additional independent data collection.

| Measure | Proposed acceptance threshold | Counting rule |
|---|---|---|
| Brute-force recall | **≥ 90%** | Correct `brute_force` / all ground-truth `brute_force` cases; non-brute predictions, including `unknown`, count as misses |
| Privilege-misuse recall | **≥ 90%** | Correct `privilege_misuse` / all true privilege-misuse cases; `unknown` also counts as a miss |
| Attacks mislabeled as benign | **≤ 2%** | All ground-truth malicious cases predicted `benign` / all ground-truth malicious cases; report per malicious class |
| Benign precision | **≥ 98%** | Correct `benign` / all predictions of `benign`; especially important because the current Wazuh benign fast path can skip the investigation graph |
| Benign false-alert/workload rate | **≤ 5%** | True benign cases predicted **any non-benign label** (`brute_force`, `privilege_misuse`, `unknown`, etc.) / all ground-truth benign cases. Also report separately (a) malicious-label false positives and (b) `unknown`/abstentions |
| Macro-F1 | **≥ 0.90** | Unweighted average F1 over `benign`, `brute_force`, `privilege_misuse` with zero-support/unknown treatment stated; report support and all per-class scores |
| Feature/model-loader compatibility | **100% of specified contract tests pass** | Exact 15 names/order, supported/required class mapping, model interface, version and unavailable/invalid artifact tests |
| Runtime failure safeguards | **100% of specified negative-path tests show no unauthorized action** | Model unavailable, corrupted artifact, invalid class mapping, missing required signal, low-confidence/unknown or parser failures; coverage/results must be shown, not assumed |

**Implementation status qualification:** These targets are policy proposals, not current runtime controls. In particular, the reviewed extractor may default missing metadata to `0`, and a model confidence score alone does not currently establish a configured low-confidence authorization gate. `unknown`, incomplete-feature and low-confidence cases therefore need explicit end-to-end negative testing before claiming zero unauthorized actions. If a gate is not implemented, report it as a gap rather than marking the proposed 100% target satisfied.

**Operational rule:** All test rows remain in their declared denominator. Do not drop false benign predictions or `unknown` predictions to inflate recall, precision, or false-positive results. Include confusion matrix and coverage explicitly. Report precision/recall/F1, macro-F1, balanced accuracy, malicious-as-benign rate, benign workload rate, and abstention/unknown frequency. An `unknown` prediction must not be portrayed as a successful malicious diagnosis; it may be a safe operational abstention when response authorization appropriately fails closed.

**Calibration reporting (not yet a fixed numeric pass threshold):** Reliability/calibration plots and Brier score or expected calibration error if probability outputs can be responsibly evaluated. Do not interpret uncalibrated `confidence` as a guaranteed likelihood of correctness.

## 3. Representative holdout and provenance acceptance

- **Minimum proposed candidate screening support:** At least **50 held-out unique 15-feature vectors per required class** (150 total) in the final test partition, **with independence assessed separately at original dataset/source, event, replay-template and scenario-group level**. Uniqueness of feature vectors alone does *not* establish statistical independence. This is **future target support**, not achieved/current data volume; the existing replay may not yet provide that diversity. Do not multiply counts by replaying the same feature vector, source event or closely related replay instance. For later production consideration, propose **100+ genuinely independent cases per class** spanning environments and datasets, subject to security-owner approval. Neither count automatically establishes production readiness or a sufficiently narrow confidence interval.
- Freeze train/validation/test assignment **before** comparing models. Isolate test by scenario/source as feasible, de-duplicate exact feature vectors and detect any cross-label collisions. Avoid shared behavior scenarios, user/host/time-window leakage or replay templates appearing across partitions. Use validation data for model selection and only untouched final test for final performance claims.
- Required scenario strata: routine benign login/account/group activity; SSH/failed-sudo brute force; unauthorized sudo; forbidden sudo command; privilege-group/account changes; source/IP/user context and absent-field/unknown cases. Identify when the same 15-feature vector occurs across different behaviors.
- Report leave-one-dataset-out and source/scenario holdouts for **each dataset/class combination with sufficient support**; clearly list unsupported cells. The nine adapter implementations are not evidence that all nine datasets yielded equivalent replay coverage. The original primary replay sources are CIC IDS 2017, CIC IDS 2018, ADFA-LD, and CMU CERT r4.2.
- Compute uncertainty intervals (e.g., 95% binomial interval) and show exact sample counts; when small samples leave wide intervals, report **provisional**, not production-qualified, even if point thresholds appear to pass.
- Retain a reproducible manifest: source dataset and row identifier, behavior label, approved replay scenario, Wazuh alert ID and optional Indexer `_index`/`_id`, normalized alert ID, extracted feature-vector hash, feature-order version, split/group assignment and seed, candidate/model version, artifact SHA-256, environment/version, and date. Store no secrets in it.
- Candidate models to evaluate on leakage-controlled validation evidence: Logistic Regression, Random Forest, ExtraTrees, and XGBoost. A perfect result on a tiny split is not sufficient model-selection justification. Preserve V1 compatibility; do not replace the packaged artifact until a tested replacement is approved and rollback is possible.

## 4. Levels of evidence versus deployment permission

| Stage | Evidence required | What it does **not** authorize |
|---|---|---|
| Development / SHADOW | Contract-valid load/inference, test matrix, transparent metrics/known limits, zero Cortex execution | Autonomous/live containment |
| Candidate for isolated integration | Numeric targets on adequately independent tests, per-class support/confusion matrix, artifacts/manifests, negative-path and integration checks | Production rollout or bypass of deterministic approvals |
| Production eligibility (later) | Untouched external/realistic testing, monitoring/calibration/rollback plan, pinned reviewed artifact, independent approval, real service and security sign-off | Execution outside the configured deterministic Action Policy Engine |

Even with high model scores: **MISP hits, ML confidence, and Qwen output cannot authorize Cortex**. Evidence verification, incident risk, action risk, protected-target rules, approvals and runtime safeguards remain mandatory. The current benign fast path is a **known safety-sensitive evaluation point**; false benign predictions do not magically become proven benign events.

## 5. Historical evidence (not re-tested for this review)

`agent/docs/ml-integration-design.md` on the reviewed branch reports a leakage-aware Phase 13 Random Forest test of **88.9% accuracy and 0.852 macro-F1 on 9 unique test vectors**, with **50% benign recall**. It also reports CMU CERT r4.2 leave-one-dataset-out privilege-misuse recall **7.69% (1 of 13 unique vectors)**; **12 of 13 were predicted benign**. This shows that strong within-scenario scores do not establish cross-dataset generalization.

A **later user-reported** evaluation of **18 correct out of 19 unique held-out vectors** exists in project discussion; the test manifest, model version and evaluation protocol for that figure were **not independently revalidated here**. Do not conflate these two evaluation runs or present them as production evidence.

The checked `agent/app/ml/model_loader.py` validates the model interface, feature-name ordering, required classes and version format. That is **runtime compatibility**, not proof of recall, calibration, representativeness or deployment quality.

## 6. Evidence required to sign off this requirement

**Phase 0 definition sign-off (not achievement):** The ≥90%, ≤2%, ≥98%, ≤5%, ≥0.90 and 50-per-class numbers are **choices to approve, not existing project facts**. If the team changes them, record the chosen thresholds and justification instead of silently treating proposals as approved. Daniel proposes numeric thresholds; Ahmad checks testability and sampling; team/security owner approves or records requested changes. Record approver, approval date and the chosen values in Git review or a phase decision record.

**Later Phase 4/9/10 achievement:** Save split/feature manifests and checksums, candidate comparison, held-out confusion matrices and per-class support, LODO/source holdouts, statistical uncertainty, deployed-artifact load/feature contract tests, fallback/negative-path tests, environment, branch/commit and independent review. A failed or unsupported metric remains explicitly **not qualified**; do not relax an approved threshold silently to make a release pass.
