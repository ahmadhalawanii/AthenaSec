\# AthenaSec ML Integration Design



\## Purpose



The machine learning component provides AthenaSec with an initial

attack classification before the agentic investigation begins.



The ML model is not responsible for autonomous response decisions.



Its role is to provide:



\- predicted attack classification

\- prediction confidence

\- model identification/version



The final security decision remains deterministic.



\---



\## Final AthenaSec Flow



Wazuh detects a security event.



↓



ML classifies the event.



↓



MISP enriches indicators related to the event.



↓



The Agentic AI investigates using:



\- the original Wazuh alert

\- the ML prediction

\- MISP enrichment

\- grounded Wazuh evidence



↓



The deterministic risk engine calculates risk.



↓



The deterministic policy engine determines whether response is permitted.



↓



If response is not permitted:



\- AthenaSec automatically creates a case

\- the event and decision are stored

\- the complete process is audited



↓



If response is permitted:



\- AthenaSec executes the permitted Cortex responder

\- the result is stored

\- the complete process is audited



\---



\## ML Responsibility



The ML model provides an initial attack hypothesis.



Example:



classification: brute\_force



confidence: 0.93



model\_version: athenasec-classifier-v1



The prediction becomes part of the investigation state.



The ML model must not:



\- execute Cortex actions

\- decide whether response is permitted

\- calculate the final deterministic risk score

\- override the policy engine



\---



\## Agentic AI Responsibility



The Agentic AI receives the ML prediction as an investigation hypothesis.



It must investigate that hypothesis against grounded evidence.



The Agentic AI may conclude that the evidence does not support the

initial ML prediction.



The investigation output should therefore distinguish between:



\- ML prediction

\- investigation classification

\- supporting evidence

\- uncertainty



This prevents an incorrect ML prediction from automatically becoming

a security response.



\---



\## Risk and Policy Authority



The deterministic risk engine remains responsible for calculating

the final risk score.



The deterministic policy engine remains responsible for deciding:



response\_allowed = true



or



response\_allowed = false



No LLM or ML output directly authorizes an autonomous response.



\---



\## ML Interface



AthenaSec will introduce an MLClassifier interface.



The investigation pipeline will depend on this interface rather than

directly depending on a specific trained model.



The classifier will return an AttackPrediction containing:



\- classification

\- confidence

\- model\_version



This allows AthenaSec to use:



\- fake classifiers during tests

\- local trained models

\- future replacement models



without changing the investigation architecture.



\---



\## Failure Behaviour



If the ML classifier cannot produce a prediction, AthenaSec must fail

safely.



A classifier failure must not silently produce a trusted classification.



The failure should be recorded and handled explicitly by the

investigation workflow.



Autonomous response must never occur solely because ML classification

failed or returned invalid output.



\---



\## Testing Strategy



ML integration will be implemented using test-driven development.



Tests will cover:



1\. AttackPrediction schema validation.

2\. MLClassifier interface behaviour.

3\. Investigation state stores the ML prediction.

4\. The graph invokes the classifier.

5\. The AI investigation receives the ML prediction.

6\. Invalid ML confidence is rejected.

7\. Classifier failure is handled safely.

8\. Existing AthenaSec investigation behaviour remains compatible.

9\. The complete existing test suite continues to pass.



Real trained-model loading will be added only after the pipeline

interface is stable and tested.



\---



\## Initial Supported Focus



The first AthenaSec ML training focus is:



\- brute-force attacks

\- privilege misuse



The architecture must remain extensible so additional attack classes

can be added later without changing the investigation pipeline.



\---



\## Final Authority Chain



ML

&#x20;   = predicts



Agentic AI

&#x20;   = investigates



Risk Engine

&#x20;   = calculates danger



Policy Engine

&#x20;   = determines permission



Cortex

&#x20;   = executes permitted response



Database and Audit

&#x20;   = preserve the complete record



\## Implemented ML Training and Evaluation Status



AthenaSec's ML training pipeline is now implemented and validated against real Wazuh-generated observations.



External datasets provide behavior labels and provenance only. They do not directly provide AthenaSec's runtime ML feature values.



The implemented training path is:



External dataset behavior



→ deterministic BehaviorReplay manifest



→ approved Wazuh lab scenario



→ real Wazuh alert



→ existing Wazuh parser



→ existing 15-feature extractor



→ TrainingRow



This preserves the same feature contract between training and runtime.



\### Runtime Feature Contract



AthenaSec uses the following exact 15 ML features:



1\. rule\_level

2\. rule\_frequency

3\. failed\_attempts

4\. privileged\_target

5\. source\_port

6\. destination\_port

7\. has\_source\_ip

8\. has\_target\_user

9\. has\_agent

10\. mitre\_id\_count

11\. rule\_group\_count

12\. is\_sudo\_event

13\. is\_account\_change\_event

14\. is\_privilege\_group\_change

15\. has\_command



No external dataset feature is fabricated or arbitrarily zero-filled to satisfy this contract.



\### Phase 13 Replay Dataset



Phase 13 executed 108 deterministic behavior replays through the real Wazuh lab.



Raw labels:



\* benign: 40

\* brute\_force: 30

\* privilege\_misuse: 38



All 108 captures contained valid Wazuh event IDs.



There were:



\* 108 unique Wazuh event IDs

\* 0 missing event IDs

\* 0 duplicate event IDs

\* 108 unique replay execution identities

\* 0 missing provenance records



After conversion through the existing runtime parser and feature extractor, all 108 TrainingRows contained exactly the required 15 features.



\### Feature Diversity



The 108 real-Wazuh TrainingRows produced 51 unique full feature vectors:



\* benign: 14

\* brute\_force: 24

\* privilege\_misuse: 13



Phase 12 contained 45 unique full vectors, including only 7 unique privilege\_misuse vectors.



Phase 13 therefore increased privilege-misuse feature diversity from 7 to 13 unique vectors.



When source\_port is excluded from the diversity comparison, unique vectors increased from 12 in the earlier dataset to 18 in Phase 13.



No cross-label feature-vector collisions were observed.



\### Leakage-Safe Evaluation



The random evaluation methodology was strengthened to prevent replay leakage.



Rows are treated as inseparable when they share either:



\* the same external provenance `(source\_dataset, source\_row\_id)`, or

\* the exact same 15-feature vector.



Connected provenance/feature components are allocated deterministically across train, validation, and test partitions.



Allocation is weighted by unique Wazuh feature-vector diversity so that the training partition retains the majority of meaningful feature diversity.



Deduplication then occurs independently inside train, validation, and test.



Benign undersampling and class weighting are applied to the training partition only.



The final Phase 13 split contained zero provenance overlap and zero exact-feature-vector overlap between all partitions.



Unique feature vectors after partition deduplication:



\* training: 35



&#x20; \* benign: 10

&#x20; \* brute\_force: 17

&#x20; \* privilege\_misuse: 8

\* validation: 7



&#x20; \* benign: 2

&#x20; \* brute\_force: 4

&#x20; \* privilege\_misuse: 1

\* test: 9



&#x20; \* benign: 2

&#x20; \* brute\_force: 3

&#x20; \* privilege\_misuse: 4



\### Random Forest Evaluation



Using the leakage-safe Phase 13 split, the Random Forest achieved:



Validation:



\* accuracy: 85.7%

\* macro F1: 0.778

\* benign recall: 50%

\* brute\_force recall: 100%

\* privilege\_misuse recall: 100%



Test:



\* accuracy: 88.9%

\* macro F1: 0.852

\* benign recall: 50%

\* brute\_force recall: 100%

\* privilege\_misuse recall: 100%



The Logistic Regression baseline produced the same predictions on these validation and test partitions.



These results must be interpreted with the held-out support sizes. In particular, the validation partition contains only one unique privilege\_misuse vector.



\### Leave-One-Dataset-Out Evaluation



Leave-one-dataset-out evaluation holds an entire external dataset out before deduplication, balancing, class weighting, and model fitting.



Results:



ADFA-LD held out:



\* accuracy: 100%

\* benign recall: 100%

\* brute\_force recall: 100%

\* privilege\_misuse recall: 100%

\* privilege\_misuse support: 1 unique vector



CIC IDS 2017 held out:



\* accuracy: 100%

\* benign recall: 100%

\* brute\_force recall: 100%

\* privilege\_misuse support: 0



CIC IDS 2018 held out:



\* accuracy: 100%

\* benign recall: 100%

\* brute\_force recall: 100%

\* privilege\_misuse support: 0



CMU CERT r4.2 held out:



\* accuracy: 7.69%

\* privilege\_misuse recall: 7.69%

\* privilege\_misuse support: 13 unique vectors

\* 1 of 13 privilege\_misuse vectors was correctly classified

\* 12 of 13 were classified as benign



The CMU result demonstrates a remaining cross-dataset privilege-misuse generalization weakness.



Phase 13 improves Wazuh-observed privilege diversity, but the additional privilege diversity is primarily backed by CMU behavior replays. When CMU is completely unseen, the remaining external privilege coverage is not sufficiently diverse.



\### Privilege Scenario Holdouts



Each approved privilege Wazuh scenario was also held out independently.



Exact held-out feature vectors were removed from the training partition before fitting.



All scenario evaluations had zero exact-vector overlap.



Results:



\* sudo\_three\_failed\_attempts: 100% privilege\_misuse recall across 4 unique vectors

\* sudo\_unauthorized\_user: 100% privilege\_misuse recall across 4 unique vectors

\* sudo\_command\_not\_allowed: 100% privilege\_misuse recall across 4 unique vectors

\* user\_added\_to\_sudo\_group: 100% privilege\_misuse recall across 1 unique vector



These tests demonstrate generalization between the currently approved Wazuh privilege scenarios.



They do not prove broad cross-dataset privilege generalization because each held-out scenario currently represents limited independent external provenance.



\### Phase 12 vs Phase 13



Under the final leakage-safe methodology:



Phase 12 Random Forest test:



\* accuracy: 83.3%

\* macro F1: 0.778

\* privilege\_misuse test support: 1 unique vector



Phase 13 Random Forest test:



\* accuracy: 88.9%

\* macro F1: 0.852

\* privilege\_misuse test support: 4 unique vectors



A controlled comparison was also performed using the exact same Phase 13 validation and test observations.



The old-data Random Forest used:



\* 31 unique training vectors

\* 4 unique privilege\_misuse training vectors



The Phase 13 Random Forest used:



\* 35 unique training vectors

\* 8 unique privilege\_misuse training vectors



Both models produced identical predictions on the shared validation and test observations.



Therefore, Phase 13 adds meaningful real-Wazuh training diversity, but the current evidence does not demonstrate a sufficiently strong deployment prediction advantage over the existing production model.



\### Production Model Decision



The existing production artifact remains:



`athenasec-classifier-v1.pkl`



Phase 13 does not replace the production classifier at this stage.



The reasons are:



\* Phase 13 improves real-Wazuh privilege feature diversity.

\* Leakage-safe random evaluation is stronger than the earlier methodology.

\* Privilege scenario holdouts perform well.

\* The controlled old-data and Phase 13 Random Forests produce identical predictions on the same held-out observations.

\* CMU leave-one-dataset-out privilege generalization remains weak.

\* Benign recall remains 50% in the current leakage-safe random validation and test partitions.



A future model should replace v1 only when evaluation demonstrates a clear improvement without weakening AthenaSec's safety and generalization requirements.