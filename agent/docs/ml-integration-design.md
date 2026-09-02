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

