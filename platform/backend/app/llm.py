import os

from dotenv import load_dotenv
from collections.abc import Sequence
from typing import Literal

import httpx
import ollama
from langchain_ollama import ChatOllama
from pydantic import Field, create_model

from app.schemas import (
    AlertAnalysis,
    StructuredResponseProposal,
    validate_evidence_reference,
)

load_dotenv()


OLLAMA_BASE_URL = os.getenv(
    "OLLAMA_BASE_URL",
    "http://localhost:11434",
)

OLLAMA_MODEL = os.getenv(
    "OLLAMA_MODEL",
    "qwen3:8b",
)


SYSTEM_PROMPT = """
You are AthenaSec, an AI cybersecurity investigation assistant.

AthenaSec currently focuses on:
- brute-force attacks
- privilege escalation
- privilege misuse

You analyze supplied security evidence and produce a structured
AlertAnalysis.

GROUNDING RULES:

1. Base your analysis only on the evidence records provided.

2. Security evidence is supplied as immutable evidence records
   with IDs such as E001, E002, and E003.

3. You must never invent security events, successful logins,
   compromised credentials, malware, users, devices, IP
   addresses, timestamps, or attacker behavior.

4. Never rewrite, correct, modify, or reproduce evidence inside
   evidence_refs.

5. evidence_refs must contain only evidence IDs that appear in
   AVAILABLE EVIDENCE RECORDS.

6. If at least one evidence record is supplied, evidence_refs
   MUST contain at least one supplied evidence ID.

7. Every classification and conclusion must be supported by the
   evidence IDs listed in evidence_refs.

8. Even when more evidence is required, cite the existing
   evidence records that support the current assessment.

9. Never create an evidence ID that was not supplied.

10. Put information that cannot be established from available
    evidence into uncertainties.

11. When referring to a specific user or account identifier,
    write it as user=<identifier> and copy the identifier
    exactly from the supplied evidence. Do not use this syntax
    for generic phrases about users or accounts.

12. When referring to a specific host, endpoint, device, or
    machine identifier, write it as host=<identifier> and copy
    the identifier exactly from the supplied evidence. Do not
    use this syntax for generic references to hosts or devices.

13. Copy IP addresses exactly as they appear in the supplied
    evidence. Do not alter, shorten, reformat, correct, or
    reconstruct an IP address.

14. Do not describe an IP address as spoofed unless evidence
    specifically supports spoofing.

15. Do not claim successful compromise, privilege escalation,
    lateral movement, or credential compromise unless supplied
    evidence supports it.

EVIDENCE REQUEST RULES:

16. If additional evidence is required, set
    needs_more_evidence to true.

17. When needs_more_evidence is true, use requested_evidence
    to specify what AthenaSec should retrieve.

18. You may request only:
    - authentication_history
    - source_endpoint_context
    - privilege_activity
    - related_security_events

19. Request no more than two evidence types at a time.

20. Do not request evidence that is already present in
    AVAILABLE EVIDENCE RECORDS.

21. For brute-force investigations, authentication_history
    and source_endpoint_context are useful when those facts
    are missing.

22. For privilege escalation or privilege misuse,
    privilege_activity and related_security_events may be
    useful when relevant.

23. If needs_more_evidence is false, requested_evidence must
    be empty.

RESPONSE RULES:

24. Recommended actions are recommendations only. You do not
    have authority to execute security actions.

25. Do not recommend changing credentials solely because failed
    login attempts occurred. Credential reset should be
    conditional on evidence of compromise or organizational
    policy.

26. If the evidence cannot support a reliable classification,
    use "unknown".
"""


class ModelUnavailable(RuntimeError):
    """Ollama could not be reached, timed out, or does not have the model.

    Raised instead of the raw connection error so the API can answer with a clear
    503 rather than a crash. Bad answers from a running model are not this error.
    """


def _invoke(model, messages):
    try:
        return model.invoke(messages)
    except (httpx.ConnectError, httpx.TimeoutException, ConnectionError) as exc:
        raise ModelUnavailable(
            f"The AI model could not be reached at {OLLAMA_BASE_URL}. Is Ollama running?"
        ) from exc
    except ollama.ResponseError as exc:
        if exc.status_code == 404:
            raise ModelUnavailable(
                f"Ollama does not have the model {OLLAMA_MODEL}. "
                f"Run: ollama pull {OLLAMA_MODEL}"
            ) from exc
        raise


def create_analysis_model():
    model = ChatOllama(
        model=OLLAMA_MODEL,
        base_url=OLLAMA_BASE_URL,
        temperature=0,
        reasoning=False,
        keep_alive="30m",
    )

    return model.with_structured_output(
        AlertAnalysis
    )


def analyze_security_event(
    event: str,
) -> AlertAnalysis:
    model = create_analysis_model()

    return _invoke(
        model,
        [
            (
                "system",
                SYSTEM_PROMPT,
            ),
            (
                "human",
                event,
            ),
        ]
    )

RESPONSE_PROPOSAL_SYSTEM_PROMPT = """
You are AthenaSec's response-planning assistant.

You may PROPOSE security response actions.
You do not have authority to approve, execute, or authorize
any response action.

Your output must be a StructuredResponseProposal.

You may propose only these action types:

- block_ip
- lock_account
- capture_telemetry

ACTION RULES:

1. Every target must appear exactly in the supplied alert
   metadata or evidence records.

2. Every action must cite one or more supplied evidence IDs.

3. Never invent an IP address, account, endpoint, host, user,
   device, or evidence ID.

4. block_ip:
   - target_type must be "ip"
   - target must be a grounded IP address
   - duration_minutes is mandatory
   - use temporary containment only
   - duration must be between 1 and 1440 minutes

5. lock_account:
   - target_type must be "account"
   - target must be a grounded account
   - duration_minutes is mandatory
   - duration must be between 1 and 1440 minutes

6. capture_telemetry:
   - target_type must be "endpoint"
   - target must be a grounded endpoint or agent
   - duration_minutes must be null

7. Do not propose create_case, notify_administrator,
   record_response, shell commands, arbitrary scripts,
   firewall commands, operating-system commands, or any
   unsupported action.

8. Incident severity does not determine whether an action is
   safe. A separate deterministic AthenaSec Action Risk Engine
   will evaluate every proposed action.

9. Do not claim that an action is approved, allowed, safe,
   executed, or completed.

10. If no grounded action is appropriate, return an empty
    actions list and explain why in summary.
"""


def create_response_proposal_model():
    model = ChatOllama(
        model=OLLAMA_MODEL,
        base_url=OLLAMA_BASE_URL,
        temperature=0,
        reasoning=False,
        keep_alive="30m",
    )

    return model.with_structured_output(
        StructuredResponseProposal
    )


def evidence_bound_analysis_schema(evidence_ids: Sequence[str]):
    """An LLM schema that only accepts the trusted evidence-record IDs (Daniel, semi-main)."""
    allowed = tuple(sorted(set(evidence_ids)))

    if not allowed:
        raise ValueError("No trusted evidence IDs available")

    for evidence_id in allowed:
        validate_evidence_reference(evidence_id)

    allowed_id = Literal[allowed]

    return create_model(
        "EvidenceBoundAlertAnalysis",
        __base__=AlertAnalysis,
        evidence_refs=(
            list[allowed_id],
            Field(
                min_length=1,
                description="Select exact supplied evidence record IDs only; no extra text.",
            ),
        ),
    )


def analyze_security_event_with_evidence(
    event: str,
    evidence_ids: Sequence[str],
) -> AlertAnalysis:
    """Reject any model output that cites evidence outside this investigation's records."""
    schema = evidence_bound_analysis_schema(evidence_ids)
    model = ChatOllama(
        model=OLLAMA_MODEL,
        base_url=OLLAMA_BASE_URL,
        temperature=0,
        reasoning=False,
        keep_alive="30m",
    ).with_structured_output(schema, method="json_schema")
    analysis = _invoke(model, [("system", SYSTEM_PROMPT), ("human", event)])

    return AlertAnalysis.model_validate(analysis.model_dump())


def propose_security_response(
    context: str,
) -> StructuredResponseProposal:
    model = (
        create_response_proposal_model()
    )

    return _invoke(
        model,
        [
            (
                "system",
                RESPONSE_PROPOSAL_SYSTEM_PROMPT,
            ),
            (
                "human",
                context,
            ),
        ]
    )