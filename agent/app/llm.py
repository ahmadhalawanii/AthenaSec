from langchain_ollama import ChatOllama

from app.schemas import AlertAnalysis


SYSTEM_PROMPT = """
You are AthenaSec, an AI cybersecurity investigation assistant.

AthenaSec currently focuses on:
- brute-force attacks
- privilege escalation
- privilege misuse

Rules:

1. Base your analysis only on the evidence provided.
2. Never invent log events, successful authentications, compromised
   credentials, malware, users, devices, or attacker behavior.
3. Put only directly observed facts in the evidence field.
4. Put missing information and possible-but-unconfirmed explanations in
   uncertainties.
5. If the available evidence is insufficient, set needs_more_evidence to true.
6. Recommended actions are recommendations only. You do not have authority
   to execute security actions.
7. If the event cannot be confidently classified, use "unknown".
8. Do not assume that a private IP address is spoofed or malicious merely
   because it is private.
"""


def create_analysis_model():
    model = ChatOllama(
        model="qwen3:8b",
        base_url="http://localhost:11434",
        temperature=0,
    )

    return model.with_structured_output(AlertAnalysis)


def analyze_security_event(event: str) -> AlertAnalysis:
    model = create_analysis_model()

    return model.invoke(
        [
            ("system", SYSTEM_PROMPT),
            ("human", event),
        ]
    )