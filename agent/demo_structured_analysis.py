from app.llm import analyze_security_event


event = """
148 failed SSH login attempts occurred against the root account
from IP address 192.168.1.45 within five minutes.
"""


analysis = analyze_security_event(event)


print("\nATHENASEC ANALYSIS")
print("==================")

print(f"Classification: {analysis.classification}")
print(f"Confidence: {analysis.confidence}")
print(f"Severity: {analysis.severity_assessment}")

print("\nSummary:")
print(analysis.summary)

print("\nObserved Evidence:")
for item in analysis.evidence:
    print(f"- {item}")

print("\nUncertainties:")
for item in analysis.uncertainties:
    print(f"- {item}")

print("\nInvestigation Steps:")
for item in analysis.recommended_investigation_steps:
    print(f"- {item}")

print("\nRecommended Responses:")
for item in analysis.recommended_response_actions:
    print(f"- {item}")

print(
    f"\nNeeds More Evidence: "
    f"{analysis.needs_more_evidence}"
)