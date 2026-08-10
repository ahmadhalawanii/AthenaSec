from app.graph.graph import build_investigation_graph
from app.schemas import SecurityAlertInput


graph = build_investigation_graph()


alert = SecurityAlertInput(
    alert_id="ALT-001",
    source="mock",
    event_text="""
        148 failed SSH login attempts occurred
        against the root account from IP
        192.168.1.45 within five minutes.
    """,
)


result = graph.invoke(
    {
        "alert": alert,
        "status": "received",
    }
)


analysis = result["analysis"]


print("\nATHENASEC INVESTIGATION")
print("=======================")

print(f"Alert: {result['alert'].alert_id}")
print(f"Source: {result['alert'].source}")
print(f"Status: {result['status']}")

print("\nNormalized Event:")
print(result["normalized_event"])


print("\nAI ANALYSIS")
print("-----------")

print(
    f"Classification: "
    f"{analysis.classification}"
)

print(
    f"Confidence: "
    f"{analysis.confidence}"
)

print(
    f"Severity: "
    f"{analysis.severity_assessment}"
)


print("\nSummary:")
print(analysis.summary)


print("\nGrounded Evidence:")

records_by_id = {
    record.evidence_id: record
    for record in result["evidence_records"]
}

for evidence_id in analysis.evidence_refs:
    record = records_by_id[evidence_id]

    print(
        f"[{record.evidence_id}] "
        f"({record.source})"
    )

    print(
        f"  {record.content}"
    )


print("\nUncertainties:")

for uncertainty in analysis.uncertainties:
    print(f"- {uncertainty}")


print("\nInvestigation Steps:")

for step in analysis.recommended_investigation_steps:
    print(f"- {step}")


print("\nRecommended Responses:")

for action in analysis.recommended_response_actions:
    print(f"- {action}")


print(
    "\nNeeds More Evidence:",
    analysis.needs_more_evidence,
)


print("\nRequested Evidence:")

if analysis.requested_evidence:
    for request in analysis.requested_evidence:
        print(f"- {request}")
else:
    print("- None")


print("\nAll Evidence Records:")

for record in result["evidence_records"]:
    print(
        f"[{record.evidence_id}] "
        f"({record.source}) "
        f"{record.content}"
    )


print(
    "\nInvestigation Iterations:",
    result.get(
        "investigation_iteration",
        0,
    ),
)