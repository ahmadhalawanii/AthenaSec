import traceback

import app.main as m
from fastapi.testclient import TestClient

orig = m.HTTPException


class Loud(orig):
    def __init__(self, *a, **k):
        traceback.print_exc()
        super().__init__(*a, **k)


m.HTTPException = Loud

import app.graph.nodes.propose_response as pr

_orig_validate = pr.validate_response_proposal


def show(*a, **k):
    print("PROPOSAL", repr(k.get("proposal")))
    return _orig_validate(*a, **k)


pr.validate_response_proposal = show

client = TestClient(m.create_app())
r = client.post(
    "/api/v1/analyze",
    json={
        "alert_id": "ALT-DIAG-2",
        "source": "manual",
        "event_text": "148 failed SSH login attempts against root.",
        "metadata": {
            "source_ip": "203.0.113.50",
            "target_user": "root",
            "failed_attempts": 148,
            "privileged_target": True,
        },
    },
)
print("STATUS", r.status_code)
