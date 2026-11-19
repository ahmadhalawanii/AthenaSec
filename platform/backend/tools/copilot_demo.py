"""Security Copilot demo: a local backend with FAKE data and a fake sign-in.

For trying the Copilot chat in a browser, and for nothing else. Every alert, case, approval,
service status and audit event is made up, and anyone who can reach this server is signed in
without a password. It refuses to start if a database is configured, and it listens on
127.0.0.1 only. Never run it on a shared machine or expose it.

Run from platform/backend (Python 3.14, with requirements.txt installed):

    python tools/copilot_demo.py

Then in platform/frontend:

    npm run dev

Open http://localhost:8000/demo/login/analyst (or /demo/login/admin). That sets the fake
session and sends you to the Copilot page on the Vite dev server (http://localhost:5173).

Fixture dates are in March 2026, so the chat's "last 24 hours" clock is pinned to them.
"""

import os
import sys
from datetime import timedelta
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(BACKEND))

if os.getenv("ATHENASEC_DATABASE_URL"):
    sys.exit("Refusing to start: ATHENASEC_DATABASE_URL is set. This demo is for fake data only.")

import uvicorn  # noqa: E402
from fastapi.responses import RedirectResponse  # noqa: E402

import app.chat.service as chat_service  # noqa: E402
from app.main import create_app  # noqa: E402
from app.services.audit.audit_store import InMemoryAuditStore  # noqa: E402
from app.services.audit.operator_audit_store import InMemoryOperatorAuditStore  # noqa: E402
from app.services.auth.web_auth import SESSION_COOKIE_NAME, BrowserPrincipal  # noqa: E402
from app.services.health.health_probes import CATALOG, ProbeResult  # noqa: E402
from tests.test_cases_endpoints import BASE, Harness, UnusedGraph  # noqa: E402
from tests.test_chat_api import seed_approval  # noqa: E402

PORT = int(os.getenv("COPILOT_DEMO_PORT", "8000"))
FRONTEND = os.getenv("COPILOT_DEMO_FRONTEND", "http://localhost:5173")

# The fixtures are dated March 2026: pin the chat's clock so "last 24 hours" finds them
chat_service.utc_now = lambda: BASE + timedelta(hours=1)

SESSIONS = {"analyst": "demo-analyst", "admin": "demo-admin"}
ROLES = {"demo-analyst": "Analyst", "demo-admin": "Administrator"}


class DemoSessions:
    """Accepts exactly two fixed cookies. Not an authentication system."""

    def resolve_session(self, session):
        role = ROLES.get(session)

        if role is None:
            return None

        return BrowserPrincipal(
            f"demo-{role.lower()}", f"{role.lower()}@example.test", role, role,
            True, role == "Administrator", "demo-csrf",
        )


harness = Harness()
seed_approval(harness)

audit = InMemoryOperatorAuditStore()
for action in ("user.created", "policy.changed"):
    audit.append_event(actor_id="demo-admin", actor_role="Administrator", category="Users",
                       action=action, target="u-9", result="Success")

probes = {d.check_key: (lambda: ProbeResult("up", 5, None, None)) for d in CATALOG if d.probed}
probes["ollama"] = lambda: ProbeResult("degraded", 900, "Slow.")

app = create_app(
    investigation_graph=UnusedGraph(),
    investigation_store=harness.investigation_store,
    audit_store=InMemoryAuditStore(),
    incident_response_store=harness.response_store,
    case_workflow_store=harness.workflow_store,
    browser_auth_store=DemoSessions(),
    operator_audit_store=audit,
    health_probes=probes,
    autonomous_response_enabled=False,
)


@app.get("/demo/login/{who}")
def demo_login(who: str):
    if who not in SESSIONS:
        return RedirectResponse("/demo/login/analyst")

    response = RedirectResponse(f"{FRONTEND}/app/copilot")
    # Cookies are shared across ports on localhost, so the Vite site (5173) receives this one
    response.set_cookie(SESSION_COOKIE_NAME, SESSIONS[who], httponly=True, samesite="lax")
    return response


if __name__ == "__main__":
    print(f"\nCopilot demo (FAKE data, no real sign-in) on http://127.0.0.1:{PORT}", flush=True)
    print(f"  Analyst:       http://127.0.0.1:{PORT}/demo/login/analyst", flush=True)
    print(f"  Administrator: http://127.0.0.1:{PORT}/demo/login/admin", flush=True)
    print("  Start the website with `npm run dev` in platform/frontend first.\n", flush=True)
    uvicorn.run(app, host="127.0.0.1", port=PORT, log_level="warning")
