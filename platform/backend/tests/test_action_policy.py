"""The administrator's action policy: catalogue rules, storage, enforcement and the API.

The action policy is the whitelist and blacklist of agent actions. Unlike the target policy
(/api/v1/policies), the agent enforces it: blacklisted or unlisted actions are denied and
approval-mode actions (block_ip, isolate_host) always wait for a person.
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from app.main import create_app
from app.schemas import ActionPolicyContent
from app.services.audit.audit_store import InMemoryAuditStore
from app.services.audit.operator_audit_store import InMemoryOperatorAuditStore
from app.services.auth.operator_identity import InMemoryOperatorIdentityStore
from app.services.auth.web_auth import SESSION_COOKIE_NAME, BrowserPrincipal
from app.services.investigations.investigation_store import InMemoryInvestigationStore
from app.services.policy.action_catalogue import (
    TIER1_ACTIONS,
    TIER3_ACTIONS,
    default_action_policy,
    target_is_protected,
    validate_action_policy,
)
from app.services.policy.action_policy_engine import evaluate_action_policy
from app.services.policy.action_policy_store import (
    ActionPolicyVersionConflict,
    InMemoryActionPolicyStore,
    SQLiteActionPolicyStore,
    current_or_default,
)
from app.services.storage.incident_response_store import InMemoryIncidentResponseStore
from tests.test_action_policy_engine import DECIDED_AT, make_action, make_action_risk

CSRF = {"X-AthenaSec-CSRF": "csrf-admin"}


def policy(**changes) -> ActionPolicyContent:
    data = default_action_policy().model_dump()
    data.update({key: [item if isinstance(item, dict) else item.model_dump() for item in value]
                 for key, value in changes.items()})
    return ActionPolicyContent.model_validate(data)


def problems_for(data: dict) -> list[str]:
    return validate_action_policy(ActionPolicyContent.model_validate(data))


def entry(data, action):
    return next(item for item in data["whitelist"] if item["action"] == action)


# ---- catalogue rules -------------------------------------------------------

def test_default_policy_is_valid_and_matches_the_supervisor_tiers():
    default = default_action_policy()

    assert validate_action_policy(default) == []
    modes = {item.action: item.mode for item in default.whitelist}
    assert all(modes[name] == "automatic" for name in TIER1_ACTIONS)
    assert modes["block_ip"] == "approval" and modes["isolate_host"] == "approval"
    assert {item.action for item in default.blacklist} == set(TIER3_ACTIONS)


def test_prohibited_actions_cannot_be_whitelisted_or_removed():
    data = default_action_policy().model_dump()
    data["blacklist"] = [b for b in data["blacklist"] if b["action"] != "delete_logs"]
    data["whitelist"].append({"action": "delete_logs", "mode": "automatic", "limits": None})

    problems = problems_for(data)

    assert "delete_logs is prohibited and cannot be whitelisted." in problems
    assert "delete_logs is prohibited and must stay on the blacklist." in problems


def test_approval_actions_cannot_be_automatic_or_exceed_their_caps():
    data = default_action_policy().model_dump()
    block = entry(data, "block_ip")
    block["mode"] = "automatic"
    block["limits"].update(max_minutes=2000, window_minutes=60, min_risk=10)
    isolate = entry(data, "isolate_host")
    isolate["limits"]["approver"] = "soc_analyst"

    problems = problems_for(data)

    assert "block_ip always needs a person's approval; it cannot be automatic." in problems
    assert "block_ip may last at most 1440 minutes." in problems
    assert "block_ip: the time to decide may be at most 15 minutes." in problems
    assert "block_ip: the minimum risk may not be lower than 70." in problems
    assert "isolate_host must be approved by a soc_lead or higher." in problems


def test_unknown_duplicate_and_conflicting_entries_are_rejected():
    data = default_action_policy().model_dump()
    data["whitelist"].append({"action": "launch_missiles", "mode": "automatic", "limits": None})
    data["whitelist"].append({"action": "monitor", "mode": "automatic", "limits": None})
    data["blacklist"].append({"action": "create_ticket", "required": False})

    problems = problems_for(data)

    assert "launch_missiles is not an action in the catalogue." in problems
    assert "monitor is listed more than once on the whitelist." in problems
    assert "create_ticket cannot be on both the whitelist and the blacklist." in problems


def test_required_internal_ranges_stay_and_targets_must_be_well_formed():
    data = default_action_policy().model_dump()
    data["never_block"] = [t for t in data["never_block"] if t["value"] != "10.0.0.0/8"]
    data["never_isolate"] = [{"value": "not a host!", "label": "", "required": False}]

    problems = problems_for(data)

    assert "10.0.0.0/8 is a required protected range and cannot be removed." in problems
    assert "not a host! on never_isolate is not an IP address, CIDR range or host name." in problems


def test_protected_targets_match_ranges_and_host_names():
    listed = default_action_policy().never_block

    assert target_is_protected("10.4.5.6", listed)
    assert not target_is_protected("203.0.113.10", listed)
    assert target_is_protected("DC01.corp.local.", policy(never_block=[
        {"value": "dc01.corp.local", "label": "DC", "required": False}]).never_block)


# ---- storage ---------------------------------------------------------------

@pytest.fixture(params=["memory", "sqlite"])
def store(request, tmp_path):
    if request.param == "memory":
        return InMemoryActionPolicyStore()
    return SQLiteActionPolicyStore(tmp_path / "action_policy.db")


def test_store_starts_on_the_default_and_appends_versions(store):
    assert store.get_current() is None
    assert current_or_default(store).is_default is True
    assert current_or_default(store).version == 0

    content = policy(never_isolate=[{"value": "dc01", "label": "DC", "required": False}])
    first = store.append_version(base_version=0, content=content, reason="first",
                                 created_by="admin-1",
                                 created_at=datetime(2026, 10, 1, tzinfo=timezone.utc))
    second = store.append_version(base_version=1, content=default_action_policy(),
                                  reason="second", created_by="admin-2")

    assert (first.version, second.version) == (1, 2)
    assert store.get_current().version == 2 and store.get_current().is_default is False
    assert [v.version for v in store.list_versions()] == [2, 1]
    assert store.list_versions()[1].never_isolate[0].value == "dc01"
    assert store.list_versions()[1].created_by == "admin-1"


def test_store_rejects_a_stale_base_version(store):
    store.append_version(base_version=0, content=default_action_policy(), reason="a",
                         created_by="admin-1")

    with pytest.raises(ActionPolicyVersionConflict) as caught:
        store.append_version(base_version=0, content=default_action_policy(), reason="b",
                             created_by="admin-2")

    assert caught.value.current_version == 1
    assert len(store.list_versions()) == 1


def test_sqlite_rows_cannot_be_changed(tmp_path):
    import sqlite3

    sqlite_store = SQLiteActionPolicyStore(tmp_path / "p.db")
    sqlite_store.append_version(base_version=0, content=default_action_policy(), reason="a",
                                created_by="admin-1")
    connection = sqlite3.connect(tmp_path / "p.db")

    with pytest.raises(sqlite3.DatabaseError, match="append-only"):
        connection.execute("DELETE FROM action_policy_versions")


# ---- enforcement -----------------------------------------------------------

def decide(action=None, *, admin=None, incident_risk=95, score=10):
    return evaluate_action_policy(
        proposed_action=action or make_action(),
        action_risk=make_action_risk(score=score),
        decided_at=DECIDED_AT,
        admin_policy=admin if admin is not None else default_action_policy(),
        incident_risk=incident_risk,
    )


def test_block_ip_always_needs_approval_under_the_admin_policy():
    # Without the admin policy the same low-risk block would be POL-ACTION-AUTO
    decision = decide()

    assert decision.outcome == "APPROVAL_REQUIRED"
    assert decision.policy_id == "POL-ADMIN-APPROVAL"


def test_blacklisted_and_unlisted_actions_are_denied():
    blocked = policy(
        whitelist=[w for w in default_action_policy().whitelist if w.action != "block_ip"],
        blacklist=[*default_action_policy().blacklist, {"action": "block_ip", "required": False}],
    )
    unlisted = policy(
        whitelist=[w for w in default_action_policy().whitelist if w.action != "block_ip"],
    )

    assert decide(admin=blocked).policy_id == "POL-ADMIN-BLACKLIST"
    assert decide(admin=blocked).outcome == "NOT_ALLOWED"
    assert decide(admin=unlisted).policy_id == "POL-ADMIN-NOT-WHITELISTED"
    assert decide(admin=unlisted).outcome == "NOT_ALLOWED"


def test_block_ip_on_a_never_block_target_is_denied():
    decision = decide(make_action(target="192.168.1.20"))

    assert decision.outcome == "NOT_ALLOWED"
    assert decision.policy_id in {"POL-ADMIN-PROTECTED-TARGET", "POL-ACTION-PROTECTED-TARGET"}


def test_block_longer_than_the_admin_limit_is_denied():
    shorter = default_action_policy().model_dump()
    entry(shorter, "block_ip")["limits"]["max_minutes"] = 60

    decision = decide(make_action(duration_minutes=120),
                      admin=ActionPolicyContent.model_validate(shorter))

    assert decision.outcome == "NOT_ALLOWED"
    assert decision.policy_id == "POL-ADMIN-LIMIT"


def test_block_below_the_minimum_incident_risk_is_not_proposed_for_approval():
    decision = decide(incident_risk=40)

    assert decision.policy_id == "POL-ADMIN-BELOW-MIN-RISK"
    assert decision.outcome != "APPROVAL_REQUIRED"


def test_automatic_actions_still_pass_the_deterministic_checks():
    decision = decide(make_action(action_type="capture_telemetry", target_type="endpoint",
                                  target="007", duration_minutes=None, reversible=False),
                      score=20)

    assert decision.outcome == "AUTO_ALLOWED"


# ---- API -------------------------------------------------------------------

class UnusedGraph:
    def invoke(self, state):
        raise AssertionError("Graph must not be used by policy tests.")


class SessionStore:
    principals = {
        "admin": BrowserPrincipal("admin-1", "a@example.test", "Admin", "Administrator",
                                  True, True, "csrf-admin"),
        "analyst": BrowserPrincipal("analyst-1", "n@example.test", "Analyst", "Analyst",
                                    True, False, "csrf-analyst"),
    }

    def resolve_session(self, session):
        return self.principals.get(session)


class Harness:
    def __init__(self, auth="admin"):
        self.store = InMemoryActionPolicyStore()
        self.audit = InMemoryOperatorAuditStore()
        app = create_app(
            investigation_graph=UnusedGraph(),
            investigation_store=InMemoryInvestigationStore(),
            audit_store=InMemoryAuditStore(),
            incident_response_store=InMemoryIncidentResponseStore(),
            action_policy_store=self.store,
            operator_audit_store=self.audit,
            browser_auth_store=SessionStore(),
            operator_identity_store=InMemoryOperatorIdentityStore(),
            autonomous_response_enabled=False,
        )
        self.client = TestClient(app)
        self.client.cookies.set(SESSION_COOKIE_NAME, auth)

    def put(self, content=None, *, base=0, reason="tighten", headers=CSRF):
        body = (content or default_action_policy()).model_dump()
        body.update(base_version=base, reason=reason)
        return self.client.put("/api/v1/policies/actions", json=body, headers=headers)


def test_get_returns_the_default_before_any_save():
    response = Harness("analyst").client.get("/api/v1/policies/actions")

    assert response.status_code == 200
    assert response.json()["version"] == 0 and response.json()["is_default"] is True
    assert entry(response.json(), "block_ip")["mode"] == "approval"


def test_admin_save_creates_a_version_the_agent_reads_and_audits_it():
    h = Harness()
    content = policy(never_isolate=[{"value": "dc01.corp.local", "label": "DC",
                                     "required": False}])

    saved = h.put(content)

    assert saved.status_code == 200
    assert saved.json()["version"] == 1 and saved.json()["created_by"] == "admin-1"
    assert h.store.get_current().never_isolate[0].value == "dc01.corp.local"
    assert h.client.get("/api/v1/policies/actions").json()["version"] == 1
    versions = h.client.get("/api/v1/policies/actions/versions").json()
    assert versions["total"] == 1 and versions["items"][0]["reason"] == "tighten"
    events = h.audit.list_events()
    assert events[-1].event_type == "action_policy_updated"
    assert events[-1].result == "Success"


def test_invalid_policy_is_rejected_with_reasons_and_not_stored():
    h = Harness()
    data = default_action_policy().model_dump()
    entry(data, "block_ip")["mode"] = "automatic"

    response = h.put(ActionPolicyContent.model_validate(data))

    assert response.status_code == 422
    assert "block_ip always needs a person's approval; it cannot be automatic." in (
        response.json()["detail"])
    assert h.store.get_current() is None


def test_stale_save_is_a_409():
    h = Harness()
    h.put()

    response = h.put(base=0)

    assert response.status_code == 409
    assert "latest version is 1" in response.json()["detail"]


def test_only_an_admin_with_csrf_can_save():
    assert Harness("analyst").put(headers={"X-AthenaSec-CSRF": "csrf-analyst"}).status_code == 403
    assert Harness().put(headers={}).status_code == 403
    assert Harness("analyst").client.get("/api/v1/policies/actions/versions").status_code == 403


# ---- the investigation graph reads the policy -------------------------------

def run_graph(provider, duration_minutes=30):
    from tests import test_action_policy_pipeline as pipeline
    from app.graph.graph import build_investigation_graph

    graph = build_investigation_graph(
        analyzer=lambda context: pipeline.make_analysis(),
        response_proposer=lambda context: pipeline.make_proposal(duration_minutes),
        action_policy_clock=lambda: pipeline.FIXED_TIME,
        action_policy_provider=provider,
    )
    return graph.invoke({
        "incident_id": "INC-001", "investigation_id": "INV-001", "status": "received",
        "alert": pipeline.SecurityAlertInput(
            alert_id="ALT-1", source="manual",
            event_text="Failed SSH authentication attempts from 203.0.113.10.",
            metadata={"source_ip": "203.0.113.10", "failed_attempts": 20},
        ),
    })


def test_graph_reads_the_policy_once_and_holds_back_a_block_below_its_minimum_risk():
    # This incident scores 55, under block_ip's minimum of 70: the agent does not even
    # ask for approval, and the old automatic short block no longer happens.
    calls = []

    def provider():
        calls.append(1)
        return default_action_policy()

    result = run_graph(provider)
    decision = result["action_policy_decisions"][0]

    assert len(calls) == 1
    assert result["risk_assessment"].score == 55
    assert decision.policy_id == "POL-ADMIN-BELOW-MIN-RISK"
    assert decision.outcome == "NOT_ALLOWED"
    assert result["approval_requests"] == []


def test_graph_sends_a_block_for_approval_with_the_admin_decision_window():
    from datetime import timedelta

    data = default_action_policy().model_dump()
    entry(data, "block_ip")["limits"].update(min_risk=50, window_minutes=10)

    result = run_graph(lambda: ActionPolicyContent.model_validate(data))
    decision = result["action_policy_decisions"][0]
    approval = result["approval_requests"][0]

    assert decision.policy_id == "POL-ADMIN-APPROVAL"
    assert decision.outcome == "APPROVAL_REQUIRED"
    assert approval.status == "PENDING"
    assert approval.expires_at - approval.requested_at == timedelta(minutes=10)


def test_graph_denies_block_ip_once_the_admin_blacklists_it():
    blocked = policy(
        whitelist=[w for w in default_action_policy().whitelist if w.action != "block_ip"],
        blacklist=[*default_action_policy().blacklist, {"action": "block_ip", "required": False}],
    )

    result = run_graph(lambda: blocked)

    assert result["action_policy_decisions"][0].policy_id == "POL-ADMIN-BLACKLIST"
    assert result["approval_requests"] == []
