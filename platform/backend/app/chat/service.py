"""Security Copilot, Batch 1: a read-only assistant over stored AthenaSec records.

Every fact in an answer comes from a source callable (alerts, cases, runtime status), never
from a model. A phraser (Qwen) may reword the answer afterwards; it cannot add records, and
the chat has no path to propose, approve or execute a response.
"""

import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

WINDOW = timedelta(hours=24)
MAX_REFS = 5

ACTION_WORDS = re.compile(
    r"\b(isolate|quarantine|block|unblock|ban|approve|reject|deny|execute|disable|"
    r"shut\s?down|contain|kill)\b",
    re.IGNORECASE,
)
ALERT_ID = re.compile(r"\b(?:ALT|ALERT)-[A-Za-z0-9_-]+", re.IGNORECASE)
ALERT_WORD_ID = re.compile(r"\balert\s+#?([A-Za-z0-9._:-]*\d[A-Za-z0-9._:-]*)", re.IGNORECASE)
CASE_ID = re.compile(r"\bCASE-[A-Za-z0-9_-]+", re.IGNORECASE)
APPROVAL_ID = re.compile(r"\bAPR-[A-Za-z0-9_-]+", re.IGNORECASE)
AUDIT = re.compile(r"\baudit\b|activity log", re.IGNORECASE)
HEALTH = re.compile(
    r"health|monitoring|working|services?\b|\bdown\b|\bonline\b|connected|wazuh|misp|ollama|cortex",
    re.IGNORECASE,
)
APPROVALS = re.compile(r"approvals?\b|waiting|pending", re.IGNORECASE)
DEFINITION = re.compile(r"\b(what\s+(is|does|are)|mean|meaning|define|explain)\b", re.IGNORECASE)
RUNTIME = re.compile(
    r"autonomous|response mode|shadow|supervised|execution enabled|kill switch|runtime",
    re.IGNORECASE,
)
CASES = re.compile(r"\bcases?\b", re.IGNORECASE)
SNAPSHOT = re.compile(
    r"urgent|problem|happening|today|okay|\bsafe\b|status|anything|what happened|summary|"
    r"attack|incident|alerts?\b|worry|important",
    re.IGNORECASE,
)

GLOSSARY = {
    "brute force": (
        "A brute-force attempt is when someone repeatedly tries passwords or other "
        "credentials to get in. It does not automatically mean a login succeeded."
    ),
    "privilege escalation": (
        "Privilege escalation is when an account or process gains more access than it was "
        "given, for example a normal user acting as an administrator."
    ),
    "privilege misuse": (
        "Privilege misuse is when an account uses access it legitimately has in a way that "
        "looks unusual or unsafe."
    ),
    "benign": "Benign means the activity looks harmless after review. It is a judgement, not proof.",
    "mitre": (
        "MITRE ATT&CK is a public reference list of attacker techniques. A technique ID such "
        "as T1110 names a known technique; it does not prove an attack happened."
    ),
    "misp": "MISP is a threat-intelligence sharing platform. A match is context, not proof of an attack.",
    "risk score": (
        "The risk score is a 0-100 number AthenaSec calculates from recorded factors. It is "
        "separate from the detection model's classification."
    ),
    "shadow": "SHADOW mode investigates and records what AthenaSec would do, without acting.",
    "supervised": "SUPERVISED mode needs a person to approve risky response actions.",
    "autonomous": "AUTONOMOUS mode lets AthenaSec run actions its policy allows, within its safeguards.",
    "alert": "An alert is a single detection from the monitoring system, such as one rule firing.",
    "case": "A case is a tracked record an analyst works on when something needs follow-up.",
}

CLASS_PLAIN = {
    "brute_force": "repeated sign-in attempts",
    "privilege_escalation": "an attempt to gain more access than allowed",
    "privilege_misuse": "unusual use of existing access",
    "benign": "activity that looks harmless",
    "unknown": "activity AthenaSec could not classify",
}
CLASS_CAUTION = {
    "brute_force": "A brute-force attempt does not mean a login succeeded.",
    "privilege_escalation": "An escalation attempt does not mean it worked; check what was recorded afterwards.",
    "privilege_misuse": "Unusual use of access is not proof of malicious intent.",
    "benign": "A benign label is a judgement from the evidence available, not a guarantee.",
    "unknown": "AthenaSec could not classify this, so treat it as unconfirmed.",
}

FOLLOWUPS = [
    "Are there any urgent problems?",
    "Show my unresolved cases",
    "Is autonomous response enabled?",
    "What does brute force mean?",
]


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class ChatSources:
    """Read-only access to AthenaSec records. Each callable reads; none writes."""

    list_alerts: Callable[[datetime], list]
    get_alert: Callable[[str], Any]
    list_cases: Callable[[], list]
    get_case: Callable[[str], Any]
    runtime_status: Callable[[], dict]
    list_approvals: Callable[[str], list]
    get_approval: Callable[[str], Any]
    get_action: Callable[[str], Any]
    get_policy_decision: Callable[[str], Any]
    health: Callable[[], Any]
    recent_audit: Callable[[int], list]


def _ref(kind: str, record_id: str) -> dict[str, str]:
    return {"type": kind, "id": record_id, "href": f"/api/v1/{kind}s/{record_id}"}


def _answer(text, *, kind, status, tools, refs=None, limitations=None, technical=None,
            followups=None):
    return {
        "answer": text,
        "answer_type": kind,
        "data_status": status,
        "checked_at": utc_now().isoformat(),
        "evidence_refs": refs or [],
        "known_limitations": limitations or [],
        "suggested_followups": followups or [],
        "technical": technical,
        "tools": tools,
    }


def route(text: str) -> tuple[str, str | None]:
    if ACTION_WORDS.search(text):
        return "refuse_action", None
    if match := ALERT_ID.search(text):
        return "alert", match.group(0).upper()
    if match := CASE_ID.search(text):
        return "case", match.group(0).upper()
    if match := APPROVAL_ID.search(text):
        return "approval", match.group(0).upper()
    if match := ALERT_WORD_ID.search(text):
        return "alert", match.group(1)
    if DEFINITION.search(text):
        lowered = text.lower()
        for term in GLOSSARY:
            if term in lowered:
                return "glossary", term
    if RUNTIME.search(text):
        return "runtime", None
    if AUDIT.search(text):
        return "audit", None
    if HEALTH.search(text):
        return "health", None
    if CASES.search(text):
        return "case_list", None
    if APPROVALS.search(text):
        return "approvals", None
    if SNAPSHOT.search(text):
        return "snapshot", None
    return "clarify", None


def respond(text: str, sources: ChatSources, *, presentation: str = "simple",
            role: str | None = None) -> dict:
    intent, arg = route(text)
    handler = {
        "refuse_action": lambda: _refuse(),
        "alert": lambda: _alert(arg, sources, presentation),
        "case": lambda: _case(arg, sources, presentation),
        "approval": lambda: _approval(arg, sources, presentation),
        "approvals": lambda: _approvals(sources, presentation),
        "health": lambda: _health(sources, presentation),
        "audit": lambda: _audit(sources, presentation, role),
        "glossary": lambda: _glossary(arg),
        "runtime": lambda: _runtime(sources, presentation),
        "case_list": lambda: _case_list(sources),
        "snapshot": lambda: _snapshot(sources, presentation),
        "clarify": lambda: _clarify(),
    }[intent]
    return handler()


def _refuse():
    return _answer(
        "I cannot block, isolate, approve or run anything from chat. I can only read and "
        "explain what AthenaSec has recorded. To review or decide a proposed response, use "
        "the Approvals page, where an authorised person confirms the exact action.",
        kind="unable_to_verify", status="stored", tools=[],
        followups=["What responses are waiting for approval?", *FOLLOWUPS[:2]],
    )


def _clarify():
    return _answer(
        "I am not sure what you are asking. I can summarise recent alerts, explain a "
        "specific alert or case by its ID, list open cases, or check the response mode.",
        kind="unable_to_verify", status="stored", tools=[], followups=FOLLOWUPS,
    )


def _slug(term: str) -> str:
    return term.replace(" ", "-")


def knowledge_source(source_id: str) -> dict | None:
    """One glossary entry, so an explanation can be opened and checked."""
    term = source_id.replace("-", " ")

    if term not in GLOSSARY:
        return None

    return {"source_id": source_id, "title": term.title(), "text": GLOSSARY[term]}


def _glossary(term):
    return _answer(
        GLOSSARY[term], kind="knowledge", status="stored", tools=["glossary"],
        refs=[{"type": "knowledge", "id": _slug(term),
               "href": f"/api/v1/chat/knowledge/sources/{_slug(term)}"}],
        followups=["Are there any urgent problems?"],
    )


def _still_available(sources) -> str:
    """After one source fails, say which others still answer, from a real check."""
    working = ["security terms"]

    for name, read in (("cases", sources.list_cases), ("response mode", sources.runtime_status)):
        try:
            read()
            working.append(name)
        except Exception:
            pass

    return "These are still available: " + ", ".join(working) + "."


def _runtime(sources, presentation):
    try:
        status = sources.runtime_status()
    except Exception:
        return _answer(
            "I could not confirm the current response settings because the runtime status "
            "is unavailable. I will not guess.",
            kind="action_status", status="unavailable", tools=["runtime_status"],
            limitations=["Runtime status could not be read."],
        )
    mode = status.get("response_mode", "unknown")
    effective = status.get("effective_execution_enabled")
    if presentation == "technical":
        keys = ("response_mode", "autonomous_response_enabled", "operator_execution_enabled",
                "effective_execution_enabled")
        text = "; ".join(f"{key}={status.get(key)}" for key in keys)
    else:
        text = (
            f"The response mode is {mode}. "
            + ("Automatic response actions can run right now."
               if effective else "Automatic response actions are not running right now.")
        )
    return _answer(
        text, kind="action_status", status="live", tools=["runtime_status"],
        technical={"runtime": {k: v for k, v in status.items() if not isinstance(v, (dict, list))}},
        followups=["What does SHADOW mean?"],
    )


def _snapshot(sources, presentation):
    since = utc_now() - WINDOW
    try:
        alerts = list(sources.list_alerts(since))
    except Exception:
        return _answer(
            "I could not confirm current alerts because the alert records are unavailable "
            "right now. I will not guess. Please check again shortly or ask an analyst.",
            kind="operational", status="unavailable", tools=["soc_snapshot"],
            limitations=["Alert records could not be read.", _still_available(sources)],
            followups=FOLLOWUPS,
        )
    caveat = (
        "I cannot confirm the whole environment is safe from these records alone; "
        "they show only what AthenaSec has detected."
    )
    if not alerts:
        return _answer(
            f"I found no alerts in the last 24 hours. {caveat}",
            kind="operational", status="stored", tools=["soc_snapshot"],
            limitations=["No alerts in the window does not prove nothing happened."],
            followups=FOLLOWUPS,
        )
    ranked = sorted(alerts, key=lambda a: a.risk_assessment.score, reverse=True)
    kinds: dict[str, int] = {}
    for alert in alerts:
        kinds[alert.classification] = kinds.get(alert.classification, 0) + 1
    top = ranked[0]
    if presentation == "technical":
        by_class = ", ".join(f"{label}={count}" for label, count in kinds.items())
        text = (
            f"Window: last 24h (since {since.isoformat()}). {len(alerts)} alerts. "
            f"By class: {by_class}. Highest: {top.alert_id} "
            f"risk {top.risk_assessment.score}/100 ({top.risk_assessment.band}). {caveat}"
        )
    else:
        breakdown = ", ".join(
            f"{count} of {CLASS_PLAIN.get(label, label)}" for label, count in kinds.items()
        )
        text = (
            f"In the last 24 hours AthenaSec recorded {len(alerts)} alerts: {breakdown}. "
            f"The most serious is {top.alert_id}, rated {top.risk_assessment.band} risk. {caveat}"
        )
    return _answer(
        text, kind="operational", status="stored", tools=["soc_snapshot"],
        refs=[_ref("alert", a.alert_id) for a in ranked[:MAX_REFS]],
        followups=[f"Explain alert {top.alert_id}", "Show my unresolved cases"],
    )


def _alert(alert_id, sources, presentation):
    try:
        found = sources.get_alert(alert_id)
    except Exception:
        return _answer(
            f"I could not look up {alert_id} because the alert records are unavailable. "
            "I will not guess.",
            kind="operational", status="unavailable", tools=["alert_lookup"],
            limitations=["Alert records could not be read.", _still_available(sources)],
        )
    if found is None:
        return _answer(
            f"Alert {alert_id} was not found, so I have nothing to explain. Check the ID, "
            "or ask for recent alerts.",
            kind="operational", status="stored", tools=["alert_lookup"], followups=FOLLOWUPS,
        )
    label = found.analysis.classification
    risk = found.risk_assessment
    meta = found.alert_metadata or {}
    ml = found.ml_prediction
    if presentation == "technical":
        fields = [
            f"{found.alert_id}", f"classification: {label}",
            f"risk {risk.score}/100 ({risk.band})", f"status: {found.status}",
        ]
        if ml is not None:
            fields.append(f"ML: {ml.classification} {round(ml.confidence * 100)}%")
        for name, key in (("source_ip", "source_ip"), ("endpoint", "agent_name")):
            if meta.get(key):
                fields.append(f"{name}: {meta[key]}")
        if meta.get("mitre_ids"):
            fields.append("MITRE: " + ", ".join(meta["mitre_ids"]))
        parts = [" | ".join(fields) + ".", CLASS_CAUTION.get(label, "")]
    else:
        parts = [
            f"{found.alert_id} looks like {CLASS_PLAIN.get(label, label)}.",
            CLASS_CAUTION.get(label, ""),
            f"AthenaSec rates it {risk.score}/100 ({risk.band} risk); the status is {found.status}.",
        ]
        if ml is not None:
            parts.append(
                f"The detection model read it as {CLASS_PLAIN.get(ml.classification, ml.classification)} "
                f"with {round(ml.confidence * 100)}% confidence; this is separate from the risk score."
            )
    if found.analysis.uncertainties:
        parts.append("Not yet known: " + "; ".join(found.analysis.uncertainties) + ".")
    technical = None
    if presentation == "technical":
        technical = {
            "alert_id": found.alert_id, "incident_id": found.incident_id,
            "classification": label, "risk_score": risk.score, "risk_band": risk.band,
            "ml_prediction": (
                found.ml_prediction.model_dump(mode="json") if found.ml_prediction else None),
            "status": found.status, "source_ip": meta.get("source_ip"),
            "endpoint": meta.get("agent_name"), "mitre_ids": meta.get("mitre_ids", []),
        }
    return _answer(
        " ".join(p for p in parts if p), kind="operational", status="stored",
        tools=["alert_lookup"], refs=[_ref("alert", found.alert_id)], technical=technical,
        followups=["Show my unresolved cases", "What does MITRE mean?"],
    )


def _case_line(case):
    owner = case.assigned_analyst or "unassigned"
    return f"{case.case_id} ({case.status}, {owner}): {case.reason}"


def _case(case_id, sources, presentation):
    try:
        case = sources.get_case(case_id)
    except Exception:
        return _answer(
            f"I could not look up {case_id} because case records are unavailable.",
            kind="operational", status="unavailable", tools=["case_lookup"],
            limitations=["Case records could not be read."],
        )
    if case is None:
        return _answer(
            f"Case {case_id} was not found.", kind="operational", status="stored",
            tools=["case_lookup"], followups=FOLLOWUPS,
        )
    if presentation == "technical":
        fields = [case.case_id, f"status: {case.status}",
                  f"assigned: {case.assigned_analyst or 'none'}",
                  f"incident: {case.incident_id}"]
        for name, value in (("alert", case.alert_id), ("classification", case.classification),
                            ("source_ip", case.source_ip)):
            if value:
                fields.append(f"{name}: {value}")
        if case.risk_score is not None:
            fields.append(f"risk {case.risk_score}/100 ({case.risk_band})")
        text = " | ".join(fields) + f". Reason: {case.reason}"
    else:
        owner = f"assigned to {case.assigned_analyst}" if case.assigned_analyst else "not assigned yet"
        text = f"Case {case.case_id} is {case.status} and {owner}. Reason: {case.reason}"
        if case.risk_band:
            text += f" It is rated {case.risk_band} risk."
    return _answer(
        text, kind="operational", status="stored", tools=["case_lookup"],
        refs=[_ref("case", case.case_id)],
        followups=[f"Explain alert {case.alert_id}"] if case.alert_id else FOLLOWUPS[:2],
    )


def _case_list(sources):
    try:
        cases = [c for c in sources.list_cases() if c.status != "closed"]
    except Exception:
        return _answer(
            "I could not confirm open cases because case records are unavailable.",
            kind="operational", status="unavailable", tools=["case_list"],
            limitations=["Case records could not be read."],
        )
    if not cases:
        return _answer(
            "There are no unresolved cases in the records I can read.", kind="operational",
            status="stored", tools=["case_list"], followups=FOLLOWUPS,
        )
    shown = cases[:10]
    text = f"There are {len(cases)} unresolved cases. " + " ".join(_case_line(c) + "." for c in shown)
    return _answer(
        text, kind="operational", status="stored", tools=["case_list"],
        refs=[_ref("case", c.case_id) for c in shown],
        limitations=[] if len(cases) <= 10 else [f"Showing 10 of {len(cases)} cases."],
    )


# ---- approvals and the policy decision behind them ---------------------------------

APPROVALS_PAGE = (
    "I cannot approve or reject anything from chat; use the Approvals page, where an "
    "authorised person confirms the exact action."
)
POLICY_SENTENCE = {
    "APPROVAL_REQUIRED": "AthenaSec's policy decided this needs a person's approval.",
    "NOT_ALLOWED": "AthenaSec's policy did not allow this action.",
    "AUTO_ALLOWED": "AthenaSec's policy allowed this action to run automatically.",
}
STATUS_SENTENCE = {
    "PENDING": "It is waiting for a person to decide.",
    "APPROVED": (
        "A person approved it. An approval alone does not show whether it has run, "
        "and I cannot confirm that from here."
    ),
    "REJECTED": "A person rejected it, so it will not run.",
    "EXPIRED": "The request expired before anyone decided, so it did not run.",
    "CANCELLED": "The request was cancelled, so it did not run.",
}


def _action_text(sources, proposed_action_id):
    try:
        action = sources.get_action(proposed_action_id)
    except Exception:
        action = None

    return (f"{action.action_type} on {action.target}" if action else "an action"), action


def _approvals(sources, presentation):
    try:
        pending = list(sources.list_approvals("PENDING"))
    except Exception:
        return _answer(
            "I could not confirm what is waiting for approval because the approval records "
            "are unavailable. I will not guess.",
            kind="action_status", status="unavailable", tools=["approval_list"],
            limitations=["Approval records could not be read.", _still_available(sources)],
        )
    if not pending:
        return _answer(
            f"Nothing is waiting for approval in the records I can read. {APPROVALS_PAGE}",
            kind="action_status", status="stored", tools=["approval_list"],
            followups=FOLLOWUPS,
        )
    shown = pending[:MAX_REFS]
    lines = []
    for approval in shown:
        what, _ = _action_text(sources, approval.proposed_action_id)
        if presentation == "technical":
            expires = approval.expires_at.isoformat() if approval.expires_at else "none"
            lines.append(
                f"{approval.approval_id} | status: {approval.status} | action: {what} | "
                f"requested_by: {approval.requested_by} | expires_at: {expires}"
            )
        else:
            lines.append(f"{approval.approval_id} ({what})")
    head = (f"{len(pending)} response(s) waiting for a person to approve: "
            if presentation != "technical" else f"{len(pending)} PENDING approvals: ")
    return _answer(
        head + ("; " if presentation == "technical" else ", ").join(lines) + f". {APPROVALS_PAGE}",
        kind="action_status", status="stored", tools=["approval_list"],
        refs=[_ref("approval", a.approval_id) for a in shown],
        limitations=[] if len(pending) <= MAX_REFS else [f"Showing {MAX_REFS} of {len(pending)}."],
        followups=[f"Explain {shown[0].approval_id}"],
    )


def _approval(approval_id, sources, presentation):
    try:
        record = sources.get_approval(approval_id)
    except Exception:
        return _answer(
            f"I could not look up {approval_id} because the approval records are unavailable.",
            kind="action_status", status="unavailable", tools=["approval_lookup"],
            limitations=["Approval records could not be read.", _still_available(sources)],
        )
    if record is None:
        return _answer(
            f"Approval {approval_id} was not found.", kind="action_status", status="stored",
            tools=["approval_lookup"], followups=FOLLOWUPS,
        )
    what, action = _action_text(sources, record.proposed_action_id)
    try:
        decision = sources.get_policy_decision(record.policy_decision_id)
    except Exception:
        decision = None

    sentences = []
    if decision is not None:
        sentences.append(POLICY_SENTENCE.get(decision.outcome, ""))
        sentences.append(f"Reason recorded: {decision.reason}")
    sentences.append(STATUS_SENTENCE.get(record.status, ""))
    if record.decision_reason:
        sentences.append(f"Reason given: {record.decision_reason}")

    if presentation == "technical":
        fields = [record.approval_id, f"status: {record.status}", f"action: {what}",
                  f"incident: {record.incident_id}"]
        if decision is not None:
            fields[2:2] = [f"policy: {decision.policy_id}", f"outcome: {decision.outcome}"]
        head = " | ".join(fields) + "."
    else:
        head = f"{record.approval_id} is a request to run {what}."
    return _answer(
        " ".join([head, *[s for s in sentences if s], APPROVALS_PAGE]),
        kind="action_status", status="stored", tools=["approval_lookup"],
        refs=[_ref("approval", record.approval_id)],
        followups=["What is waiting for approval?"],
    )


# ---- system health -------------------------------------------------------------------

def _health(sources, presentation):
    try:
        report = sources.health()
    except Exception:
        return _answer(
            "I could not confirm whether monitoring is working because the health checks "
            "are unavailable. I will not guess.",
            kind="operational", status="unavailable", tools=["system_health"],
            limitations=["Health checks could not be read.", _still_available(sources)],
        )
    checked = [s for s in report.services if s.status != "unconfigured"]
    problems = [s for s in checked if s.status in ("down", "degraded")]
    starting = [s for s in checked if s.status == "starting"]
    counts: dict[str, int] = {}
    for service in report.services:
        counts[service.status] = counts.get(service.status, 0) + 1
    caveat = "These checks show whether tools are running, not that the environment is safe."

    if presentation == "technical":
        summary = ", ".join(f"{status}={count}" for status, count in sorted(counts.items()))
        detail = "; ".join(
            f"{s.check_key}={s.status}" + (f" ({s.detail})" if s.detail else "")
            for s in [*problems, *starting]
        )
        text = f"{summary}." + (f" Not up: {detail}." if detail else "") + f" {caveat}"
    else:
        parts = []
        if problems:
            names = ", ".join(f"{s.name} ({s.status})" for s in problems)
            parts.append(f"{len(problems)} of {len(checked)} checked services need attention: {names}.")
        if starting:
            parts.append("Still starting up: " + ", ".join(s.name for s in starting) + ".")
        if not parts:
            parts.append(f"All {len(checked)} checked services reported up.")
        text = " ".join(parts) + f" {caveat}"
    return _answer(
        text, kind="operational", status="live", tools=["system_health"],
        refs=[{"type": "system", "id": "health", "href": "/api/v1/system/health"}],
        followups=["Are there any urgent problems?"],
    )


# ---- audit log (administrators only, like the Audit Logs page) ------------------------

def _audit(sources, presentation, role):
    if role != "Administrator":
        return _answer(
            "Audit records are only available to administrators, the same as the Audit "
            "Logs page. I cannot show them to your account.",
            kind="unable_to_verify", status="stored", tools=[], followups=FOLLOWUPS,
        )
    try:
        events = list(sources.recent_audit(5))
    except Exception:
        return _answer(
            "I could not read the audit log right now. I will not guess.",
            kind="operational", status="unavailable", tools=["audit_recent"],
            limitations=["Audit records could not be read.", _still_available(sources)],
        )
    if not events:
        return _answer(
            "There are no audit events in the records I can read.", kind="operational",
            status="stored", tools=["audit_recent"],
        )
    if presentation == "technical":
        lines = [
            f"{e.event_id} | {e.occurred_at.isoformat()} | {e.actor_id} ({e.actor_role}) | "
            f"{e.category} | {e.action} | {e.target} | {e.result}" for e in events
        ]
        text = f"{len(events)} most recent audit events: " + "; ".join(lines) + "."
    else:
        lines = [f"{e.action} by {e.actor_id} ({e.result})" for e in events]
        text = f"The {len(events)} most recent audit events: " + ", ".join(lines) + "."
    return _answer(
        text, kind="operational", status="stored", tools=["audit_recent"],
        refs=[{"type": "audit", "id": e.event_id, "href": f"/api/v1/audit/{e.event_id}"}
              for e in events],
    )
