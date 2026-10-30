"""Regroup backend/app/services into topic folders and rewrite every import.

Usage (from the backend folder):
    python tools/regroup_services.py            # move files + rewrite imports
    python tools/regroup_services.py --imports  # only rewrite imports (for a teammate's branch)

Safe to run twice: files already moved are skipped.
"""

import re
import shutil
import sys
from pathlib import Path

GROUPS = {
    "investigations": (
        "Turning alerts into investigations: correlation, evidence, analysis checks.",
        [
            "investigation_store", "investigation_lifecycle", "investigation_trace",
            "investigation_budget", "benign_investigation", "analysis_verifier",
            "evidence_sufficiency", "incident_correlation", "incident_correlator",
            "ml_classifier",
        ],
    ),
    "risk": (
        "Risk scoring for incidents and for each proposed action.",
        ["risk_engine", "action_risk_engine", "action_risk_context", "response_risk_lifecycle"],
    ),
    "policy": (
        "Response policy: the admin's allowed and blocked actions, and how they are applied.",
        [
            "policy_engine", "policy_document", "action_policy_engine",
            "action_policy_lifecycle", "structured_action_policy",
            "response_policy_store", "response_mode",
        ],
    ),
    "response": (
        "Planning and running a response: proposals, autonomous mode, the structured runtime.",
        ["response_planner", "response_proposal", "autonomous_response", "structured_response_runtime"],
    ),
    "approvals": (
        "Human approval of actions: fingerprints, requests and decisions.",
        ["action_approval", "approval_resolution"],
    ),
    "execution": (
        "Carrying out approved actions, then verifying or rolling them back. Protected targets.",
        [
            "structured_execution", "action_verification", "action_rollback",
            "target_operation_coordinator", "target_protection", "target_protection_store",
        ],
    ),
    "containment": (
        "Time-limited containment: tracking expiry and undoing blocks when they run out.",
        [
            "containment_expiry", "containment_expiry_store",
            "containment_expiry_worker", "containment_expiry_runner",
        ],
    ),
    "cortex": (
        "Talking to Cortex (TheHive's responder engine) to run and check actions.",
        [
            "cortex_client", "cortex_config", "cortex_executor",
            "structured_cortex_executor", "structured_cortex_verifier",
        ],
    ),
    "misp": (
        "Threat intelligence lookups against MISP.",
        ["misp_client", "misp_config", "misp_http_client", "misp_indicator_extractor"],
    ),
    "cases": (
        "Incident cases: creating them, the case workflow, and how a case is displayed.",
        ["case_service", "case_view", "case_workflow_store"],
    ),
    "audit": (
        "Audit trail: what the agent and each operator did, and when.",
        ["audit_service", "audit_store", "operator_audit_store"],
    ),
    "auth": (
        "Sign-in for the web console and operator identities.",
        ["web_auth", "operator_identity"],
    ),
    "health": (
        "System health: probing each service and recording outages.",
        ["health_probes", "health_event_store", "system_health"],
    ),
    "runtime": (
        "Runtime controls the admin can switch at runtime, such as pausing the agent.",
        ["runtime_control", "runtime_control_store"],
    ),
    "dashboard": (
        "Dashboard numbers and shared list paging.",
        ["dashboard_summary", "list_pagination"],
    ),
    "storage": (
        "Choosing the database (memory, SQLite or Postgres) and the main response-record store.",
        ["persistence_config", "incident_response_store"],
    ),
}

MOVES = {old: group for group, (_, names) in GROUPS.items() for old in names}

# app.services.<old>  ->  app.services.<group>.<old>   (dotted imports, mock.patch strings)
DOTTED = re.compile(r"\bapp\.services\.(" + "|".join(sorted(MOVES, key=len, reverse=True)) + r")\b")
# app/services/<old>.py or app/services/<old>/  ->  app/services/<group>/<old>...   (docs)
SLASHED = re.compile(r"\bapp/services/(" + "|".join(sorted(MOVES, key=len, reverse=True)) + r")\b")
# from app.services import x, y
FROM_PKG = re.compile(r"^(\s*)from app\.services import ([A-Za-z_, ]+)$", re.M)


def rewrite(text):
    text = DOTTED.sub(lambda m: f"app.services.{MOVES[m.group(1)]}.{m.group(1)}", text)
    text = SLASHED.sub(lambda m: f"app/services/{MOVES[m.group(1)]}/{m.group(1)}", text)

    def fix_from(m):
        indent, names = m.group(1), [n.strip() for n in m.group(2).split(",") if n.strip()]
        if not all(n in MOVES for n in names):
            return m.group(0)
        return "\n".join(f"{indent}from app.services.{MOVES[n]} import {n}" for n in names)

    return FROM_PKG.sub(fix_from, text)


def move_files(services):
    for group, (purpose, names) in GROUPS.items():
        folder = services / group
        folder.mkdir(exist_ok=True)
        init = folder / "__init__.py"
        if not init.exists():
            init.write_text(f'"""{purpose}"""\n', newline="\r\n")
        for name in names:
            for src in (services / f"{name}.py", services / name):
                if src.exists():
                    shutil.move(str(src), str(folder / src.name))


def rewrite_tree(root):
    changed = 0
    for path in root.rglob("*"):
        if not path.is_file() or path.suffix not in {".py", ".md", ".ini", ".yaml", ".yml", ".toml", ".sh", ".txt"}:
            continue
        if any(p in {".git", "node_modules", "__pycache__", ".venv", "venv"} for p in path.parts):
            continue
        raw = path.read_bytes()
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            continue
        new = rewrite(text)
        if new != text:
            path.write_bytes(new.encode("utf-8"))
            changed += 1
    return changed


if __name__ == "__main__":
    backend = Path.cwd()
    services = backend / "app" / "services"
    if not services.is_dir():
        sys.exit("Run this from the backend folder (the one that contains app/).")
    if "--imports" not in sys.argv:
        move_files(services)
    print(f"Rewrote imports in {rewrite_tree(backend)} files.")
