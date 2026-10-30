"""The agent action catalogue, the default action policy, and the rules a policy must follow.

Three tiers (design/agent-action-policy.pdf, mirrored by the website in
frontend/src/data/agentPolicyData.ts):

- Tier 1: low-risk actions. May run automatically.
- Tier 2: higher-impact actions. Always need a person's approval, within caps the
  administrator cannot raise.
- Tier 3: prohibited. Always blacklisted; the agent has no tool for them.

The administrator's policy picks, for each catalogue action, whether it is whitelisted
(and in which mode), blacklisted, or on neither list. An action on neither list is denied.
"""

import ipaddress
from dataclasses import dataclass

from app.schemas import (
    ActionBlacklistEntry,
    ActionPolicyContent,
    ActionPolicyLimits,
    ActionProtectedTarget,
    ActionWhitelistEntry,
)


@dataclass(frozen=True)
class Tier2Cap:
    """The most an administrator may allow for an approval-required action."""

    max_minutes: int | None
    window_minutes: int
    approver: str
    min_risk: int


TIER1_ACTIONS = (
    "get_logs",
    "analyse_alert",
    "check_ip_reputation",
    "get_asset_context",
    "monitor",
    "create_alert",
    "create_ticket",
    "recommend_response",
    "notify_analyst",
    "capture_telemetry",
)

TIER2_CAPS = {
    "block_ip": Tier2Cap(max_minutes=1440, window_minutes=15, approver="soc_analyst", min_risk=70),
    "isolate_host": Tier2Cap(max_minutes=240, window_minutes=15, approver="soc_lead", min_risk=85),
    "suspend_user_session": Tier2Cap(max_minutes=60, window_minutes=15, approver="soc_analyst", min_risk=75),
    "kill_process": Tier2Cap(max_minutes=None, window_minutes=15, approver="soc_lead", min_risk=75),
    "quarantine_file": Tier2Cap(max_minutes=None, window_minutes=15, approver="soc_lead", min_risk=75),
    "reset_password": Tier2Cap(max_minutes=None, window_minutes=15, approver="soc_lead", min_risk=75),
}

TIER3_ACTIONS = (
    "block_ip_permanent",
    "delete_logs",
    "disable_security_control",
    "modify_privileged_account",
    "isolate_critical_host",
    "change_policy",
)

CATALOGUE = set(TIER1_ACTIONS) | set(TIER2_CAPS) | set(TIER3_ACTIONS)

# The agent's structured actions (StructuredResponseProposal) and the catalogue entry
# that governs each. lock_account is the catalogue's suspend_user_session ("locking an account").
AGENT_ACTION_KEYS = {
    "block_ip": "block_ip",
    "lock_account": "suspend_user_session",
    "capture_telemetry": "capture_telemetry",
}

APPROVER_RANK = {"soc_analyst": 1, "soc_lead": 2}

_REQUIRED_NEVER_BLOCK = (
    ("10.0.0.0/8", "Internal range"),
    ("172.16.0.0/12", "Internal range"),
    ("192.168.0.0/16", "Internal range"),
    ("127.0.0.0/8", "Internal range"),
)


def default_action_policy() -> ActionPolicyContent:
    """The policy in force until an administrator saves one (matches the website's default)."""

    return ActionPolicyContent(
        whitelist=[
            *(ActionWhitelistEntry(action=name, mode="automatic") for name in TIER1_ACTIONS),
            ActionWhitelistEntry(
                action="block_ip",
                mode="approval",
                limits=ActionPolicyLimits(
                    default_minutes=30, max_minutes=1440, approver="soc_analyst",
                    window_minutes=15, min_risk=70,
                ),
            ),
            ActionWhitelistEntry(
                action="isolate_host",
                mode="approval",
                limits=ActionPolicyLimits(
                    default_minutes=120, max_minutes=240, approver="soc_lead",
                    window_minutes=15, min_risk=90,
                ),
            ),
        ],
        blacklist=[ActionBlacklistEntry(action=name, required=True) for name in TIER3_ACTIONS],
        never_block=[
            ActionProtectedTarget(value=value, label=label, required=True)
            for value, label in _REQUIRED_NEVER_BLOCK
        ],
        never_isolate=[],
    )


def _valid_target(value: str) -> bool:
    try:
        ipaddress.ip_network(value, strict=False)
        return True
    except ValueError:
        pass

    labels = value.lower().rstrip(".").split(".")

    return all(
        label and len(label) <= 63 and label.replace("-", "").isalnum()
        and not label.startswith("-") and not label.endswith("-")
        for label in labels
    )


def validate_action_policy(policy: ActionPolicyContent) -> list[str]:
    """Every rule the policy breaks, as plain sentences. Empty means the policy is valid."""

    problems: list[str] = []
    white = [entry.action for entry in policy.whitelist]
    black = [entry.action for entry in policy.blacklist]

    for name in white + black:
        if name not in CATALOGUE:
            problems.append(f"{name} is not an action in the catalogue.")

    for label, names in (("whitelist", white), ("blacklist", black)):
        duplicates = sorted({name for name in names if names.count(name) > 1})
        for name in duplicates:
            problems.append(f"{name} is listed more than once on the {label}.")

    for name in sorted(set(white) & set(black)):
        problems.append(f"{name} cannot be on both the whitelist and the blacklist.")

    for name in TIER3_ACTIONS:
        if name in white:
            problems.append(f"{name} is prohibited and cannot be whitelisted.")
        if name not in black:
            problems.append(f"{name} is prohibited and must stay on the blacklist.")

    for entry in policy.whitelist:
        cap = TIER2_CAPS.get(entry.action)

        if cap is None:
            continue

        if entry.mode != "approval":
            problems.append(f"{entry.action} always needs a person's approval; it cannot be automatic.")

        limits = entry.limits

        if limits is None:
            problems.append(f"{entry.action} needs approval limits.")
            continue

        if cap.max_minutes is None:
            if limits.max_minutes is not None or limits.default_minutes is not None:
                problems.append(f"{entry.action} does not reverse on its own, so it takes no duration.")
        else:
            if limits.max_minutes is None or limits.max_minutes > cap.max_minutes:
                problems.append(f"{entry.action} may last at most {cap.max_minutes} minutes.")
            if limits.default_minutes is not None and limits.max_minutes is not None and (
                limits.default_minutes > limits.max_minutes
            ):
                problems.append(f"{entry.action}: the default duration cannot exceed the longest allowed.")

        if limits.window_minutes > cap.window_minutes:
            problems.append(f"{entry.action}: the time to decide may be at most {cap.window_minutes} minutes.")

        if APPROVER_RANK[limits.approver] < APPROVER_RANK[cap.approver]:
            problems.append(f"{entry.action} must be approved by a {cap.approver} or higher.")

        if limits.min_risk < cap.min_risk:
            problems.append(f"{entry.action}: the minimum risk may not be lower than {cap.min_risk}.")

    for label, targets in (("never_block", policy.never_block), ("never_isolate", policy.never_isolate)):
        values = [target.value.strip().lower() for target in targets]
        for target in targets:
            if not _valid_target(target.value.strip()):
                problems.append(f"{target.value} on {label} is not an IP address, CIDR range or host name.")
        for value in sorted({value for value in values if values.count(value) > 1}):
            problems.append(f"{value} is listed more than once on {label}.")

    kept = {target.value.strip().lower() for target in policy.never_block}
    for value, _ in _REQUIRED_NEVER_BLOCK:
        if value not in kept:
            problems.append(f"{value} is a required protected range and cannot be removed.")

    return problems


def target_is_protected(target: str, protected: list[ActionProtectedTarget]) -> bool:
    """True when the target is on the list: an IP inside a listed range, or the same host name."""

    value = target.strip().lower()

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        address = None

    for entry in protected:
        listed = entry.value.strip().lower()

        if address is not None:
            try:
                if address in ipaddress.ip_network(listed, strict=False):
                    return True
            except ValueError:
                continue
        elif listed.rstrip(".") == value.rstrip("."):
            return True

    return False


def whitelist_entry(policy: ActionPolicyContent, catalogue_key: str) -> ActionWhitelistEntry | None:
    return next((entry for entry in policy.whitelist if entry.action == catalogue_key), None)


def is_blacklisted(policy: ActionPolicyContent, catalogue_key: str) -> bool:
    return any(entry.action == catalogue_key for entry in policy.blacklist)
