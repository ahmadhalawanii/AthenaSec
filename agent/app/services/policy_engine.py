from app.schemas import (
    AlertAnalysis,
    PolicyDecision,
    RiskAssessment,
)


def no_policy_match(
    reason: str,
) -> PolicyDecision:
    return PolicyDecision(
        policy_id="NONE",
        policy_name="No Response Policy",
        matched=False,
        approval_type="none",
        execution_mode="dry_run",
        actions=[],
        reason=reason,
    )


def evaluate_policy(
    analysis: AlertAnalysis,
    risk: RiskAssessment,
) -> PolicyDecision:
    if analysis.classification == "benign":
        return no_policy_match(
            "Benign events do not trigger response policies."
        )

    if (
        analysis.classification == "brute_force"
        and risk.score >= 90
    ):
        return PolicyDecision(
            policy_id="POL-BF-CRITICAL",
            policy_name=(
                "Critical Brute Force Containment"
            ),
            matched=True,
            approval_type="automatic",
            execution_mode="dry_run",
            actions=[
                "block_ip",
                "notify_administrator",
                "create_case",
                "record_response",
            ],
            reason=(
                "Critical brute-force risk reached "
                "the automatic containment threshold."
            ),
        )

    if (
        analysis.classification == "brute_force"
        and risk.score >= 70
    ):
        return PolicyDecision(
            policy_id="POL-BF-HIGH",
            policy_name=(
                "High-Risk Brute Force Review"
            ),
            matched=True,
            approval_type="analyst",
            execution_mode="dry_run",
            actions=[
                "block_ip",
                "notify_administrator",
                "create_case",
            ],
            reason=(
                "High-risk brute-force activity requires "
                "analyst approval before containment."
            ),
        )

    if (
        analysis.classification
        == "privilege_misuse"
        and risk.score >= 80
    ):
        return PolicyDecision(
            policy_id="POL-PM-HIGH",
            policy_name=(
                "Privilege Misuse Containment"
            ),
            matched=True,
            approval_type="analyst",
            execution_mode="dry_run",
            actions=[
                "lock_account",
                "capture_telemetry",
                "notify_administrator",
                "create_case",
            ],
            reason=(
                "High-risk privilege misuse requires "
                "analyst-approved containment."
            ),
        )

    return no_policy_match(
        "The investigation did not reach a configured "
        "response-policy threshold."
    )