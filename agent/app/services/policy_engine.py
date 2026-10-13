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
        policy_name="No Autonomous Response Policy",
        matched=False,
        response_allowed=False,
        actions=[],
        reason=reason,
    )


def evaluate_policy(
    analysis: AlertAnalysis,
    risk: RiskAssessment,
) -> PolicyDecision:
    if analysis.classification == "benign":
        return no_policy_match(
            "Benign events do not trigger "
            "autonomous response policies."
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
            response_allowed=True,
            actions=[
                "block_ip",
            ],
            reason=(
                "Critical brute-force activity met "
                "the autonomous containment threshold."
            ),
        )

    if (
        analysis.classification == "brute_force"
        and risk.score >= 70
    ):
        return PolicyDecision(
            policy_id="POL-BF-HIGH",
            policy_name=(
                "High-Risk Brute Force"
            ),
            matched=True,
            response_allowed=False,
            actions=[],
            reason=(
                "High-risk brute-force activity was "
                "confirmed, but the configured policy "
                "does not permit autonomous containment "
                "at this risk level."
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
                "High-Risk Privilege Misuse"
            ),
            matched=True,
            response_allowed=False,
            actions=[],
            reason=(
                "High-risk privilege misuse was "
                "identified, but automatic account "
                "containment is not currently permitted."
            ),
        )

    return no_policy_match(
        "The investigation did not reach a configured "
        "autonomous-response threshold."
    )