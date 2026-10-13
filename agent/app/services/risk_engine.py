from app.schemas import (
    AlertAnalysis,
    RiskAssessment,
    RiskContext,
    RiskFactor,
)


BASE_RISK = {
    "brute_force": 30,
    "privilege_escalation": 45,
    "privilege_misuse": 40,
    "benign": 0,
    "unknown": 10,
}


ASSET_POINTS = {
    "low": 0,
    "medium": 5,
    "high": 10,
    "critical": 15,
}


def determine_risk_band(
    score: int,
) -> str:
    if score >= 90:
        return "critical"

    if score >= 70:
        return "high"

    if score >= 40:
        return "medium"

    return "low"


def calculate_risk(
    analysis: AlertAnalysis,
    context: RiskContext,
) -> RiskAssessment:
    if analysis.classification == "benign":
        return RiskAssessment(
            score=0,
            band="low",
            factors=[
                RiskFactor(
                    name="benign_classification",
                    points=0,
                    reason=(
                        "The event was classified as benign."
                    ),
                )
            ],
        )

    factors: list[RiskFactor] = []

    base_points = BASE_RISK[
        analysis.classification
    ]

    factors.append(
        RiskFactor(
            name="base_classification",
            points=base_points,
            reason=(
                "Base risk for classification: "
                f"{analysis.classification}"
            ),
        )
    )

    if analysis.classification != "unknown":
        confidence_points = round(
            analysis.confidence * 10
        )

        factors.append(
            RiskFactor(
                name="classification_confidence",
                points=confidence_points,
                reason=(
                    "Confidence contribution from "
                    "the AI classification."
                ),
            )
        )

    asset_points = ASSET_POINTS[
        context.asset_criticality
    ]

    if asset_points:
        factors.append(
            RiskFactor(
                name="asset_criticality",
                points=asset_points,
                reason=(
                    "The affected asset has "
                    f"{context.asset_criticality} criticality."
                ),
            )
        )

    if context.privileged_target:
        factors.append(
            RiskFactor(
                name="privileged_target",
                points=15,
                reason=(
                    "The activity targets a privileged "
                    "account or privileged resource."
                ),
            )
        )

    if analysis.classification == "brute_force":
        if context.failed_attempts >= 100:
            attempt_points = 15
        elif context.failed_attempts >= 20:
            attempt_points = 10
        elif context.failed_attempts >= 5:
            attempt_points = 5
        else:
            attempt_points = 0

        if attempt_points:
            factors.append(
                RiskFactor(
                    name="failed_attempt_volume",
                    points=attempt_points,
                    reason=(
                        f"{context.failed_attempts} failed "
                        "authentication attempts were observed."
                    ),
                )
            )

    if context.successful_authentication is True:
        factors.append(
            RiskFactor(
                name="successful_authentication",
                points=20,
                reason=(
                    "A successful authentication was "
                    "observed during suspicious activity."
                ),
            )
        )

    if (
        analysis.classification
        in {
            "privilege_escalation",
            "privilege_misuse",
        }
        and context.privilege_change_observed
    ):
        factors.append(
            RiskFactor(
                name="privilege_change",
                points=20,
                reason=(
                    "A privilege change was directly observed."
                ),
            )
        )

    if (
        analysis.classification
        == "privilege_misuse"
        and context.policy_violation_observed
    ):
        factors.append(
            RiskFactor(
                name="policy_violation",
                points=15,
                reason=(
                    "A confirmed privilege-policy "
                    "violation was observed."
                ),
            )
        )

    score = min(
        sum(
            factor.points
            for factor in factors
        ),
        100,
    )

    return RiskAssessment(
        score=score,
        band=determine_risk_band(
            score
        ),
        factors=factors,
    )