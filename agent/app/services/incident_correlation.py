from datetime import (
    datetime,
    timedelta,
    timezone,
)
from typing import Any

from app.schemas import (
    AlertCorrelationFingerprint,
    AttackClassification,
    CorrelationMatchResult,
    IncidentCorrelationProfile,
    SecurityAlertInput,
)


DEFAULT_CORRELATION_WINDOW = timedelta(
    minutes=15,
)

CORRELATION_THRESHOLD = 5


def _normalized_optional_string(
    value: Any,
) -> str | None:
    if not isinstance(
        value,
        str,
    ):
        return None

    normalized = value.strip()

    if not normalized:
        return None

    return normalized.lower()


def _normalized_values(
    value: Any,
) -> list[str]:
    if value is None:
        return []

    if not isinstance(
        value,
        list,
    ):
        value = [
            value,
        ]

    normalized = {
        item.strip()
        for item in value
        if (
            isinstance(
                item,
                str,
            )
            and item.strip()
        )
    }

    return sorted(
        normalized
    )


def _parse_observed_at(
    value: Any,
) -> datetime:
    if isinstance(
        value,
        datetime,
    ):
        parsed = value

    elif isinstance(
        value,
        str,
    ):
        normalized = (
            value.strip()
        )

        if not normalized:
            raise ValueError(
                "Alert timestamp is required "
                "for incident correlation."
            )

        if normalized.endswith(
            "Z"
        ):
            normalized = (
                normalized[:-1]
                + "+00:00"
            )

        try:
            parsed = datetime.fromisoformat(
                normalized
            )
        except ValueError as exc:
            raise ValueError(
                "Alert timestamp is invalid "
                "for incident correlation."
            ) from exc

    else:
        raise ValueError(
            "Alert timestamp is required "
            "for incident correlation."
        )

    if parsed.tzinfo is None:
        raise ValueError(
            "Alert timestamp must include "
            "timezone information."
        )

    return parsed.astimezone(
        timezone.utc
    )


def build_alert_correlation_fingerprint(
    alert: SecurityAlertInput,
    *,
    classification: AttackClassification,
) -> AlertCorrelationFingerprint:
    metadata = alert.metadata

    return AlertCorrelationFingerprint(
        alert_id=alert.alert_id,
        classification=classification,
        observed_at=_parse_observed_at(
            metadata.get(
                "timestamp"
            )
        ),
        source_ip=(
            _normalized_optional_string(
                metadata.get(
                    "source_ip"
                )
            )
        ),
        target_user=(
            _normalized_optional_string(
                metadata.get(
                    "target_user"
                )
            )
        ),
        agent_id=(
            _normalized_optional_string(
                metadata.get(
                    "agent_id"
                )
            )
        ),
        mitre_ids=(
            _normalized_values(
                metadata.get(
                    "mitre_ids"
                )
            )
        ),
    )


def _inside_correlation_window(
    profile: IncidentCorrelationProfile,
    fingerprint: AlertCorrelationFingerprint,
    window: timedelta,
) -> bool:
    earliest_allowed = (
        profile.first_seen
        - window
    )

    latest_allowed = (
        profile.last_seen
        + window
    )

    return (
        earliest_allowed
        <= fingerprint.observed_at
        <= latest_allowed
    )


def evaluate_correlation(
    profile: IncidentCorrelationProfile,
    fingerprint: AlertCorrelationFingerprint,
    *,
    window: timedelta = DEFAULT_CORRELATION_WINDOW,
) -> CorrelationMatchResult:
    if (
        profile.classification
        != fingerprint.classification
    ):
        return CorrelationMatchResult(
            matched=False,
            score=0,
            reasons=[
                "classification_mismatch",
            ],
        )

    if not _inside_correlation_window(
        profile,
        fingerprint,
        window,
    ):
        return CorrelationMatchResult(
            matched=False,
            score=0,
            reasons=[
                "outside_time_window",
            ],
        )

    score = 0

    reasons: list[str] = []

    if (
        fingerprint.source_ip
        and fingerprint.source_ip
        in profile.source_ips
    ):
        score += 5

        reasons.append(
            "source_ip"
        )

    if (
        fingerprint.agent_id
        and fingerprint.agent_id
        in profile.agent_ids
    ):
        score += 3

        reasons.append(
            "agent_id"
        )

    if (
        fingerprint.target_user
        and fingerprint.target_user
        in profile.target_users
    ):
        score += 2

        reasons.append(
            "target_user"
        )

    if (
        set(
            fingerprint.mitre_ids
        )
        & set(
            profile.mitre_ids
        )
    ):
        score += 2

        reasons.append(
            "mitre_id"
        )

    return CorrelationMatchResult(
        matched=(
            score
            >= CORRELATION_THRESHOLD
        ),
        score=score,
        reasons=reasons,
    )


def _merge_values(
    existing: list[str],
    value: str | None,
) -> list[str]:
    values = set(
        existing
    )

    if value:
        values.add(
            value
        )

    return sorted(
        values
    )


def update_correlation_profile(
    profile: IncidentCorrelationProfile,
    fingerprint: AlertCorrelationFingerprint,
) -> IncidentCorrelationProfile:
    if (
        profile.classification
        != fingerprint.classification
    ):
        raise ValueError(
            "Cannot update an incident "
            "correlation profile with a "
            "different classification."
        )

    return profile.model_copy(
        update={
            "source_ips": (
                _merge_values(
                    profile.source_ips,
                    fingerprint.source_ip,
                )
            ),
            "target_users": (
                _merge_values(
                    profile.target_users,
                    fingerprint.target_user,
                )
            ),
            "agent_ids": (
                _merge_values(
                    profile.agent_ids,
                    fingerprint.agent_id,
                )
            ),
            "mitre_ids": sorted(
                set(
                    profile.mitre_ids
                )
                | set(
                    fingerprint.mitre_ids
                )
            ),
            "first_seen": min(
                profile.first_seen,
                fingerprint.observed_at,
            ),
            "last_seen": max(
                profile.last_seen,
                fingerprint.observed_at,
            ),
        }
    )


def build_initial_correlation_profile(
    *,
    incident_id: str,
    fingerprint: AlertCorrelationFingerprint,
) -> IncidentCorrelationProfile:
    return IncidentCorrelationProfile(
        incident_id=incident_id,
        classification=(
            fingerprint.classification
        ),
        source_ips=(
            [fingerprint.source_ip]
            if fingerprint.source_ip
            else []
        ),
        target_users=(
            [fingerprint.target_user]
            if fingerprint.target_user
            else []
        ),
        agent_ids=(
            [fingerprint.agent_id]
            if fingerprint.agent_id
            else []
        ),
        mitre_ids=list(
            fingerprint.mitre_ids
        ),
        first_seen=(
            fingerprint.observed_at
        ),
        last_seen=(
            fingerprint.observed_at
        ),
    )