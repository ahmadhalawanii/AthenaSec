from uuid import (
    NAMESPACE_URL,
    uuid5,
)

from app.schemas import (
    AlertCorrelationFingerprint,
    AttackPrediction,
    IncidentAlertRecord,
    IncidentCorrelationDecision,
    IncidentCorrelationProfile,
    IncidentRecord,
    SecurityAlertInput,
)
from app.services.incident_correlation import (
    DEFAULT_CORRELATION_WINDOW,
    build_alert_correlation_fingerprint,
    build_initial_correlation_profile,
    evaluate_correlation,
    update_correlation_profile,
)
from app.services.investigation_store import (
    InvestigationStore,
)


ACTIVE_INCIDENT_STATUSES = {
    "open",
    "contained",
}


def _build_incident_id(
    alert_id: str,
) -> str:
    incident_uuid = uuid5(
        NAMESPACE_URL,
        (
            "athenasec-incident:"
            f"{alert_id}"
        ),
    )

    return (
        "INC-"
        f"{str(incident_uuid).upper()}"
    )


def _build_incident_title(
    classification: str,
) -> str:
    titles = {
        "brute_force": (
            "Brute force activity"
        ),
        "privilege_misuse": (
            "Privilege misuse activity"
        ),
        "privilege_escalation": (
            "Privilege escalation activity"
        ),
        "unknown": (
            "Unclassified security activity"
        ),
        "benign": (
            "Benign security activity"
        ),
    }

    return titles.get(
        classification,
        "Security activity",
    )


def _build_incident_alert(
    *,
    incident_id: str,
    alert: SecurityAlertInput,
    observed_at,
) -> IncidentAlertRecord:
    return IncidentAlertRecord(
        incident_id=incident_id,
        alert_id=alert.alert_id,
        source=alert.source,
        event_text=alert.event_text,
        metadata=dict(
            alert.metadata
        ),
        observed_at=observed_at,
    )


def _load_existing_decision(
    *,
    alert: SecurityAlertInput,
    store: InvestigationStore,
) -> IncidentCorrelationDecision | None:
    stored_alert = (
        store.get_incident_alert(
            alert.alert_id
        )
    )

    if stored_alert is None:
        return None

    incident = store.get_incident(
        stored_alert.incident_id
    )

    if incident is None:
        raise RuntimeError(
            "Stored incident alert references "
            "a missing incident."
        )

    profile = (
        store.get_correlation_profile(
            incident.incident_id
        )
    )

    if profile is None:
        raise RuntimeError(
            "Stored incident alert references "
            "an incident without a "
            "correlation profile."
        )

    return IncidentCorrelationDecision(
        incident=incident,
        alert=stored_alert,
        profile=profile,
        created_new_incident=False,
        duplicate_alert=True,
        correlation_score=0,
        correlation_reasons=[
            "alert_already_correlated",
        ],
    )


def _find_best_match(
    *,
    store: InvestigationStore,
    fingerprint: AlertCorrelationFingerprint,
):
    candidates = (
        store.list_correlation_candidates(
            classification=(
                fingerprint.classification
            ),
            observed_at=(
                fingerprint.observed_at
            ),
            window=(
                DEFAULT_CORRELATION_WINDOW
            ),
        )
    )

    matches = []

    for profile in candidates:
        incident = store.get_incident(
            profile.incident_id
        )

        if incident is None:
            continue

        if (
            incident.status
            not in ACTIVE_INCIDENT_STATUSES
        ):
            continue

        result = evaluate_correlation(
            profile,
            fingerprint,
        )

        if not result.matched:
            continue

        matches.append(
            (
                result.score,
                profile.last_seen,
                profile.incident_id,
                incident,
                profile,
                result,
            )
        )

    if not matches:
        return None

    matches.sort(
        key=lambda item: (
            -item[0],
            -item[1].timestamp(),
            item[2],
        )
    )

    return matches[0][3:]


def correlate_or_create_incident(
    *,
    alert: SecurityAlertInput,
    prediction: AttackPrediction,
    store: InvestigationStore,
) -> IncidentCorrelationDecision:
    existing = (
        _load_existing_decision(
            alert=alert,
            store=store,
        )
    )

    if existing is not None:
        return existing

    fingerprint = (
        build_alert_correlation_fingerprint(
            alert,
            classification=(
                prediction.classification
            ),
        )
    )

    best_match = _find_best_match(
        store=store,
        fingerprint=fingerprint,
    )

    if best_match is not None:
        (
            incident,
            profile,
            match_result,
        ) = best_match

        updated_profile = (
            update_correlation_profile(
                profile,
                fingerprint,
            )
        )

        updated_incident = (
            incident.model_copy(
                update={
                    "updated_at": max(
                        incident.updated_at,
                        fingerprint.observed_at,
                    ),
                }
            )
        )

        incident_alert = (
            _build_incident_alert(
                incident_id=(
                    incident.incident_id
                ),
                alert=alert,
                observed_at=(
                    fingerprint.observed_at
                ),
            )
        )

        store.save_incident(
            updated_incident
        )

        store.save_correlation_profile(
            updated_profile
        )

        store.save_incident_alert(
            incident_alert
        )

        return IncidentCorrelationDecision(
            incident=updated_incident,
            alert=incident_alert,
            profile=updated_profile,
            created_new_incident=False,
            duplicate_alert=False,
            correlation_score=(
                match_result.score
            ),
            correlation_reasons=(
                match_result.reasons
            ),
        )

    incident_id = _build_incident_id(
        alert.alert_id
    )

    incident = IncidentRecord(
        incident_id=incident_id,
        title=_build_incident_title(
            prediction.classification
        ),
        status="open",
        created_at=(
            fingerprint.observed_at
        ),
        updated_at=(
            fingerprint.observed_at
        ),
    )

    profile = (
        build_initial_correlation_profile(
            incident_id=incident_id,
            fingerprint=fingerprint,
        )
    )

    incident_alert = (
        _build_incident_alert(
            incident_id=incident_id,
            alert=alert,
            observed_at=(
                fingerprint.observed_at
            ),
        )
    )

    store.save_incident(
        incident
    )

    store.save_correlation_profile(
        profile
    )

    store.save_incident_alert(
        incident_alert
    )

    return IncidentCorrelationDecision(
        incident=incident,
        alert=incident_alert,
        profile=profile,
        created_new_incident=True,
        duplicate_alert=False,
        correlation_score=0,
        correlation_reasons=[
            "new_incident",
        ],
    )