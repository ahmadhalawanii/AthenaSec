import re
from datetime import (
    datetime,
    timedelta,
    timezone,
)

from app.schemas import (
    AlertAnalysis,
    AnalysisVerificationResult,
    AttackPrediction,
    EvidenceRecord,
    EvidenceSufficiencyAssessment,
    SecurityAlertInput,
)


MAX_CITED_EVIDENCE_TIME_DISTANCE = (
    timedelta(
        minutes=30,
    )
)


TIMESTAMP_PATTERN = re.compile(
    r"(?:^|;\s*)"
    r"timestamp=([^;]+)",
    re.IGNORECASE,
)


SUCCESSFUL_AUTHENTICATION_PATTERN = (
    re.compile(
        r"\b(?:"
        r"successful authentication|"
        r"successful ssh authentication|"
        r"successful login"
        r")\b",
        re.IGNORECASE,
    )
)


NEGATING_PREFIX_PATTERN = re.compile(
    r"(?:"
    r"\bno(?: confirmed)?|"
    r"\bnot(?: a)?|"
    r"\bwithout(?: a)?"
    r")\s*$",
    re.IGNORECASE,
)


NEGATIVE_SUCCESS_EVIDENCE_PATTERNS = (
    "no successful authentication",
    "no successful ssh authentication",
    "no successful login",
    "no confirmed successful authentication",
    "no confirmed successful login",
)


def _append_unique(
    values: list[str],
    value: str,
) -> None:
    if value not in values:
        values.append(
            value
        )


def _parse_datetime(
    value,
) -> datetime | None:
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
            return None

        if normalized.endswith(
            "Z"
        ):
            normalized = (
                normalized[:-1]
                + "+00:00"
            )

        try:
            parsed = (
                datetime.fromisoformat(
                    normalized
                )
            )

        except ValueError:
            return None

    else:
        return None

    if parsed.tzinfo is None:
        return None

    return parsed.astimezone(
        timezone.utc
    )


def _extract_evidence_timestamp(
    record: EvidenceRecord,
) -> datetime | None:
    match = TIMESTAMP_PATTERN.search(
        record.content
    )

    if match is None:
        return None

    return _parse_datetime(
        match.group(1).strip()
    )


def _analysis_text(
    analysis: AlertAnalysis,
) -> str:
    values = [
        analysis.summary,
        *analysis.uncertainties,
        *analysis.recommended_investigation_steps,
        *analysis.recommended_response_actions,
    ]

    return "\n".join(
        values
    )


def _claims_successful_authentication(
    analysis: AlertAnalysis,
) -> bool:
    text = _analysis_text(
        analysis
    )

    for match in (
        SUCCESSFUL_AUTHENTICATION_PATTERN
        .finditer(
            text
        )
    ):
        prefix = text[
            max(
                0,
                match.start() - 32,
            ):
            match.start()
        ]

        if NEGATING_PREFIX_PATTERN.search(
            prefix
        ):
            continue

        return True

    return False


def _evidence_denies_successful_authentication(
    evidence_records: list[
        EvidenceRecord
    ],
) -> bool:
    for record in evidence_records:
        text = (
            record.content.lower()
        )

        if any(
            phrase in text
            for phrase
            in NEGATIVE_SUCCESS_EVIDENCE_PATTERNS
        ):
            return True

    return False


def verify_analysis(
    *,
    alert: SecurityAlertInput,
    analysis: AlertAnalysis,
    evidence_records: list[
        EvidenceRecord
    ],
    ml_prediction: (
        AttackPrediction | None
    ),
    evidence_sufficiency: (
        EvidenceSufficiencyAssessment
        | None
    ),
    investigation_budget_exhausted: bool,
) -> AnalysisVerificationResult:
    blocking_issues: list[str] = []

    warnings: list[str] = []

    evidence_by_id = {
        record.evidence_id: record
        for record in evidence_records
    }

    checked_evidence_refs = list(
        dict.fromkeys(
            analysis.evidence_refs
        )
    )

    missing_references = [
        evidence_id
        for evidence_id
        in checked_evidence_refs
        if evidence_id
        not in evidence_by_id
    ]

    for evidence_id in (
        missing_references
    ):
        _append_unique(
            blocking_issues,
            (
                "missing_evidence_reference:"
                f"{evidence_id}"
            ),
        )

    classification_consistent = True

    if (
        ml_prediction is not None
        and ml_prediction.classification
        != "unknown"
        and analysis.classification
        != ml_prediction.classification
    ):
        classification_consistent = (
            False
        )

        _append_unique(
            blocking_issues,
            "classification_mismatch",
        )

    evidence_sufficient = (
        evidence_sufficiency.sufficient
        if evidence_sufficiency
        is not None
        else True
    )

    if (
        alert.source == "wazuh"
        and evidence_sufficiency
        is not None
        and not evidence_sufficiency.sufficient
    ):
        _append_unique(
            blocking_issues,
            "evidence_insufficient",
        )

    if investigation_budget_exhausted:
        _append_unique(
            warnings,
            (
                "investigation_budget_exhausted"
            ),
        )

    if (
        _evidence_denies_successful_authentication(
            evidence_records
        )
        and _claims_successful_authentication(
            analysis
        )
    ):
        _append_unique(
            blocking_issues,
            (
                "successful_authentication_"
                "contradiction"
            ),
        )

    alert_timestamp = (
        _parse_datetime(
            alert.metadata.get(
                "timestamp"
            )
        )
    )

    if alert_timestamp is not None:
        for evidence_id in (
            checked_evidence_refs
        ):
            record = evidence_by_id.get(
                evidence_id
            )

            if record is None:
                continue

            if record.source != "wazuh":
                continue

            evidence_timestamp = (
                _extract_evidence_timestamp(
                    record
                )
            )

            if evidence_timestamp is None:
                continue

            distance = abs(
                evidence_timestamp
                - alert_timestamp
            )

            if (
                distance
                > MAX_CITED_EVIDENCE_TIME_DISTANCE
            ):
                _append_unique(
                    blocking_issues,
                    (
                        "stale_cited_evidence:"
                        f"{evidence_id}"
                    ),
                )

    tool_evidence_ids = {
        record.evidence_id
        for record in evidence_records
        if (
            record.evidence_type
            not in {
                None,
                "alert",
            }
        )
    }

    cited_tool_evidence = (
        tool_evidence_ids
        & set(
            checked_evidence_refs
        )
    )

    if (
        tool_evidence_ids
        and not cited_tool_evidence
    ):
        _append_unique(
            warnings,
            "tool_evidence_not_cited",
        )

    return AnalysisVerificationResult(
        verified=(
            len(blocking_issues)
            == 0
        ),
        classification_consistent=(
            classification_consistent
        ),
        evidence_sufficient=(
            evidence_sufficient
        ),
        checked_evidence_refs=(
            checked_evidence_refs
        ),
        blocking_issues=(
            blocking_issues
        ),
        warnings=warnings,
    )