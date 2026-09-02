import ipaddress
import re
from collections.abc import Callable

from app.graph.state import InvestigationState
from app.schemas import (
    AlertAnalysis,
    EvidenceRecord,
)


Analyzer = Callable[
    [str],
    AlertAnalysis,
]


IPV4_CANDIDATE_PATTERN = re.compile(
    r"(?<![\d.])"
    r"(?:\d{1,3}\.){3}\d{1,3}"
    r"(?![\d.])"
)

USER_EVIDENCE_PATTERN = re.compile(
    r"\b(?:"
    r"target_user|"
    r"source_user|"
    r"user|"
    r"srcuser|"
    r"dstuser"
    r")\s*=\s*"
    r"([A-Za-z0-9_.@\\-]+)",
    re.IGNORECASE,
)

HOST_EVIDENCE_PATTERN = re.compile(
    r"\b(?:"
    r"agent_name|"
    r"hostname|"
    r"host|"
    r"endpoint|"
    r"device|"
    r"machine"
    r")\s*=\s*"
    r"([A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)

USER_REFERENCE_PATTERN = re.compile(
    r"\b(?:user|account)\s+"
    r"([A-Za-z0-9_.@\\-]+)",
    re.IGNORECASE,
)

HOST_REFERENCE_PATTERN = re.compile(
    r"\b(?:"
    r"host|"
    r"endpoint|"
    r"device|"
    r"machine"
    r")\s+"
    r"([A-Za-z0-9_.-]+)",
    re.IGNORECASE,
)


def build_analysis_context(
    state: InvestigationState,
) -> str:
    sections: list[str] = []

    ml_prediction = state.get(
        "ml_prediction"
    )

    if ml_prediction is not None:
        sections.append(
            "\n".join(
                [
                    "ML prediction:",
                    (
                        "classification="
                        f"{ml_prediction.classification}"
                    ),
                    (
                        "confidence="
                        f"{ml_prediction.confidence}"
                    ),
                    (
                        "model_version="
                        f"{ml_prediction.model_version}"
                    ),
                ]
            )
        )

    misp_enrichment = state.get(
        "misp_enrichment"
    )

    if misp_enrichment is not None:
        misp_lines = [
            "MISP enrichment:",
        ]

        if misp_enrichment.matches:
            for match in misp_enrichment.matches:
                misp_lines.append(
                    (
                        f"indicator_type="
                        f"{match.indicator_type}; "
                        f"indicator_value="
                        f"{match.indicator_value}; "
                        f"event_id="
                        f"{match.event_id}; "
                        f"event_info="
                        f"{match.event_info}; "
                        f"threat_level="
                        f"{match.threat_level}"
                    )
                )

        else:
            misp_lines.append(
                "No MISP matches found."
            )

        sections.append(
            "\n".join(
                misp_lines
            )
        )

    evidence_records = state.get(
        "evidence_records",
        [],
    )

    for record in evidence_records:
        sections.append(
            (
                f"[{record.evidence_id}] "
                f"source={record.source}; "
                f"content={record.content}"
            )
        )

    if not sections:
        return (
            "No grounded evidence or "
            "enrichment is available."
        )

    return "\n\n".join(
        sections
    )

def validate_evidence_references(
    analysis: AlertAnalysis,
    evidence_records: list[
        EvidenceRecord
    ],
) -> None:
    if not analysis.evidence_refs:
        raise ValueError(
            "Analysis must cite at least one "
            "available evidence record."
        )

    available_ids = {
        record.evidence_id
        for record in evidence_records
    }

    unavailable_ids = [
        evidence_id
        for evidence_id
        in analysis.evidence_refs
        if evidence_id
        not in available_ids
    ]

    if unavailable_ids:
        joined_ids = ", ".join(
            unavailable_ids
        )

        raise ValueError(
            "Analysis cited unavailable "
            f"evidence: {joined_ids}"
        )


def _extract_ipv4_addresses(
    text: str,
) -> set[str]:
    addresses: set[str] = set()

    for candidate in (
        IPV4_CANDIDATE_PATTERN.findall(
            text
        )
    ):
        try:
            address = ipaddress.ip_address(
                candidate
            )
        except ValueError:
            continue

        if address.version == 4:
            addresses.add(
                str(address)
            )

    return addresses


def _extract_pattern_values(
    pattern: re.Pattern[str],
    text: str,
) -> set[str]:
    return {
        match.lower()
        for match in pattern.findall(text)
    }


def _grounded_ipv4_addresses(
    evidence_records: list[
        EvidenceRecord
    ],
) -> set[str]:
    grounded: set[str] = set()

    for record in evidence_records:
        grounded.update(
            _extract_ipv4_addresses(
                record.content
            )
        )

    return grounded


def _grounded_users(
    evidence_records: list[
        EvidenceRecord
    ],
) -> set[str]:
    grounded: set[str] = set()

    for record in evidence_records:
        grounded.update(
            _extract_pattern_values(
                USER_EVIDENCE_PATTERN,
                record.content,
            )
        )

    return grounded


def _grounded_hosts(
    evidence_records: list[
        EvidenceRecord
    ],
) -> set[str]:
    grounded: set[str] = set()

    for record in evidence_records:
        grounded.update(
            _extract_pattern_values(
                HOST_EVIDENCE_PATTERN,
                record.content,
            )
        )

    return grounded


def _analysis_text_fields(
    analysis: AlertAnalysis,
) -> list[str]:
    text_fields = [
        analysis.summary,
    ]

    text_fields.extend(
        analysis.uncertainties
    )

    text_fields.extend(
        analysis.recommended_investigation_steps
    )

    text_fields.extend(
        analysis.recommended_response_actions
    )

    return text_fields


def validate_grounded_entities(
    analysis: AlertAnalysis,
    evidence_records: list[
        EvidenceRecord
    ],
) -> None:
    grounded_ips = (
        _grounded_ipv4_addresses(
            evidence_records
        )
    )

    grounded_users = (
        _grounded_users(
            evidence_records
        )
    )

    grounded_hosts = (
        _grounded_hosts(
            evidence_records
        )
    )

    mentioned_ips: set[str] = set()
    mentioned_users: set[str] = set()
    mentioned_hosts: set[str] = set()

    for text in _analysis_text_fields(
        analysis
    ):
        mentioned_ips.update(
            _extract_ipv4_addresses(
                text
            )
        )

        mentioned_users.update(
            _extract_pattern_values(
                USER_REFERENCE_PATTERN,
                text,
            )
        )

        mentioned_hosts.update(
            _extract_pattern_values(
                HOST_REFERENCE_PATTERN,
                text,
            )
        )

    ungrounded_ips = (
        mentioned_ips
        - grounded_ips
    )

    if ungrounded_ips:
        joined_ips = ", ".join(
            sorted(
                ungrounded_ips
            )
        )

        raise ValueError(
            "Analysis contains ungrounded IP "
            f"address(es): {joined_ips}"
        )

    ungrounded_users = (
        mentioned_users
        - grounded_users
    )

    if ungrounded_users:
        joined_users = ", ".join(
            sorted(
                ungrounded_users
            )
        )

        raise ValueError(
            "Analysis contains ungrounded user "
            f"reference(s): {joined_users}"
        )

    ungrounded_hosts = (
        mentioned_hosts
        - grounded_hosts
    )

    if ungrounded_hosts:
        joined_hosts = ", ".join(
            sorted(
                ungrounded_hosts
            )
        )

        raise ValueError(
            "Analysis contains ungrounded host "
            f"reference(s): {joined_hosts}"
        )


def make_analyze_alert_node(
    analyzer: Analyzer,
):
    def analyze_alert(
        state: InvestigationState,
    ) -> InvestigationState:
        evidence_records = state.get(
            "evidence_records",
            [],
        )

        context = build_analysis_context(
            state
        )

        analysis = analyzer(
            context
        )

        validate_evidence_references(
            analysis,
            evidence_records,
        )

        validate_grounded_entities(
            analysis,
            evidence_records,
        )

        return {
            "analysis": analysis,
            "status": "analyzed",
        }

    return analyze_alert