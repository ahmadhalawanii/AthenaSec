import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


_ADFA_ATTACK_MAP = {
    "Hydra_FTP": "brute_force",
    "Hydra_SSH": "brute_force",
    "Adduser": "privilege_misuse",
}


@dataclass(frozen=True)
class ADFARecord:
    label: str
    source_dataset: str
    source_row_id: str
    raw_family: str
    trace: str


def _normalize_attack_family(
    raw_family: str,
) -> str:
    normalized = raw_family.strip()

    return re.sub(
        r"_\d+$",
        "",
        normalized,
    )


def map_adfa_attack_family(
    raw_family: str,
) -> str | None:
    normalized = _normalize_attack_family(
        raw_family
    )

    return _ADFA_ATTACK_MAP.get(
        normalized
    )


def _classify_trace_path(
    root: Path,
    trace_path: Path,
) -> tuple[str, str] | None:
    relative_path = trace_path.relative_to(
        root
    )

    if not relative_path.parts:
        return None

    top_level = relative_path.parts[0]

    if top_level in {
        "Training_Data_Master",
        "Validation_Data_Master",
    }:
        return (
            "benign",
            top_level,
        )

    if (
        top_level
        != "Attack_Data_Master"
        or len(relative_path.parts) < 3
    ):
        return None

    raw_family = relative_path.parts[1]

    label = map_adfa_attack_family(
        raw_family
    )

    if label is None:
        return None

    return (
        label,
        raw_family,
    )


def iter_adfa_records(
    root_path: str | Path,
) -> Iterator[ADFARecord]:
    root = Path(root_path)

    for trace_path in sorted(
        root.rglob("*.txt")
    ):
        classification = (
            _classify_trace_path(
                root,
                trace_path,
            )
        )

        if classification is None:
            continue

        label, raw_family = classification

        relative_path = (
            trace_path
            .relative_to(root)
            .as_posix()
        )

        trace = trace_path.read_text(
            encoding="utf-8"
        )

        yield ADFARecord(
            label=label,
            source_dataset="adfa_ld",
            source_row_id=relative_path,
            raw_family=raw_family,
            trace=trace,
        )