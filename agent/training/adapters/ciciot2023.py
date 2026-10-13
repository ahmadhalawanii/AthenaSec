import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


_CICIOT2023_LABEL_MAP = {
    "BENIGN": "benign",
    "DICTIONARYBRUTEFORCE": "brute_force",
}


@dataclass(frozen=True)
class CICIoT2023Record:
    label: str
    source_dataset: str
    source_row_id: str
    raw_label: str
    fields: dict[str, str]


def map_ciciot2023_label(
    raw_label: str,
) -> str | None:
    normalized = raw_label.strip()

    return _CICIOT2023_LABEL_MAP.get(
        normalized
    )


def iter_ciciot2023_records(
    csv_path: str | Path,
) -> Iterator[CICIoT2023Record]:
    path = Path(csv_path)

    with path.open(
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as handle:
        reader = csv.DictReader(handle)

        if reader.fieldnames is None:
            return

        reader.fieldnames = [
            field_name.strip()
            for field_name in reader.fieldnames
        ]

        for row_number, fields in enumerate(
            reader,
            start=1,
        ):
            raw_label = fields.get(
                "Label"
            )

            if raw_label is None:
                continue

            label = map_ciciot2023_label(
                raw_label
            )

            if label is None:
                continue

            yield CICIoT2023Record(
                label=label,
                source_dataset="cic_iot_2023",
                source_row_id=(
                    f"{path.name}:{row_number}"
                ),
                raw_label=raw_label,
                fields=dict(fields),
            )