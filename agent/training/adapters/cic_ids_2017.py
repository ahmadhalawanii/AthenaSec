import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


_CIC2017_LABEL_MAP = {
    "BENIGN": "benign",
    "FTP-Patator": "brute_force",
    "SSH-Patator": "brute_force",
}


@dataclass(frozen=True)
class CIC2017Record:
    label: str
    source_dataset: str
    source_row_id: str
    raw_label: str
    fields: dict[str, str]


def map_cic2017_label(
    raw_label: str,
) -> str | None:
    normalized = raw_label.strip()

    return _CIC2017_LABEL_MAP.get(
        normalized
    )


def iter_cic2017_records(
    csv_path: str | Path,
) -> Iterator[CIC2017Record]:
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
                "Label",
                "",
            )

            label = map_cic2017_label(
                raw_label
            )

            if label is None:
                continue

            yield CIC2017Record(
                label=label,
                source_dataset="cic_ids_2017",
                source_row_id=(
                    f"{path.name}:{row_number}"
                ),
                raw_label=raw_label,
                fields=dict(fields),
            )