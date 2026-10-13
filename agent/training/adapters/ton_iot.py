import csv
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


_TON_IOT_LABEL_MAP = {
    "normal": "benign",
    "password": "brute_force",
}


@dataclass(frozen=True)
class ToNIoTRecord:
    label: str
    source_dataset: str
    source_row_id: str
    raw_label: str
    fields: dict[str, str]


def map_ton_iot_label(
    raw_label: str,
) -> str | None:
    normalized = raw_label.strip()

    return _TON_IOT_LABEL_MAP.get(
        normalized
    )


def iter_ton_iot_records(
    csv_path: str | Path,
) -> Iterator[ToNIoTRecord]:
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
                "type",
                "",
            )

            label = map_ton_iot_label(
                raw_label
            )

            if label is None:
                continue

            yield ToNIoTRecord(
                label=label,
                source_dataset="ton_iot",
                source_row_id=(
                    f"{path.name}:{row_number}"
                ),
                raw_label=raw_label,
                fields=dict(fields),
            )