import json
import zipfile
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator


@dataclass(frozen=True)
class LIDDS2021Record:
    label: str
    source_dataset: str
    source_row_id: str
    raw_label: str
    fields: dict[str, object]


def iter_lid_ds_2021_records(
    root_path: str | Path,
) -> Iterator[LIDDS2021Record]:
    root = Path(root_path)

    for archive_path in sorted(
        root.rglob("*.zip")
    ):
        with zipfile.ZipFile(
            archive_path
        ) as archive:
            json_names = [
                name
                for name in archive.namelist()
                if name.endswith(".json")
            ]

            if not json_names:
                continue

            metadata = json.loads(
                archive.read(
                    json_names[0]
                )
            )

        relative_path = (
            archive_path
            .relative_to(root)
            .as_posix()
        )

        if not metadata.get(
            "exploit",
            False,
        ):
            yield LIDDS2021Record(
                label="benign",
                source_dataset="lid_ds_2021",
                source_row_id=(
                    f"{relative_path}:normal"
                ),
                raw_label="normal",
                fields=metadata,
            )
            continue

        path_parts = set(
            archive_path.parts
        )

        if (
            "Bruteforce_CWE-307"
            in path_parts
        ):
            exploit_events = (
                metadata
                .get("time", {})
                .get("exploit", [])
            )

            for event_index, event in enumerate(
                exploit_events
            ):
                if (
                    event.get("name")
                    == "attack"
                    and event.get("source")
                    == "SYSDIG"
                ):
                    yield LIDDS2021Record(
                        label="brute_force",
                        source_dataset=(
                            "lid_ds_2021"
                        ),
                        source_row_id=(
                            f"{relative_path}"
                            f":exploit:"
                            f"{event_index}"
                        ),
                        raw_label=(
                            "Bruteforce_CWE-307"
                        ),
                        fields=metadata,
                    )

            continue

        if (
            "CVE-2017-12635_6"
            in path_parts
        ):
            exploit_events = (
                metadata
                .get("time", {})
                .get("exploit", [])
            )

            for event_index, event in enumerate(
                exploit_events
            ):
                if (
                    event.get("name")
                    == "privilege-escalation"
                    and event.get("source")
                    == "SYSDIG"
                ):
                    yield LIDDS2021Record(
                        label=(
                            "privilege_misuse"
                        ),
                        source_dataset=(
                            "lid_ds_2021"
                        ),
                        source_row_id=(
                            f"{relative_path}"
                            f":exploit:"
                            f"{event_index}"
                        ),
                        raw_label=(
                            "privilege-escalation"
                        ),
                        fields=metadata,
                    )