import hashlib
import re
from dataclasses import dataclass
from typing import Iterable, TypeAlias

from training.adapters.adfa_ld import (
    ADFARecord,
)
from training.adapters.cic_ids_2017 import (
    CIC2017Record,
)
from training.adapters.cic_ids_2018 import (
    CIC2018Record,
)
from training.adapters.cmu_insider import (
    CMUInsiderScenario,
)
from training.wazuh_lab_scenarios import (
    prepare_scenario_run,
)


ExternalBehaviorRecord: TypeAlias = (
    CIC2017Record
    | CIC2018Record
    | ADFARecord
    | CMUInsiderScenario
)


_SCENARIO_NAMES_BY_LABEL = {
    "brute_force": (
        "ssh_invalid_user_bruteforce",
        "ssh_root_password_bruteforce",
        "ssh_root_none_bruteforce",
    ),
    "privilege_misuse": (
        "sudo_three_failed_attempts",
        "sudo_unauthorized_user",
        "sudo_command_not_allowed",
        "user_added_to_sudo_group",
    ),
    "benign": (
        "ssh_authentication_success",
        "sudo_non_privileged_success",
        "pam_login_session_opened",
    ),
}


@dataclass(frozen=True)
class BehaviorReplay:
    label: str
    source_dataset: str
    source_row_id: str
    source_behavior: str
    scenario_name: str


def scenario_names_for_label(
    label: str,
) -> tuple[str, ...]:
    try:
        return _SCENARIO_NAMES_BY_LABEL[
            label
        ]
    except KeyError as exc:
        raise ValueError(
            f"Unsupported training label: "
            f"{label}"
        ) from exc


def _stable_scenario_index(
    *,
    label: str,
    source_dataset: str,
    source_row_id: str,
    source_behavior: str,
    seed: int,
    scenario_count: int,
) -> int:
    selection_key = (
        f"{seed}|"
        f"{label}|"
        f"{source_dataset}|"
        f"{source_row_id}|"
        f"{source_behavior}"
    )

    digest = hashlib.sha256(
        selection_key.encode(
            "utf-8"
        )
    ).hexdigest()

    return (
        int(
            digest,
            16,
        )
        % scenario_count
    )


def build_behavior_replay(
    *,
    label: str,
    source_dataset: str,
    source_row_id: str,
    source_behavior: str,
    seed: int,
) -> BehaviorReplay:
    scenario_names = (
        scenario_names_for_label(
            label
        )
    )

    scenario_index = (
        _stable_scenario_index(
            label=label,
            source_dataset=source_dataset,
            source_row_id=source_row_id,
            source_behavior=source_behavior,
            seed=seed,
            scenario_count=len(
                scenario_names
            ),
        )
    )

    return BehaviorReplay(
        label=label,
        source_dataset=source_dataset,
        source_row_id=source_row_id,
        source_behavior=source_behavior,
        scenario_name=(
            scenario_names[
                scenario_index
            ]
        ),
    )


def build_behavior_replay_from_record(
    record: ExternalBehaviorRecord,
    *,
    seed: int,
) -> BehaviorReplay:
    if isinstance(
        record,
        CIC2017Record,
    ):
        source_behavior = (
            record.raw_label
        )

    elif isinstance(
        record,
        CIC2018Record,
    ):
        source_behavior = (
            record.raw_label
        )

    elif isinstance(
        record,
        ADFARecord,
    ):
        source_behavior = (
            record.raw_family
        )

    elif isinstance(
        record,
        CMUInsiderScenario,
    ):
        source_behavior = (
            f"scenario_"
            f"{record.scenario}"
        )

    else:
        raise TypeError(
            "Unsupported external "
            "behavior record: "
            f"{type(record).__name__}"
        )

    return build_behavior_replay(
        label=record.label,
        source_dataset=(
            record.source_dataset
        ),
        source_row_id=(
            record.source_row_id
        ),
        source_behavior=(
            source_behavior
        ),
        seed=seed,
    )


def behavior_family_for_record(
    record: ExternalBehaviorRecord,
) -> str:
    if isinstance(
        record,
        CIC2017Record,
    ):
        return record.raw_label

    if isinstance(
        record,
        CIC2018Record,
    ):
        return record.raw_label

    if isinstance(
        record,
        ADFARecord,
    ):
        return re.sub(
            r"_\d+$",
            "",
            record.raw_family,
        )

    if isinstance(
        record,
        CMUInsiderScenario,
    ):
        return (
            f"scenario_"
            f"{record.scenario}"
        )

    raise TypeError(
        "Unsupported external "
        "behavior record: "
        f"{type(record).__name__}"
    )


def _sampling_rank(
    record: ExternalBehaviorRecord,
    *,
    seed: int,
) -> str:
    family = (
        behavior_family_for_record(
            record
        )
    )

    ranking_key = (
        f"{seed}|"
        f"{record.source_dataset}|"
        f"{record.label}|"
        f"{family}|"
        f"{record.source_row_id}"
    )

    return hashlib.sha256(
        ranking_key.encode(
            "utf-8"
        )
    ).hexdigest()


def sample_behavior_records(
    records: Iterable[
        ExternalBehaviorRecord
    ],
    *,
    per_group_limit: int,
    seed: int,
) -> list[ExternalBehaviorRecord]:
    if per_group_limit <= 0:
        raise ValueError(
            "per_group_limit must be positive"
        )

    groups: dict[
        tuple[str, str, str],
        list[ExternalBehaviorRecord],
    ] = {}

    for record in records:
        family = (
            behavior_family_for_record(
                record
            )
        )

        group_key = (
            record.source_dataset,
            record.label,
            family,
        )

        groups.setdefault(
            group_key,
            [],
        ).append(
            record
        )

    sampled: list[
        ExternalBehaviorRecord
    ] = []

    for group_key in sorted(
        groups
    ):
        ranked_records = sorted(
            groups[group_key],
            key=lambda record: (
                _sampling_rank(
                    record,
                    seed=seed,
                ),
                record.source_row_id,
            ),
        )

        sampled.extend(
            ranked_records[
                :per_group_limit
            ]
        )

    return sampled

def build_behavior_manifest(
    records: Iterable[
        ExternalBehaviorRecord
    ],
    *,
    per_group_limit: int,
    seed: int,
) -> list[BehaviorReplay]:
    sampled_records = (
        sample_behavior_records(
            records,
            per_group_limit=(
                per_group_limit
            ),
            seed=seed,
        )
    )

    return [
        build_behavior_replay_from_record(
            record,
            seed=seed,
        )
        for record in sampled_records
    ]

def prepare_behavior_replay_run(
    replay: BehaviorReplay,
    *,
    container_name: str,
    log_path: str,
) -> dict[str, str]:
    run = prepare_scenario_run(
        name=replay.scenario_name,
        container_name=container_name,
        log_path=log_path,
    )

    if run["label"] != replay.label:
        raise ValueError(
            "Wazuh scenario label mismatch: "
            f"manifest label={replay.label}, "
            f"scenario label={run['label']}"
        )

    return {
        **run,
        "wazuh_source_dataset": (
            run["source_dataset"]
        ),
        "wazuh_source_row_id": (
            run["source_row_id"]
        ),
        "label": replay.label,
        "source_dataset": (
            replay.source_dataset
        ),
        "source_row_id": (
            replay.source_row_id
        ),
        "source_behavior": (
            replay.source_behavior
        ),
    }