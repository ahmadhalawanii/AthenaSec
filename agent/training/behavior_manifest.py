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

    if (
        isinstance(
            record,
            ADFARecord,
        )
        and behavior_family_for_record(
            record
        )
        == "Adduser"
    ):
        return BehaviorReplay(
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
            scenario_name=(
                "user_added_to_sudo_group"
            ),
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

    unsupported_families = {
        "FTP-Patator",
        "FTP-BruteForce",
        "Hydra_FTP",
    }

    return [
        build_behavior_replay_from_record(
            record,
            seed=seed,
        )
        for record in sampled_records
        if behavior_family_for_record(
            record
        )
        not in unsupported_families
    ]

def behavior_replay_variation(
    replay: BehaviorReplay,
    *,
    variant_index: int = 0,
) -> dict[str, str]:
    variation_key = (
        f"{replay.label}|"
        f"{replay.source_dataset}|"
        f"{replay.source_row_id}|"
        f"{replay.source_behavior}|"
        f"{replay.scenario_name}"
    )

    digest = hashlib.sha256(
        variation_key.encode(
            "utf-8"
        )
    ).digest()

    if replay.scenario_name.startswith(
        "ssh_"
    ):
        source_ip = (
            f"198."
            f"{18 + (digest[0] % 2)}."
            f"{digest[1]}."
            f"{1 + (digest[2] % 254)}"
        )

        source_port = (
            49152
            + (
                int.from_bytes(
                    digest[3:5],
                    byteorder="big",
                )
                % 16384
            )
        )

        return {
            "source_ip": source_ip,
            "source_port": str(
                source_port
            ),
        }

    sudo_misuse_scenarios = {
        "sudo_three_failed_attempts",
        "sudo_unauthorized_user",
        "sudo_command_not_allowed",
    }

    if (
        replay.scenario_name
        in sudo_misuse_scenarios
    ):
        baseline_index = (
            (
                0
                if digest[0] % 2 == 0
                else 2
            )
            + (
                0
                if digest[1] % 2 == 0
                else 1
            )
        )

        combination_index = (
            baseline_index
            + variant_index
        ) % 4

        combinations = (
            ("root", "true"),
            ("root", "false"),
            ("backupuser", "true"),
            ("backupuser", "false"),
        )

        (
            target_user,
            include_command,
        ) = combinations[
            combination_index
        ]

        return {
            "target_user": target_user,
            "include_command": (
                include_command
            ),
        }

    return {}


def prepare_behavior_replay_run(
    replay: BehaviorReplay,
    *,
    container_name: str,
    log_path: str,
    variant_index: int = 0,
) -> dict[str, str | int]:
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

    variation = (
        behavior_replay_variation(
            replay,
            variant_index=variant_index,
        )
    )

    if (
        "source_ip"
        in variation
    ):
        source_ip = variation[
            "source_ip"
        ]

        source_port = variation[
            "source_port"
        ]

        injection_command = (
            run["injection_command"]
            .replace(
                (
                    f"from "
                    f"{run['source_ip']} "
                ),
                (
                    f"from "
                    f"{source_ip} "
                ),
            )
        )

        injection_command = re.sub(
            r" port \d+ ssh2",
            (
                f" port "
                f"{source_port} ssh2"
            ),
            injection_command,
            count=1,
        )

        run = {
            **run,
            "source_ip": source_ip,
            "injection_command": (
                injection_command
            ),
        }

    if (
        "target_user"
        in variation
    ):
        target_user = variation[
            "target_user"
        ]

        injection_command = (
            run["injection_command"]
            .replace(
                "USER=root",
                f"USER={target_user}",
            )
        )

        if (
            variation[
                "include_command"
            ]
            == "false"
        ):
            injection_command = (
                injection_command
                .replace(
                    " ; COMMAND=/bin/bash",
                    "",
                )
            )

        run = {
            **run,
            "injection_command": (
                injection_command
            ),
        }

    return {
        **run,
        "variant_index": variant_index,
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
