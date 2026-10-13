from dataclasses import dataclass
from random import Random

from training.data_contract import (
    TrainingRow,
    training_feature_vector,
)


ProvenanceKey = tuple[str, str]
Component = list[ProvenanceKey]


@dataclass(frozen=True)
class DatasetSplit:
    train: list[TrainingRow]
    validation: list[TrainingRow]
    test: list[TrainingRow]


def _provenance_key(
    row: TrainingRow,
) -> ProvenanceKey:
    return (
        row.source_dataset,
        row.source_row_id,
    )


def _build_components(
    rows: list[TrainingRow],
) -> tuple[
    dict[
        ProvenanceKey,
        list[TrainingRow],
    ],
    dict[
        str,
        list[Component],
    ],
]:
    grouped_rows: dict[
        ProvenanceKey,
        list[TrainingRow],
    ] = {}

    for row in rows:
        grouped_rows.setdefault(
            _provenance_key(row),
            [],
        ).append(row)

    for group in grouped_rows.values():
        labels = {
            row.label
            for row in group
        }

        if len(labels) != 1:
            raise ValueError(
                "Rows sharing the same "
                "provenance group must have "
                "the same label."
            )

    parent = {
        key: key
        for key in grouped_rows
    }

    def find(
        key: ProvenanceKey,
    ) -> ProvenanceKey:
        root = key

        while parent[root] != root:
            root = parent[root]

        while parent[key] != key:
            next_key = parent[key]
            parent[key] = root
            key = next_key

        return root

    def union(
        left: ProvenanceKey,
        right: ProvenanceKey,
    ) -> None:
        left_root = find(left)
        right_root = find(right)

        if left_root != right_root:
            parent[right_root] = left_root

    vector_owner: dict[
        tuple[object, ...],
        ProvenanceKey,
    ] = {}

    for row in rows:
        group_key = _provenance_key(
            row
        )

        feature_key = tuple(
            training_feature_vector(
                row
            )
        )

        previous_group = (
            vector_owner.get(
                feature_key
            )
        )

        if previous_group is None:
            vector_owner[
                feature_key
            ] = group_key
        else:
            union(
                previous_group,
                group_key,
            )

    components: dict[
        ProvenanceKey,
        Component,
    ] = {}

    for group_key in grouped_rows:
        root = find(
            group_key
        )

        components.setdefault(
            root,
            [],
        ).append(
            group_key
        )

    components_by_label: dict[
        str,
        list[Component],
    ] = {}

    for component in (
        components.values()
    ):
        labels = {
            row.label
            for group_key in component
            for row in (
                grouped_rows[
                    group_key
                ]
            )
        }

        if len(labels) != 1:
            raise ValueError(
                "Connected provenance and "
                "feature-vector components "
                "must have the same label."
            )

        label = next(
            iter(labels)
        )

        components_by_label.setdefault(
            label,
            [],
        ).append(
            component
        )

    return (
        grouped_rows,
        components_by_label,
    )


def _allocate_components(
    components: list[Component],
    *,
    grouped_rows: dict[
        ProvenanceKey,
        list[TrainingRow],
    ],
    rng: Random,
) -> tuple[
    list[Component],
    list[Component],
    list[Component],
]:
    if len(components) < 3:
        raise ValueError(
            "Each class must contain at "
            "least three independent "
            "provenance/feature components."
        )

    ordered = sorted(
        components,
        key=lambda component: tuple(
            sorted(component)
        ),
    )

    rng.shuffle(
        ordered
    )

    component_weights = {
        tuple(component): len(
            {
                tuple(
                    training_feature_vector(
                        row
                    )
                )
                for group_key in component
                for row in grouped_rows[
                    group_key
                ]
            }
        )
        for component in ordered
    }

    total_weight = sum(
        component_weights[
            tuple(component)
        ]
        for component in ordered
    )

    states: dict[
        tuple[int, int],
        tuple[int, ...],
    ] = {
        (0, 0): (),
    }

    for component in ordered:
        weight = component_weights[
            tuple(component)
        ]

        next_states: dict[
            tuple[int, int],
            tuple[int, ...],
        ] = {}

        for (
            train_weight,
            validation_weight,
        ), assignment in (
            states.items()
        ):
            candidates = (
                (
                    (
                        train_weight
                        + weight,
                        validation_weight,
                    ),
                    assignment + (0,),
                ),
                (
                    (
                        train_weight,
                        validation_weight
                        + weight,
                    ),
                    assignment + (1,),
                ),
                (
                    (
                        train_weight,
                        validation_weight,
                    ),
                    assignment + (2,),
                ),
            )

            for (
                state_key,
                state_assignment,
            ) in candidates:
                next_states.setdefault(
                    state_key,
                    state_assignment,
                )

        states = next_states

    target_train = (
        total_weight
        * 0.70
    )

    target_validation = (
        total_weight
        * 0.15
    )

    target_test = (
        total_weight
        * 0.15
    )

    choices = []

    for (
        train_weight,
        validation_weight,
    ), assignment in (
        states.items()
    ):
        test_weight = (
            total_weight
            - train_weight
            - validation_weight
        )

        if (
            train_weight == 0
            or validation_weight == 0
            or test_weight == 0
        ):
            continue

        deviations = (
            abs(
                train_weight
                - target_train
            ),
            abs(
                validation_weight
                - target_validation
            ),
            abs(
                test_weight
                - target_test
            ),
        )

        score = (
            max(deviations),
            sum(deviations),
            abs(
                validation_weight
                - test_weight
            ),
            assignment,
        )

        choices.append(
            (
                score,
                assignment,
            )
        )

    if not choices:
        raise ValueError(
            "Unable to create a "
            "provenance and feature-safe "
            "70/15/15 split."
        )

    assignment = min(
        choices,
        key=lambda item: item[0],
    )[1]

    train_components = [
        component
        for component, destination
        in zip(
            ordered,
            assignment,
            strict=True,
        )
        if destination == 0
    ]

    validation_components = [
        component
        for component, destination
        in zip(
            ordered,
            assignment,
            strict=True,
        )
        if destination == 1
    ]

    test_components = [
        component
        for component, destination
        in zip(
            ordered,
            assignment,
            strict=True,
        )
        if destination == 2
    ]

    return (
        train_components,
        validation_components,
        test_components,
    )


def _expand_components(
    components: list[Component],
    grouped_rows: dict[
        ProvenanceKey,
        list[TrainingRow],
    ],
) -> list[TrainingRow]:
    return [
        row
        for component in components
        for group_key in component
        for row in grouped_rows[
            group_key
        ]
    ]


def split_rows(
    rows: list[TrainingRow],
    random_state: int = 42,
) -> DatasetSplit:
    if not rows:
        raise ValueError(
            "Training rows must not be empty."
        )

    (
        grouped_rows,
        components_by_label,
    ) = _build_components(
        rows
    )

    rng = Random(
        random_state
    )

    train_components: list[
        Component
    ] = []

    validation_components: list[
        Component
    ] = []

    test_components: list[
        Component
    ] = []

    for label in sorted(
        components_by_label
    ):
        (
            label_train,
            label_validation,
            label_test,
        ) = _allocate_components(
            components_by_label[
                label
            ],
            grouped_rows=grouped_rows,
            rng=rng,
        )

        train_components.extend(
            label_train
        )

        validation_components.extend(
            label_validation
        )

        test_components.extend(
            label_test
        )

    return DatasetSplit(
        train=_expand_components(
            train_components,
            grouped_rows,
        ),
        validation=_expand_components(
            validation_components,
            grouped_rows,
        ),
        test=_expand_components(
            test_components,
            grouped_rows,
        ),
    )


def leave_one_dataset_out(
    rows: list[TrainingRow],
    held_out_dataset: str,
) -> tuple[
    list[TrainingRow],
    list[TrainingRow],
]:
    training_rows = [
        row
        for row in rows
        if (
            row.source_dataset
            != held_out_dataset
        )
    ]

    held_out_rows = [
        row
        for row in rows
        if (
            row.source_dataset
            == held_out_dataset
        )
    ]

    return (
        training_rows,
        held_out_rows,
    )