from training.data_contract import TrainingRow
from training.splitting import (
    leave_one_dataset_out,
    split_rows,
)


def make_rows(
    *,
    count_per_class=20,
    source_dataset="fixture",
):
    rows = []

    classes = [
        "benign",
        "brute_force",
        "privilege_misuse",
    ]

    counter = 0

    for label in classes:
        for index in range(
            count_per_class
        ):
            counter += 1

            rows.append(
                TrainingRow(
                    rule_level=(
                        1
                        + (index % 10)
                    ),
                    rule_frequency=(
                        1
                        + (index % 7)
                    ),
                    failed_attempts=(
                        index
                        if (
                            label
                            == "brute_force"
                        )
                        else 0
                    ),
                    privileged_target=(
                        1
                        if (
                            label
                            == "privilege_misuse"
                        )
                        else 0
                    ),
                    source_port=(
                        10000
                        + counter
                    ),
                    destination_port=(
                        22
                        if (
                            label
                            == "brute_force"
                        )
                        else 443
                    ),
                    has_source_ip=1,
                    has_target_user=1,
                    has_agent=1,
                    mitre_id_count=1,
                    rule_group_count=2,
                    is_sudo_event=(
                        1
                        if label
                        == "privilege_misuse"
                        else 0
                    ),
                    is_account_change_event=0,
                    is_privilege_group_change=0,
                    has_command=(
                        1
                        if label
                        == "privilege_misuse"
                        else 0
                    ),
                    label=label,
                    source_dataset=(
                        source_dataset
                    ),
                    source_row_id=str(
                        counter
                    ),
                )
            )

    return rows


def test_split_is_reproducible_with_same_seed():
    rows = make_rows()

    first = split_rows(
        rows,
        random_state=42,
    )

    second = split_rows(
        rows,
        random_state=42,
    )

    assert first == second


def test_split_has_no_overlap():
    rows = make_rows()

    split = split_rows(
        rows,
        random_state=42,
    )

    train_ids = {
        row.source_row_id
        for row in split.train
    }

    validation_ids = {
        row.source_row_id
        for row in split.validation
    }

    test_ids = {
        row.source_row_id
        for row in split.test
    }

    assert train_ids.isdisjoint(
        validation_ids
    )

    assert train_ids.isdisjoint(
        test_ids
    )

    assert validation_ids.isdisjoint(
        test_ids
    )


def test_split_is_approximately_70_15_15():
    rows = make_rows(
        count_per_class=40
    )

    split = split_rows(
        rows,
        random_state=42,
    )

    total = len(
        rows
    )

    assert abs(
        len(split.train)
        / total
        - 0.70
    ) < 0.03

    assert abs(
        len(split.validation)
        / total
        - 0.15
    ) < 0.03

    assert abs(
        len(split.test)
        / total
        - 0.15
    ) < 0.03


def test_all_classes_are_represented_in_each_split():
    rows = make_rows(
        count_per_class=20
    )

    split = split_rows(
        rows,
        random_state=42,
    )

    expected = {
        "benign",
        "brute_force",
        "privilege_misuse",
    }

    assert {
        row.label
        for row in split.train
    } == expected

    assert {
        row.label
        for row in split.validation
    } == expected

    assert {
        row.label
        for row in split.test
    } == expected


def test_leave_one_dataset_out_isolates_dataset():
    rows = (
        make_rows(
            count_per_class=5,
            source_dataset=(
                "cic_ids_2017"
            ),
        )
        + make_rows(
            count_per_class=5,
            source_dataset=(
                "cic_ids_2018"
            ),
        )
    )

    training_rows, held_out_rows = (
        leave_one_dataset_out(
            rows,
            held_out_dataset=(
                "cic_ids_2018"
            ),
        )
    )

    assert all(
        row.source_dataset
        != "cic_ids_2018"
        for row in training_rows
    )

    assert all(
        row.source_dataset
        == "cic_ids_2018"
        for row in held_out_rows
    )

    assert (
        len(training_rows)
        + len(held_out_rows)
        == len(rows)
    )

def test_split_keeps_same_provenance_group_together():
    from dataclasses import replace

    base_rows = make_rows(
        count_per_class=20
    )

    rows = []

    for row in base_rows:
        rows.extend(
            [
                row,
                replace(
                    row,
                    source_port=(
                        row.source_port
                        + 100000
                    ),
                ),
                replace(
                    row,
                    source_port=(
                        row.source_port
                        + 200000
                    ),
                ),
                replace(
                    row,
                    source_port=(
                        row.source_port
                        + 300000
                    ),
                ),
            ]
        )

    split = split_rows(
        rows,
        random_state=42,
    )

    train_groups = {
        (
            row.source_dataset,
            row.source_row_id,
        )
        for row in split.train
    }

    validation_groups = {
        (
            row.source_dataset,
            row.source_row_id,
        )
        for row in split.validation
    }

    test_groups = {
        (
            row.source_dataset,
            row.source_row_id,
        )
        for row in split.test
    }

    assert train_groups.isdisjoint(
        validation_groups
    )

    assert train_groups.isdisjoint(
        test_groups
    )

    assert validation_groups.isdisjoint(
        test_groups
    )


def test_split_keeps_identical_feature_vectors_together():
    from dataclasses import replace

    from training.data_contract import (
        training_feature_vector,
    )

    base_rows = make_rows(
        count_per_class=20
    )

    rows = []

    for row in base_rows:
        rows.extend(
            [
                row,
                replace(
                    row,
                    source_row_id=(
                        f"{row.source_row_id}"
                        "-duplicate"
                    ),
                ),
            ]
        )

    split = split_rows(
        rows,
        random_state=42,
    )

    train_vectors = {
        tuple(
            training_feature_vector(row)
        )
        for row in split.train
    }

    validation_vectors = {
        tuple(
            training_feature_vector(row)
        )
        for row in split.validation
    }

    test_vectors = {
        tuple(
            training_feature_vector(row)
        )
        for row in split.test
    }

    assert train_vectors.isdisjoint(
        validation_vectors
    )

    assert train_vectors.isdisjoint(
        test_vectors
    )

    assert validation_vectors.isdisjoint(
        test_vectors
    )

def test_split_keeps_majority_feature_diversity_in_training():
    from dataclasses import replace

    from training.data_contract import (
        training_feature_vector,
    )

    base_rows = make_rows(
        count_per_class=1
    )

    rows = []

    for base_row in base_rows:
        label = base_row.label

        # One large provenance component with
        # many records but only one feature vector.
        for index in range(14):
            rows.append(
                replace(
                    base_row,
                    source_row_id=(
                        f"{label}-low-"
                        f"{index}"
                    ),
                )
            )

        # Three small provenance components,
        # each containing four unique vectors.
        for component_index in range(3):
            source_row_id = (
                f"{label}-high-"
                f"{component_index}"
            )

            for variant_index in range(4):
                rows.append(
                    replace(
                        base_row,
                        source_row_id=(
                            source_row_id
                        ),
                        source_port=(
                            base_row.source_port
                            + (
                                100000
                                * (
                                    component_index
                                    + 1
                                )
                            )
                            + variant_index
                            + 1
                        ),
                    )
                )

    split = split_rows(
        rows,
        random_state=42,
    )

    def unique_vector_count(
        split_rows,
        label,
    ):
        return len(
            {
                tuple(
                    training_feature_vector(
                        row
                    )
                )
                for row in split_rows
                if row.label == label
            }
        )

    for label in (
        "benign",
        "brute_force",
        "privilege_misuse",
    ):
        train_count = (
            unique_vector_count(
                split.train,
                label,
            )
        )

        validation_count = (
            unique_vector_count(
                split.validation,
                label,
            )
        )

        test_count = (
            unique_vector_count(
                split.test,
                label,
            )
        )

        assert train_count >= (
            validation_count
            + test_count
        )
