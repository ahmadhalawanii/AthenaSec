from training.data_contract import (
    TrainingRow,
)
from training.deduplication import (
    deduplicate_rows,
)


def make_row(
    *,
    label="brute_force",
    source_dataset="fixture",
    source_row_id="1",
    failed_attempts=5,
):
    return TrainingRow(
        rule_level=10,
        rule_frequency=12,
        failed_attempts=failed_attempts,
        privileged_target=1,
        source_port=54321,
        destination_port=22,
        has_source_ip=1,
        has_target_user=1,
        has_agent=1,
        mitre_id_count=2,
        rule_group_count=3,
        is_sudo_event=0,
        is_account_change_event=0,
        is_privilege_group_change=0,
        has_command=0,
        label=label,
        source_dataset=source_dataset,
        source_row_id=source_row_id,
    )


def test_exact_duplicate_is_removed():
    rows = [
        make_row(
            source_row_id="1",
        ),
        make_row(
            source_row_id="2",
        ),
    ]

    deduplicated, duplicate_count = (
        deduplicate_rows(
            rows
        )
    )

    assert len(
        deduplicated
    ) == 1

    assert duplicate_count == 1


def test_first_duplicate_occurrence_is_preserved():
    first = make_row(
        source_dataset="cic2017",
        source_row_id="first",
    )

    second = make_row(
        source_dataset="cic2018",
        source_row_id="second",
    )

    deduplicated, _ = deduplicate_rows(
        [
            first,
            second,
        ]
    )

    assert deduplicated == [
        first,
    ]


def test_different_labels_are_not_collapsed():
    rows = [
        make_row(
            label="brute_force",
            source_row_id="1",
        ),
        make_row(
            label="benign",
            source_row_id="2",
        ),
    ]

    deduplicated, duplicate_count = (
        deduplicate_rows(
            rows
        )
    )

    assert len(
        deduplicated
    ) == 2

    assert duplicate_count == 0


def test_different_feature_values_are_not_duplicates():
    rows = [
        make_row(
            failed_attempts=5,
            source_row_id="1",
        ),
        make_row(
            failed_attempts=6,
            source_row_id="2",
        ),
    ]

    deduplicated, duplicate_count = (
        deduplicate_rows(
            rows
        )
    )

    assert len(
        deduplicated
    ) == 2

    assert duplicate_count == 0


def test_source_metadata_does_not_prevent_duplicate_detection():
    rows = [
        make_row(
            source_dataset="cic2017",
            source_row_id="101",
        ),
        make_row(
            source_dataset="cmu",
            source_row_id="999",
        ),
    ]

    deduplicated, duplicate_count = (
        deduplicate_rows(
            rows
        )
    )

    assert len(
        deduplicated
    ) == 1

    assert duplicate_count == 1