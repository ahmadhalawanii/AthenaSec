import csv
import io
import tarfile

from training.adapters import cmu_insider
from training.adapters.cmu_insider import (
    map_cmu_scenario,
)


def test_r42_scenario_3_maps_to_privilege_misuse():
    assert (
        map_cmu_scenario(
            dataset="4.2",
            scenario=3,
        )
        == "privilege_misuse"
    )


def test_r42_scenario_1_is_ignored():
    assert (
        map_cmu_scenario(
            dataset="4.2",
            scenario=1,
        )
        is None
    )


def test_r42_scenario_2_is_ignored():
    assert (
        map_cmu_scenario(
            dataset="4.2",
            scenario=2,
        )
        is None
    )


def test_other_dataset_release_is_ignored():
    assert (
        map_cmu_scenario(
            dataset="5.2",
            scenario=3,
        )
        is None
    )


def test_string_scenario_is_supported():
    assert (
        map_cmu_scenario(
            dataset="4.2",
            scenario="3",
        )
        == "privilege_misuse"
    )


def test_dataset_whitespace_is_normalized():
    assert (
        map_cmu_scenario(
            dataset=" 4.2 ",
            scenario=3,
        )
        == "privilege_misuse"
    )


def _write_csv_member(
    tar,
    name,
    rows,
):
    buffer = io.StringIO()

    writer = csv.writer(buffer)
    writer.writerows(rows)

    data = buffer.getvalue().encode(
        "utf-8"
    )

    info = tarfile.TarInfo(
        name=name
    )
    info.size = len(data)

    tar.addfile(
        info,
        io.BytesIO(data),
    )


def test_iter_cmu_scenarios_uses_insiders_ground_truth(
    tmp_path,
):
    archive_path = (
        tmp_path
        / "answers.tar.bz2"
    )

    with tarfile.open(
        archive_path,
        mode="w:bz2",
    ) as tar:
        _write_csv_member(
            tar,
            "answers/insiders.csv",
            [
                [
                    "dataset",
                    "scenario",
                    "details",
                    "user",
                    "start",
                    "end",
                ],
                [
                    "4.2",
                    "3",
                    "r4.2-3-BBS0039.csv",
                    "BBS0039",
                    "08/12/2010 10:24:05",
                    "08/13/2010 19:08:58",
                ],
                [
                    "4.2",
                    "1",
                    "r4.2-1-TEST0001.csv",
                    "TEST0001",
                    "01/01/2010 00:00:00",
                    "01/02/2010 00:00:00",
                ],
                [
                    "5.2",
                    "3",
                    "r5.2-3-TEST0002.csv",
                    "TEST0002",
                    "01/01/2011 00:00:00",
                    "01/02/2011 00:00:00",
                ],
            ],
        )

        _write_csv_member(
            tar,
            (
                "answers/r4.2-3/"
                "r4.2-3-BBS0039.csv"
            ),
            [
                [
                    "http",
                    "{EVENT-1}",
                    "08/12/2010 13:35:00",
                    "BBS0039",
                    "PC-9436",
                    "http://example.com/keylogger",
                ],
                [
                    "email",
                    "{EVENT-2}",
                    "08/12/2010 14:00:00",
                    "FAW0032",
                    "PC-5866",
                    "BBS0039@example.com",
                ],
            ],
        )

    scenarios = list(
        cmu_insider.iter_cmu_scenarios(
            archive_path
        )
    )

    assert len(scenarios) == 1

    scenario = scenarios[0]

    assert (
        scenario.label
        == "privilege_misuse"
    )

    assert (
        scenario.source_dataset
        == "cmu_cert_r4_2"
    )

    assert (
        scenario.insider_user
        == "BBS0039"
    )

    assert scenario.dataset == "4.2"
    assert scenario.scenario == 3

    assert (
        scenario.start
        == "08/12/2010 10:24:05"
    )

    assert (
        scenario.end
        == "08/13/2010 19:08:58"
    )


def test_iter_cmu_scenarios_preserves_all_scenario_events(
    tmp_path,
):
    archive_path = (
        tmp_path
        / "answers.tar.bz2"
    )

    with tarfile.open(
        archive_path,
        mode="w:bz2",
    ) as tar:
        _write_csv_member(
            tar,
            "answers/insiders.csv",
            [
                [
                    "dataset",
                    "scenario",
                    "details",
                    "user",
                    "start",
                    "end",
                ],
                [
                    "4.2",
                    "3",
                    "r4.2-3-BBS0039.csv",
                    "BBS0039",
                    "08/12/2010 10:24:05",
                    "08/13/2010 19:08:58",
                ],
            ],
        )

        _write_csv_member(
            tar,
            (
                "answers/r4.2-3/"
                "r4.2-3-BBS0039.csv"
            ),
            [
                [
                    "http",
                    "{EVENT-1}",
                    "08/12/2010 13:35:00",
                    "BBS0039",
                    "PC-9436",
                    "http://example.com/keylogger",
                ],
                [
                    "email",
                    "{EVENT-2}",
                    "08/13/2010 09:00:00",
                    "FAW0032",
                    "PC-5866",
                    "BBS0039@example.com",
                ],
            ],
        )

    scenarios = list(
        cmu_insider.iter_cmu_scenarios(
            archive_path
        )
    )

    assert len(scenarios) == 1

    scenario = scenarios[0]

    assert (
        scenario.source_row_id
        == (
            "answers/r4.2-3/"
            "r4.2-3-BBS0039.csv"
        )
    )

    assert (
        scenario.source_file
        == (
            "answers/r4.2-3/"
            "r4.2-3-BBS0039.csv"
        )
    )

    assert len(
        scenario.events
    ) == 2

    assert scenario.events[0] == (
        "http",
        "{EVENT-1}",
        "08/12/2010 13:35:00",
        "BBS0039",
        "PC-9436",
        "http://example.com/keylogger",
    )

    assert scenario.events[1] == (
        "email",
        "{EVENT-2}",
        "08/13/2010 09:00:00",
        "FAW0032",
        "PC-5866",
        "BBS0039@example.com",
    )