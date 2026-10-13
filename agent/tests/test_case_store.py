from app.schemas import CaseRecord

from app.services.investigation_store import (
    InMemoryInvestigationStore,
    SQLiteInvestigationStore,
)


def make_case() -> CaseRecord:
    return CaseRecord(
        case_id="CASE-TEST-001",
        alert_id="ALT-CASE-001",
        policy_id="POL-BF-HIGH",
        classification="brute_force",
        risk_score=78,
        risk_band="high",
        status="open",
        reason=(
            "Automatic containment "
            "is not permitted."
        ),
    )


def test_in_memory_store_saves_and_gets_case():
    store = InMemoryInvestigationStore()

    case = make_case()

    store.save_case(
        case
    )

    stored = store.get_case(
        "CASE-TEST-001"
    )

    assert stored is not None

    assert (
        stored.case_id
        == "CASE-TEST-001"
    )

    assert (
        stored.alert_id
        == "ALT-CASE-001"
    )


def test_in_memory_store_finds_case_by_alert_id():
    store = InMemoryInvestigationStore()

    case = make_case()

    store.save_case(
        case
    )

    stored = store.get_case_by_alert_id(
        "ALT-CASE-001"
    )

    assert stored is not None

    assert (
        stored.case_id
        == "CASE-TEST-001"
    )


def test_sqlite_store_persists_case(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-case.db"
    )

    first_store = SQLiteInvestigationStore(
        database_path
    )

    case = make_case()

    first_store.save_case(
        case
    )

    second_store = SQLiteInvestigationStore(
        database_path
    )

    stored = second_store.get_case(
        "CASE-TEST-001"
    )

    assert stored is not None

    assert (
        stored.case_id
        == "CASE-TEST-001"
    )

    assert (
        stored.alert_id
        == "ALT-CASE-001"
    )


def test_sqlite_store_finds_case_by_alert_id(
    tmp_path,
):
    database_path = (
        tmp_path
        / "athenasec-case.db"
    )

    store = SQLiteInvestigationStore(
        database_path
    )

    case = make_case()

    store.save_case(
        case
    )

    stored = store.get_case_by_alert_id(
        "ALT-CASE-001"
    )

    assert stored is not None

    assert (
        stored.case_id
        == "CASE-TEST-001"
    )