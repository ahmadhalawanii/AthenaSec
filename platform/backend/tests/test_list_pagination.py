from datetime import datetime, timedelta, timezone

import pytest

from app.services.dashboard.list_pagination import (
    InvalidCursor,
    decode_cursor,
    encode_cursor,
    paginate,
)

BASE = datetime(2026, 1, 1, tzinfo=timezone.utc)


def make_items(count):
    # Already newest first, as the stores return them.
    return [
        (f"ID-{index:03d}", BASE - timedelta(minutes=index))
        for index in range(count)
    ]


def run(items, limit, cursor=None):
    return paginate(
        items,
        sort_key=lambda item: item[1],
        id_key=lambda item: item[0],
        limit=limit,
        cursor=cursor,
    )


def test_cursor_round_trip():
    cursor = encode_cursor(BASE, "ID-1")

    assert decode_cursor(cursor) == (BASE, "ID-1")


def test_cursor_round_trip_without_timestamp():
    assert decode_cursor(encode_cursor(None, "ID-1")) == (None, "ID-1")


@pytest.mark.parametrize(
    "cursor",
    ["", "not-base64!", "e30=", "WzEsMl0="],
)
def test_invalid_cursor_rejected(cursor):
    with pytest.raises(InvalidCursor):
        decode_cursor(cursor)


def test_single_page_has_no_next_cursor():
    page, next_cursor = run(make_items(3), limit=5)

    assert len(page) == 3
    assert next_cursor is None


def test_exact_fit_has_no_next_cursor():
    page, next_cursor = run(make_items(5), limit=5)

    assert len(page) == 5
    assert next_cursor is None


def test_walks_all_items_without_gaps_or_repeats():
    items = make_items(7)
    seen = []
    cursor = None

    while True:
        page, cursor = run(items, limit=3, cursor=cursor)
        seen.extend(page)
        if cursor is None:
            break

    assert seen == items


def test_equal_timestamps_break_ties_by_id():
    items = [("B", BASE), ("A", BASE)]

    first, cursor = run(items, limit=1)
    second, end = run(items, limit=1, cursor=cursor)

    assert first == [("B", BASE)]
    assert second == [("A", BASE)]
    assert end is None


def test_insert_between_pages_does_not_shift_next_page():
    items = make_items(4)
    first, cursor = run(items, limit=2)

    newer = ("NEW", BASE + timedelta(hours=1))
    second, _ = run([newer, *items], limit=2, cursor=cursor)

    assert second == items[2:4]


def test_undated_items_sort_last_and_are_reachable():
    dated = ("A", BASE)
    undated = ("Z", None)
    items = [dated, undated]

    first, cursor = run(items, limit=1)
    second, end = run(items, limit=1, cursor=cursor)

    assert first == [dated]
    assert second == [undated]
    assert end is None
