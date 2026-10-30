import base64
import binascii
import json
from datetime import (
    datetime,
    timezone,
)
from typing import Callable, TypeVar

T = TypeVar("T")

DEFAULT_LIST_LIMIT = 50
MAX_LIST_LIMIT = 200


class InvalidCursor(ValueError):
    pass


def as_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def encode_cursor(
    sort_value: datetime | None,
    tiebreaker: str,
) -> str:
    payload = json.dumps(
        [
            None
            if sort_value is None
            else as_utc(sort_value).isoformat(),
            tiebreaker,
        ]
    )

    return base64.urlsafe_b64encode(
        payload.encode("utf-8")
    ).decode("ascii")


def decode_cursor(
    cursor: str,
) -> tuple[datetime | None, str]:
    try:
        raw = base64.urlsafe_b64decode(
            cursor.encode("ascii")
        )
        sort_text, tiebreaker = json.loads(raw)

        if not isinstance(tiebreaker, str):
            raise ValueError

        sort_value = (
            None
            if sort_text is None
            else as_utc(
                datetime.fromisoformat(sort_text)
            )
        )
    except (
        ValueError,
        TypeError,
        binascii.Error,
        UnicodeError,
    ) as exc:
        raise InvalidCursor(
            "Cursor is not valid."
        ) from exc

    return sort_value, tiebreaker


def paginate(
    items: list[T],
    *,
    sort_key: Callable[[T], datetime | None],
    id_key: Callable[[T], str],
    limit: int,
    cursor: str | None,
) -> tuple[list[T], str | None]:
    """Keyset-paginate items already ordered newest first.

    Order is (sort_key DESC, id_key DESC); undated items sort last.
    The cursor is the position of the last item returned, so inserts
    between requests do not shift later pages.
    """

    remaining = items

    if cursor is not None:
        after_time, after_id = decode_cursor(cursor)

        def is_after(item: T) -> bool:
            item_time = sort_key(item)
            item_id = id_key(item)

            if item_time is None or after_time is None:
                if item_time is None and after_time is None:
                    return item_id < after_id

                return item_time is None

            item_time = as_utc(item_time)

            if item_time != after_time:
                return item_time < after_time

            return item_id < after_id

        remaining = [
            item for item in items if is_after(item)
        ]

    page = remaining[:limit]

    next_cursor = None

    if len(remaining) > limit and page:
        last = page[-1]
        next_cursor = encode_cursor(
            sort_key(last),
            id_key(last),
        )

    return page, next_cursor
