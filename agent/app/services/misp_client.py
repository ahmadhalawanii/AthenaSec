from typing import Protocol

from app.schemas import (
    MISPEnrichment,
)


MISPIndicator = tuple[
    str,
    str,
]


class MISPClient(Protocol):
    def enrich(
        self,
        indicators: list[
            MISPIndicator
        ],
    ) -> MISPEnrichment:
        ...