"""Storage interface for the raw event store.

The interface is deliberately narrow: append, read back, count, iterate. There
is no update and no delete, because the raw store is append-only by design.
Retention is a separate administrative operation, not something the ingest path
can reach.

SQLite backs development and the test suite; ClickHouse will implement the same
interface for the reference deployment.
"""

from __future__ import annotations

import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Iterable, Iterator

from ..models import RawEvent

__all__ = ["RawStore", "StoreStats"]


@dataclass(frozen=True, slots=True)
class StoreStats:
    """Outcome of an append batch."""

    accepted: int
    duplicates: int

    @property
    def submitted(self) -> int:
        return self.accepted + self.duplicates


class RawStore(ABC):
    """Append-only store of raw events."""

    @abstractmethod
    def append(self, events: Iterable[RawEvent]) -> StoreStats:
        """Persist events. Redelivered events are skipped, not duplicated."""

    @abstractmethod
    def get(self, event_uid: uuid.UUID) -> RawEvent | None:
        """Fetch one event by uid, or ``None`` if it is not present."""

    @abstractmethod
    def count(self) -> int:
        """Total events stored."""

    @abstractmethod
    def iter_events(
        self,
        *,
        source_id: str | None = None,
        since_ns: int | None = None,
        until_ns: int | None = None,
        limit: int | None = None,
        newest_first: bool = False,
    ) -> Iterator[RawEvent]:
        """Iterate stored events in arrival order, oldest first by default.

        ``newest_first`` reverses the order, which matters whenever ``limit``
        is set: a limit applied to an ascending scan returns the *oldest* N,
        so anything recent is unreachable. A console showing live data wants
        the newest N.
        """

    @abstractmethod
    def close(self) -> None:
        """Release underlying resources."""

    # Context-manager sugar so callers cannot leak connections.
    def __enter__(self) -> "RawStore":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
