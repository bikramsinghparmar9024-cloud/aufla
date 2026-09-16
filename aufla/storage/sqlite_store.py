"""SQLite implementation of the raw event store.

Chosen for development and tests because it needs no daemon, which keeps the
project runnable on an air-gapped laptop with nothing installed. The schema
mirrors the ClickHouse layout one-for-one so the production backend is a
drop-in replacement rather than a rewrite.

Two properties are enforced by the database, not by application code:

* ``raw_bytes`` is a BLOB. SQLite will not silently transcode it.
* ``idem_key`` is UNIQUE, so redelivery cannot create a second row even if two
  workers race on the same message.
"""

from __future__ import annotations

import sqlite3
import uuid
from pathlib import Path
from typing import Iterable, Iterator

from ..models import RawEvent, Transport
from .base import RawStore, StoreStats

__all__ = ["SQLiteRawStore"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS raw_events (
    event_uid       TEXT    PRIMARY KEY,
    raw_bytes       BLOB    NOT NULL,
    raw_hash        TEXT    NOT NULL,
    source_id       TEXT    NOT NULL,
    source_ip       TEXT,
    transport       TEXT    NOT NULL,
    received_at_ns  INTEGER NOT NULL,
    byte_len        INTEGER NOT NULL,
    charset         TEXT    NOT NULL,
    truncated       INTEGER NOT NULL DEFAULT 0,
    idem_key        TEXT    NOT NULL UNIQUE
);

CREATE INDEX IF NOT EXISTS idx_raw_arrival  ON raw_events (received_at_ns, event_uid);
CREATE INDEX IF NOT EXISTS idx_raw_source   ON raw_events (source_id, received_at_ns);
CREATE INDEX IF NOT EXISTS idx_raw_hash     ON raw_events (raw_hash);
"""

_COLUMNS = (
    "event_uid, raw_bytes, raw_hash, source_id, source_ip, transport, "
    "received_at_ns, byte_len, charset, truncated, idem_key"
)


class SQLiteRawStore(RawStore):
    """Append-only raw store backed by SQLite."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)

        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        # WAL keeps readers from blocking the ingest writer. It is unavailable
        # for in-memory databases, where it is also unnecessary.
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ---- writes -----------------------------------------------------------

    def append(self, events: Iterable[RawEvent]) -> StoreStats:
        rows = [
            (
                str(e.event_uid),
                e.raw_bytes,
                e.raw_hash,
                e.source_id,
                e.source_ip,
                e.transport.value,
                e.received_at_ns,
                e.byte_len,
                e.charset,
                1 if e.truncated else 0,
                e.idem_key,
            )
            for e in events
        ]
        if not rows:
            return StoreStats(accepted=0, duplicates=0)

        before = self.count()
        placeholders = ", ".join(["?"] * 11)
        # INSERT OR IGNORE lets the UNIQUE constraint on idem_key do the
        # deduplication, which is race-free in a way an application-side
        # "check then insert" never is.
        self._conn.executemany(
            f"INSERT OR IGNORE INTO raw_events ({_COLUMNS}) VALUES ({placeholders})",
            rows,
        )
        self._conn.commit()
        accepted = self.count() - before
        return StoreStats(accepted=accepted, duplicates=len(rows) - accepted)

    # ---- reads ------------------------------------------------------------

    def get(self, event_uid: uuid.UUID) -> RawEvent | None:
        cur = self._conn.execute(
            f"SELECT {_COLUMNS} FROM raw_events WHERE event_uid = ?",
            (str(event_uid),),
        )
        row = cur.fetchone()
        return self._to_event(row) if row is not None else None

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM raw_events").fetchone()[0])

    def iter_events(
        self,
        *,
        source_id: str | None = None,
        since_ns: int | None = None,
        until_ns: int | None = None,
        limit: int | None = None,
    ) -> Iterator[RawEvent]:
        clauses: list[str] = []
        params: list[object] = []
        if source_id is not None:
            clauses.append("source_id = ?")
            params.append(source_id)
        if since_ns is not None:
            clauses.append("received_at_ns >= ?")
            params.append(since_ns)
        if until_ns is not None:
            clauses.append("received_at_ns < ?")
            params.append(until_ns)

        sql = f"SELECT {_COLUMNS} FROM raw_events"
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY received_at_ns, event_uid"
        if limit is not None:
            sql += " LIMIT ?"
            params.append(limit)

        for row in self._conn.execute(sql, params):
            yield self._to_event(row)

    # ---- helpers ----------------------------------------------------------

    @staticmethod
    def _to_event(row: sqlite3.Row) -> RawEvent:
        return RawEvent(
            event_uid=uuid.UUID(row["event_uid"]),
            raw_bytes=bytes(row["raw_bytes"]),
            raw_hash=row["raw_hash"],
            source_id=row["source_id"],
            received_at_ns=row["received_at_ns"],
            byte_len=row["byte_len"],
            idem_key=row["idem_key"],
            source_ip=row["source_ip"],
            transport=Transport(row["transport"]),
            charset=row["charset"],
            truncated=bool(row["truncated"]),
        )

    def close(self) -> None:
        self._conn.close()
