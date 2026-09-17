"""Storage for the derived OCSF projection.

Raw stays canonical; this table is the *materialised* projection of it. That
distinction matters in both directions:

* rows here may be deleted and rebuilt from raw at any time, so nothing is
  lost by rewriting them when a mapping is corrected;
* but they must actually exist, or "derived" degenerates into "recomputed on
  every read", which is what this store replaces. Re-parsing every event per
  request does not scale past a demo, and leaves the lineage fields
  unqueryable.

Quarantine accounting
---------------------
Two status columns, not one:

``first_status``
    What happened the first time the event was normalised. Written once and
    never updated.
``parse_status``
    What happens now, under the mapping currently in force.

An event that arrived with no mapping and was later normalised after one was
approved therefore reads ``first_status='quarantined'`` and
``parse_status='full'`` -- which is exactly the "quarantined N, since resolved
M" figure the console reports. Collapsing these into one column would make a
resolved event indistinguishable from one that always parsed.
"""

from __future__ import annotations

import json
import sqlite3
import time
import uuid
from pathlib import Path
from typing import Any, Iterable, Iterator

from ..normalize.engine import NormalizedRecord

__all__ = ["OCSFStore"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS ocsf_events (
    event_uid        TEXT    PRIMARY KEY,
    raw_hash         TEXT    NOT NULL,
    source_id        TEXT    NOT NULL,
    observed_time    INTEGER NOT NULL,
    event_time       INTEGER,
    class_uid        INTEGER,
    mapping_id       TEXT,
    mapping_version  INTEGER,
    mapping_hash     TEXT,
    rule_name        TEXT,
    parse_status     TEXT    NOT NULL,
    first_status     TEXT    NOT NULL,
    first_seen_ns    INTEGER NOT NULL,
    resolved_at_ns   INTEGER,
    mapping_coverage REAL    NOT NULL DEFAULT 0,
    severity_id      INTEGER,
    src_ip           TEXT,
    src_port         INTEGER,
    dst_ip           TEXT,
    dst_port         INTEGER,
    summary          TEXT,
    fields           TEXT    NOT NULL,
    unmapped         TEXT,
    warnings         TEXT,
    notes            TEXT
);

CREATE INDEX IF NOT EXISTS idx_ocsf_time   ON ocsf_events (observed_time);
CREATE INDEX IF NOT EXISTS idx_ocsf_source ON ocsf_events (source_id, observed_time);
CREATE INDEX IF NOT EXISTS idx_ocsf_status ON ocsf_events (parse_status);
CREATE INDEX IF NOT EXISTS idx_ocsf_first  ON ocsf_events (first_status);
CREATE INDEX IF NOT EXISTS idx_ocsf_class  ON ocsf_events (class_uid);
CREATE INDEX IF NOT EXISTS idx_ocsf_map    ON ocsf_events (mapping_id, mapping_version);
"""


def _summarise(record: NormalizedRecord) -> str:
    f = record.fields
    if title := f.get("finding_info.title"):
        return str(title)
    if url := f.get("http_request.url.text"):
        return f"{f.get('http_request.http_method', '')} {url}".strip()
    src, dst = f.get("src_endpoint.ip"), f.get("dst_endpoint.ip")
    if src and dst:
        port = f.get("dst_endpoint.port")
        return f"{src} -> {dst}" + (f":{port}" if port else "")
    return "unparsed - awaiting a mapping"


class OCSFStore:
    """The materialised OCSF projection."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        if self.path != ":memory:":
            self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=NORMAL")
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ---- writes -----------------------------------------------------------

    def upsert(self, records: Iterable[NormalizedRecord]) -> dict[str, int]:
        """Write or rewrite projections. Returns counts, including resolutions.

        ``first_status`` and ``first_seen_ns`` survive a rewrite; everything
        else is replaced. That is what lets a backfill be a plain re-derivation
        while still leaving a record that the event was once quarantined.
        """
        written = resolved = 0
        now = time.time_ns()

        for record in records:
            uid = str(record.event_uid)
            status = record.parse_status.value
            prior = self._conn.execute(
                "SELECT first_status, first_seen_ns, resolved_at_ns"
                " FROM ocsf_events WHERE event_uid = ?",
                (uid,),
            ).fetchone()

            if prior is None:
                first_status, first_seen = status, now
                resolved_at = None
            else:
                first_status = prior["first_status"]
                first_seen = prior["first_seen_ns"]
                resolved_at = prior["resolved_at_ns"]

            # A quarantined event that now parses has been resolved. Stamped
            # once, so a later re-derivation does not move the date.
            if (
                first_status == "quarantined"
                and status != "quarantined"
                and resolved_at is None
            ):
                resolved_at = now
                resolved += 1

            f = record.fields
            self._conn.execute(
                "INSERT OR REPLACE INTO ocsf_events ("
                " event_uid, raw_hash, source_id, observed_time, event_time,"
                " class_uid, mapping_id, mapping_version, mapping_hash, rule_name,"
                " parse_status, first_status, first_seen_ns, resolved_at_ns,"
                " mapping_coverage, severity_id, src_ip, src_port, dst_ip, dst_port,"
                " summary, fields, unmapped, warnings, notes"
                ") VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (
                    uid, record.raw_hash, record.source_id,
                    record.observed_time, f.get("time"),
                    record.ocsf_class, record.mapping_id, record.mapping_version,
                    record.mapping_hash, record.rule_name,
                    status, first_status, first_seen, resolved_at,
                    record.mapping_coverage, f.get("severity_id"),
                    f.get("src_endpoint.ip"), f.get("src_endpoint.port"),
                    f.get("dst_endpoint.ip"), f.get("dst_endpoint.port"),
                    _summarise(record),
                    json.dumps(f, default=str),
                    json.dumps(record.unmapped, default=str) if record.unmapped else None,
                    json.dumps(record.warnings) if record.warnings else None,
                    json.dumps(record.notes) if record.notes else None,
                ),
            )
            written += 1

        self._conn.commit()
        return {"written": written, "resolved": resolved}

    # ---- reads ------------------------------------------------------------

    def count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM ocsf_events").fetchone()[0])

    def get(self, event_uid: uuid.UUID | str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM ocsf_events WHERE event_uid = ?", (str(event_uid),)
        ).fetchone()
        return None if row is None else self._to_dict(row)

    def _where(
        self,
        *,
        source_id: str | None = None,
        status: str | None = None,
        since_ms: int | None = None,
    ) -> tuple[str, list[Any]]:
        clauses: list[str] = []
        params: list[Any] = []
        if source_id:
            clauses.append("source_id = ?")
            params.append(source_id)
        if status:
            clauses.append("parse_status = ?")
            params.append(status)
        if since_ms is not None:
            clauses.append("observed_time >= ?")
            params.append(since_ms)
        return (" WHERE " + " AND ".join(clauses) if clauses else ""), params

    def query(
        self,
        *,
        source_id: str | None = None,
        status: str | None = None,
        since_ms: int | None = None,
        search: str | None = None,
        limit: int = 300,
        newest_first: bool = True,
    ) -> list[dict[str, Any]]:
        where, params = self._where(
            source_id=source_id, status=status, since_ms=since_ms
        )
        if search:
            where += (" AND " if where else " WHERE ") + (
                "(summary LIKE ? OR source_id LIKE ?)"
            )
            params += [f"%{search}%", f"%{search}%"]

        order = "DESC" if newest_first else "ASC"
        rows = self._conn.execute(
            f"SELECT * FROM ocsf_events{where}"
            f" ORDER BY observed_time {order}, event_uid {order} LIMIT ?",
            [*params, limit],
        )
        return [self._to_dict(r) for r in rows]

    # ---- aggregations (in SQL, not by re-parsing) -------------------------

    def counts_by(
        self, column: str, *, since_ms: int | None = None, limit: int = 20
    ) -> list[tuple[Any, int]]:
        if column not in {
            "source_id", "parse_status", "class_uid", "severity_id",
            "dst_ip", "mapping_id", "first_status",
        }:
            raise ValueError(f"not an aggregatable column: {column}")
        where, params = self._where(since_ms=since_ms)
        extra = ("AND" if where else "WHERE") + f" {column} IS NOT NULL"
        rows = self._conn.execute(
            f"SELECT {column} AS k, COUNT(*) AS n FROM ocsf_events{where} {extra}"
            " GROUP BY k ORDER BY n DESC LIMIT ?",
            [*params, limit],
        )
        return [(r["k"], r["n"]) for r in rows]

    def quarantine_summary(self) -> dict[str, int]:
        """Lifetime quarantine accounting, the figure the console reports."""
        row = self._conn.execute(
            "SELECT"
            "  SUM(first_status = 'quarantined')                        AS ever,"
            "  SUM(first_status = 'quarantined' AND parse_status != 'quarantined')"
            "                                                           AS resolved,"
            "  SUM(parse_status = 'quarantined')                        AS pending,"
            "  COUNT(*)                                                 AS total"
            " FROM ocsf_events"
        ).fetchone()
        ever = row["ever"] or 0
        resolved = row["resolved"] or 0
        return {
            "ever_quarantined": ever,
            "resolved": resolved,
            "pending": row["pending"] or 0,
            "total": row["total"] or 0,
            "resolution_rate": round(resolved / ever, 4) if ever else 0.0,
        }

    def quarantined_sources(self) -> list[tuple[str, int]]:
        """Sources with events still awaiting a mapping, worst first."""
        rows = self._conn.execute(
            "SELECT source_id, COUNT(*) AS n FROM ocsf_events"
            " WHERE parse_status = 'quarantined'"
            " GROUP BY source_id ORDER BY n DESC"
        )
        return [(r["source_id"], r["n"]) for r in rows]

    def timeline(
        self, *, since_ms: int | None = None, buckets: int = 40
    ) -> dict[str, Any]:
        where, params = self._where(since_ms=since_ms)
        span = self._conn.execute(
            f"SELECT MIN(observed_time) AS lo, MAX(observed_time) AS hi"
            f" FROM ocsf_events{where}",
            params,
        ).fetchone()
        lo, hi = span["lo"], span["hi"]
        if lo is None:
            return {"sources": [], "bucket_ms": 1000, "points": []}

        bucket = max((hi - lo) // max(buckets, 1), 1000)
        rows = self._conn.execute(
            f"SELECT source_id, ((observed_time - ?) / ?) AS b, COUNT(*) AS n"
            f" FROM ocsf_events{where} GROUP BY source_id, b ORDER BY b",
            [lo, bucket, *params],
        )

        grid: dict[int, dict[str, int]] = {}
        totals: dict[str, int] = {}
        for r in rows:
            grid.setdefault(r["b"], {})[r["source_id"]] = r["n"]
            totals[r["source_id"]] = totals.get(r["source_id"], 0) + r["n"]

        sources = [s for s, _ in sorted(totals.items(), key=lambda kv: -kv[1])]
        points = [
            {
                "t": lo + b * bucket,
                "total": sum(grid[b].values()),
                **{s: grid[b].get(s, 0) for s in sources},
            }
            for b in sorted(grid)
        ]
        return {"sources": sources, "bucket_ms": bucket, "points": points}

    def average_coverage(self, *, since_ms: int | None = None) -> float:
        where, params = self._where(since_ms=since_ms)
        row = self._conn.execute(
            f"SELECT AVG(mapping_coverage) AS a FROM ocsf_events{where}", params
        ).fetchone()
        return round(row["a"] or 0.0, 4)

    def event_count(self, *, since_ms: int | None = None) -> int:
        where, params = self._where(since_ms=since_ms)
        return int(
            self._conn.execute(
                f"SELECT COUNT(*) FROM ocsf_events{where}", params
            ).fetchone()[0]
        )

    def findings(
        self, *, since_ms: int | None = None, min_severity: int = 3, limit: int = 12
    ) -> list[dict[str, Any]]:
        where, params = self._where(since_ms=since_ms)
        joiner = "AND" if where else "WHERE"
        rows = self._conn.execute(
            f"SELECT * FROM ocsf_events{where} {joiner} severity_id >= ?"
            " ORDER BY severity_id DESC, observed_time DESC LIMIT ?",
            [*params, min_severity, limit],
        )
        return [self._to_dict(r) for r in rows]

    def sample_uids(self, source_id: str, limit: int = 5) -> list[str]:
        rows = self._conn.execute(
            "SELECT event_uid FROM ocsf_events WHERE source_id = ?"
            " ORDER BY observed_time DESC LIMIT ?",
            (source_id, limit),
        )
        return [r["event_uid"] for r in rows]

    # ---- helpers ----------------------------------------------------------

    @staticmethod
    def _to_dict(row: sqlite3.Row) -> dict[str, Any]:
        out = dict(row)
        out["fields"] = json.loads(out["fields"]) if out["fields"] else {}
        out["unmapped"] = json.loads(out["unmapped"]) if out["unmapped"] else {}
        out["warnings"] = json.loads(out["warnings"]) if out["warnings"] else []
        out["notes"] = json.loads(out["notes"]) if out.get("notes") else []
        out["resolved"] = (
            out["first_status"] == "quarantined"
            and out["parse_status"] != "quarantined"
        )
        return out

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "OCSFStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
