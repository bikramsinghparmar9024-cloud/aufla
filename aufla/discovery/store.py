"""The review queue.

Proposals that clear every check take effect on their own. Anything below the
bar waits here for a named person, and the decision is recorded: who approved
it, when, at what confidence, and against which YAML. That record is the whole
governance claim -- automation that cannot be audited is not acceptable in an
evidence system, however good its accuracy.

Approval writes the YAML into ``sources/``, where the ordinary hot-reloading
registry picks it up. There is no privileged path: a mapping the discovery lane
authored takes effect through exactly the same mechanism as one a human wrote
by hand, and faces exactly the same load-time validation.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .confidence import ConfidenceReport
from .proposer import Proposal

__all__ = ["ProposalStore", "StoredProposal"]

_SCHEMA = """
CREATE TABLE IF NOT EXISTS proposals (
    proposal_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id    TEXT    NOT NULL,
    format       TEXT    NOT NULL,
    ocsf_class   INTEGER NOT NULL,
    yaml         TEXT    NOT NULL,
    fields_json  TEXT    NOT NULL,
    confidence   REAL    NOT NULL,
    report_json  TEXT    NOT NULL,
    sample_count INTEGER NOT NULL,
    state        TEXT    NOT NULL,       -- pending | approved | rejected
    created_ns   INTEGER NOT NULL,
    decided_ns   INTEGER,
    decided_by   TEXT,
    note         TEXT
);

CREATE INDEX IF NOT EXISTS idx_prop_state  ON proposals (state);
CREATE INDEX IF NOT EXISTS idx_prop_source ON proposals (source_id);
"""


@dataclass(slots=True)
class StoredProposal:
    proposal_id: int
    source_id: str
    format: str
    ocsf_class: int
    yaml: str
    fields: dict[str, str]
    confidence: float
    report: dict[str, Any]
    sample_count: int
    state: str
    created_ns: int
    decided_ns: int | None = None
    decided_by: str | None = None
    note: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "proposal_id": self.proposal_id,
            "source_id": self.source_id,
            "format": self.format,
            "ocsf_class": self.ocsf_class,
            "yaml": self.yaml,
            "fields": self.fields,
            "confidence": round(self.confidence, 4),
            "report": self.report,
            "sample_count": self.sample_count,
            "state": self.state,
            "created_ns": self.created_ns,
            "decided_ns": self.decided_ns,
            "decided_by": self.decided_by,
            "note": self.note,
        }


class ProposalStore:
    """Pending and decided mapping proposals."""

    def __init__(self, path: str | Path = ":memory:") -> None:
        self.path = str(path)
        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    # ---- writes -----------------------------------------------------------

    def add(self, proposal: Proposal, report: ConfidenceReport) -> int:
        """Queue a proposal. Re-proposing a source replaces its pending entry."""
        self._conn.execute(
            "DELETE FROM proposals WHERE source_id = ? AND state = 'pending'",
            (proposal.source,),
        )
        cur = self._conn.execute(
            "INSERT INTO proposals (source_id, format, ocsf_class, yaml,"
            " fields_json, confidence, report_json, sample_count, state, created_ns)"
            " VALUES (?,?,?,?,?,?,?,?,'pending',?)",
            (
                proposal.source, proposal.format, proposal.ocsf_class,
                proposal.to_yaml(), json.dumps(proposal.fields),
                report.confidence, json.dumps(report.as_dict()),
                proposal.sample_count, time.time_ns(),
            ),
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def decide(
        self,
        proposal_id: int,
        *,
        state: str,
        by: str,
        note: str | None = None,
    ) -> StoredProposal | None:
        if state not in {"approved", "rejected"}:
            raise ValueError(f"not a decision: {state}")
        if not by:
            raise ValueError("a decision must name who made it")

        self._conn.execute(
            "UPDATE proposals SET state = ?, decided_ns = ?, decided_by = ?, note = ?"
            " WHERE proposal_id = ? AND state = 'pending'",
            (state, time.time_ns(), by, note, proposal_id),
        )
        self._conn.commit()
        return self.get(proposal_id)

    # ---- reads ------------------------------------------------------------

    def get(self, proposal_id: int) -> StoredProposal | None:
        row = self._conn.execute(
            "SELECT * FROM proposals WHERE proposal_id = ?", (proposal_id,)
        ).fetchone()
        return None if row is None else self._to_obj(row)

    def pending(self) -> list[StoredProposal]:
        rows = self._conn.execute(
            "SELECT * FROM proposals WHERE state = 'pending'"
            " ORDER BY confidence DESC, created_ns"
        )
        return [self._to_obj(r) for r in rows]

    def history(self, limit: int = 30) -> list[StoredProposal]:
        rows = self._conn.execute(
            "SELECT * FROM proposals WHERE state != 'pending'"
            " ORDER BY decided_ns DESC LIMIT ?",
            (limit,),
        )
        return [self._to_obj(r) for r in rows]

    def has_pending(self, source_id: str) -> bool:
        return (
            self._conn.execute(
                "SELECT 1 FROM proposals WHERE source_id = ? AND state = 'pending'",
                (source_id,),
            ).fetchone()
            is not None
        )

    def was_rejected(self, source_id: str) -> bool:
        """A rejected source is not re-proposed until its data changes shape."""
        return (
            self._conn.execute(
                "SELECT 1 FROM proposals WHERE source_id = ? AND state = 'rejected'",
                (source_id,),
            ).fetchone()
            is not None
        )

    def counts(self) -> dict[str, int]:
        rows = self._conn.execute(
            "SELECT state, COUNT(*) AS n FROM proposals GROUP BY state"
        )
        out = {"pending": 0, "approved": 0, "rejected": 0}
        for r in rows:
            out[r["state"]] = r["n"]
        return out

    @staticmethod
    def _to_obj(row: sqlite3.Row) -> StoredProposal:
        return StoredProposal(
            proposal_id=row["proposal_id"],
            source_id=row["source_id"],
            format=row["format"],
            ocsf_class=row["ocsf_class"],
            yaml=row["yaml"],
            fields=json.loads(row["fields_json"]),
            confidence=row["confidence"],
            report=json.loads(row["report_json"]),
            sample_count=row["sample_count"],
            state=row["state"],
            created_ns=row["created_ns"],
            decided_ns=row["decided_ns"],
            decided_by=row["decided_by"],
            note=row["note"],
        )

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "ProposalStore":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
