"""The append-only chained ledger.

Events are sealed in micro-batches. Each batch's leaves are the SHA-256 hashes
of its raw events; the Merkle root is chained to the previous root, and the
batch is signed with the online key.

What the chain seals
--------------------
**The raw stream.** The OCSF projection is re-buildable and therefore mutable
by design, so it is not evidence; the raw bytes are. To keep the derivation
provable, the hashes of the mappings in force are committed into each batch --
for any normalised row you can then show which raw event produced it, under
which mapping version, and that neither has changed since.

Immutability
------------
Enforced by grants and by an append-only file, not asserted as a property of
the storage engine. SQLite and ClickHouse will both happily run an UPDATE for
anyone holding the privilege; the point of the ledger is that doing so is
*detectable*, not impossible.
"""

from __future__ import annotations

import json
import sqlite3
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

from ..models import RawEvent
from .merkle import MerkleTree, hash_leaf
from .signing import KeyPair

__all__ = ["Batch", "Checkpoint", "Ledger", "VerifyResult", "GENESIS"]

# The previous-root value of the first batch. A fixed, publishable constant.
GENESIS = "0" * 64

DEFAULT_BATCH_SIZE = 5_000
DEFAULT_BATCH_SECONDS = 1.0


def leaf_for(event_uid: str, raw_hash: str) -> str:
    """The Merkle leaf committing to one event.

    Binds the event's *identity* as well as its content. Committing to the
    content hash alone would let two byte-identical events be swapped or
    reordered without changing the root; including the uid removes that.

    Deriving the leaf from the stored hash rather than from the bytes is what
    lets the ledger be verified on its own, without the raw store -- useful
    once events have aged into cold storage while the chain must stay checkable.
    """
    return hash_leaf(event_uid.encode("ascii") + b"\x1f" + bytes.fromhex(raw_hash))

_SCHEMA = """
CREATE TABLE IF NOT EXISTS batches (
    batch_id     INTEGER PRIMARY KEY,
    prev_root    TEXT    NOT NULL,
    root         TEXT    NOT NULL,
    leaf_count   INTEGER NOT NULL,
    first_uid    TEXT,
    last_uid     TEXT,
    sealed_at_ns INTEGER NOT NULL,
    mapping_set  TEXT    NOT NULL,
    signature    TEXT,
    signer       TEXT
);

CREATE TABLE IF NOT EXISTS batch_leaves (
    batch_id   INTEGER NOT NULL,
    leaf_index INTEGER NOT NULL,
    event_uid  TEXT    NOT NULL,
    raw_hash   TEXT    NOT NULL,
    PRIMARY KEY (batch_id, leaf_index)
);

CREATE TABLE IF NOT EXISTS checkpoints (
    checkpoint_id INTEGER PRIMARY KEY,
    day           TEXT    NOT NULL UNIQUE,
    first_batch   INTEGER NOT NULL,
    last_batch    INTEGER NOT NULL,
    chain_head    TEXT    NOT NULL,
    batch_count   INTEGER NOT NULL,
    event_count   INTEGER NOT NULL,
    created_at_ns INTEGER NOT NULL,
    signature     TEXT    NOT NULL,
    signer        TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_leaves_uid ON batch_leaves (event_uid);
"""


@dataclass(frozen=True, slots=True)
class Batch:
    """One sealed micro-batch."""

    batch_id: int
    prev_root: str
    root: str
    leaf_count: int
    sealed_at_ns: int
    mapping_set: dict[str, str] = field(default_factory=dict)
    first_uid: str | None = None
    last_uid: str | None = None
    signature: str | None = None
    signer: str | None = None

    def payload(self) -> dict[str, Any]:
        """The exact object that is signed. Order-independent by construction."""
        return {
            "batch_id": self.batch_id,
            "prev_root": self.prev_root,
            "root": self.root,
            "leaf_count": self.leaf_count,
            "sealed_at_ns": self.sealed_at_ns,
            "mapping_set": self.mapping_set,
        }


@dataclass(frozen=True, slots=True)
class Checkpoint:
    """A daily anchor signed by the offline root key."""

    checkpoint_id: int
    day: str
    first_batch: int
    last_batch: int
    chain_head: str
    batch_count: int
    event_count: int
    created_at_ns: int
    signature: str
    signer: str

    def payload(self) -> dict[str, Any]:
        return {
            "day": self.day,
            "first_batch": self.first_batch,
            "last_batch": self.last_batch,
            "chain_head": self.chain_head,
            "batch_count": self.batch_count,
            "event_count": self.event_count,
        }


@dataclass(slots=True)
class VerifyResult:
    """Outcome of verifying a stretch of the chain."""

    ok: bool
    batches_checked: int = 0
    events_checked: int = 0
    checkpoints_checked: int = 0
    first_divergence: int | None = None
    reason: str = ""

    def __str__(self) -> str:
        if self.ok:
            return (
                f"PASS - {self.batches_checked} batches, "
                f"{self.events_checked} events, chain intact, "
                f"{self.checkpoints_checked} checkpoints valid"
            )
        return (
            f"FAIL - divergence at batch {self.first_divergence}: {self.reason}"
        )


class Ledger:
    """Append-only chained Merkle ledger."""

    def __init__(
        self,
        path: str | Path = ":memory:",
        *,
        batch_key: KeyPair | None = None,
        checkpoint_key: KeyPair | None = None,
        batch_size: int = DEFAULT_BATCH_SIZE,
        batch_seconds: float = DEFAULT_BATCH_SECONDS,
    ) -> None:
        self.path = str(path)
        self.batch_key = batch_key
        self.checkpoint_key = checkpoint_key
        self.batch_size = batch_size
        self.batch_seconds = batch_seconds

        if self.path != ":memory:":
            Path(self.path).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(self.path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

        self._pending: list[RawEvent] = []
        self._pending_since: float | None = None

    # ---- chain state ------------------------------------------------------

    @property
    def head(self) -> str:
        row = self._conn.execute(
            "SELECT root FROM batches ORDER BY batch_id DESC LIMIT 1"
        ).fetchone()
        return GENESIS if row is None else row["root"]

    @property
    def batch_count(self) -> int:
        return int(self._conn.execute("SELECT COUNT(*) FROM batches").fetchone()[0])

    @property
    def event_count(self) -> int:
        row = self._conn.execute(
            "SELECT COALESCE(SUM(leaf_count), 0) FROM batches"
        ).fetchone()
        return int(row[0])

    # ---- sealing ----------------------------------------------------------

    def add(
        self, events: Iterable[RawEvent], *, mapping_set: dict[str, str] | None = None
    ) -> list[Batch]:
        """Buffer events, sealing whenever the size threshold is reached."""
        sealed: list[Batch] = []
        for event in events:
            if self._pending_since is None:
                self._pending_since = time.monotonic()
            self._pending.append(event)
            if len(self._pending) >= self.batch_size:
                sealed.append(self.seal(mapping_set=mapping_set))
        return sealed

    def tick(self, *, mapping_set: dict[str, str] | None = None) -> Batch | None:
        """Seal on the time threshold. Called by the ingest loop between batches."""
        if not self._pending or self._pending_since is None:
            return None
        if time.monotonic() - self._pending_since < self.batch_seconds:
            return None
        return self.seal(mapping_set=mapping_set)

    def seal(self, *, mapping_set: dict[str, str] | None = None) -> Batch:
        """Seal the pending events into a batch and chain it."""
        events = self._pending
        self._pending = []
        self._pending_since = None

        leaves = [leaf_for(str(e.event_uid), e.raw_hash) for e in events]
        tree = MerkleTree(leaves)
        prev_root = self.head
        batch_id = self.batch_count + 1

        batch = Batch(
            batch_id=batch_id,
            prev_root=prev_root,
            # Chaining the previous root *into* this root is what makes the
            # sequence unbroken: altering any earlier batch changes every
            # later root.
            root=MerkleTree([prev_root, tree.root]).root,
            leaf_count=len(events),
            sealed_at_ns=time.time_ns(),
            mapping_set=dict(mapping_set or {}),
            first_uid=str(events[0].event_uid) if events else None,
            last_uid=str(events[-1].event_uid) if events else None,
        )

        signature = self.batch_key.sign(batch.payload()) if self.batch_key else None
        signer = self.batch_key.public_hex if self.batch_key else None

        self._conn.execute(
            "INSERT INTO batches (batch_id, prev_root, root, leaf_count, first_uid,"
            " last_uid, sealed_at_ns, mapping_set, signature, signer)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                batch.batch_id,
                batch.prev_root,
                batch.root,
                batch.leaf_count,
                batch.first_uid,
                batch.last_uid,
                batch.sealed_at_ns,
                json.dumps(batch.mapping_set, sort_keys=True),
                signature,
                signer,
            ),
        )
        self._conn.executemany(
            "INSERT INTO batch_leaves (batch_id, leaf_index, event_uid, raw_hash)"
            " VALUES (?,?,?,?)",
            [
                (batch.batch_id, i, str(e.event_uid), e.raw_hash)
                for i, e in enumerate(events)
            ],
        )
        self._conn.commit()

        return Batch(
            batch_id=batch.batch_id,
            prev_root=batch.prev_root,
            root=batch.root,
            leaf_count=batch.leaf_count,
            sealed_at_ns=batch.sealed_at_ns,
            mapping_set=batch.mapping_set,
            first_uid=batch.first_uid,
            last_uid=batch.last_uid,
            signature=signature,
            signer=signer,
        )

    # ---- reading ----------------------------------------------------------

    def get_batch(self, batch_id: int) -> Batch | None:
        row = self._conn.execute(
            "SELECT * FROM batches WHERE batch_id = ?", (batch_id,)
        ).fetchone()
        return None if row is None else self._to_batch(row)

    def iter_batches(
        self, *, start: int = 1, end: int | None = None
    ) -> Iterator[Batch]:
        sql = "SELECT * FROM batches WHERE batch_id >= ?"
        params: list[Any] = [start]
        if end is not None:
            sql += " AND batch_id <= ?"
            params.append(end)
        sql += " ORDER BY batch_id"
        for row in self._conn.execute(sql, params):
            yield self._to_batch(row)

    def leaves_of(self, batch_id: int) -> list[tuple[str, str]]:
        return [
            (r["event_uid"], r["raw_hash"])
            for r in self._conn.execute(
                "SELECT event_uid, raw_hash FROM batch_leaves"
                " WHERE batch_id = ? ORDER BY leaf_index",
                (batch_id,),
            )
        ]

    def locate(self, event_uid: str) -> tuple[int, int] | None:
        """Return ``(batch_id, leaf_index)`` for an event, if it was sealed."""
        row = self._conn.execute(
            "SELECT batch_id, leaf_index FROM batch_leaves WHERE event_uid = ?",
            (event_uid,),
        ).fetchone()
        return None if row is None else (row["batch_id"], row["leaf_index"])

    @staticmethod
    def _to_batch(row: sqlite3.Row) -> Batch:
        return Batch(
            batch_id=row["batch_id"],
            prev_root=row["prev_root"],
            root=row["root"],
            leaf_count=row["leaf_count"],
            sealed_at_ns=row["sealed_at_ns"],
            mapping_set=json.loads(row["mapping_set"]),
            first_uid=row["first_uid"],
            last_uid=row["last_uid"],
            signature=row["signature"],
            signer=row["signer"],
        )

    # ---- checkpoints ------------------------------------------------------

    def create_checkpoint(self, day: str) -> Checkpoint:
        """Anchor every batch sealed so far with the offline root key."""
        if self.checkpoint_key is None or not self.checkpoint_key.can_sign:
            raise ValueError("a signing checkpoint key is required")

        row = self._conn.execute(
            "SELECT MIN(batch_id) AS lo, MAX(batch_id) AS hi, COUNT(*) AS n,"
            " COALESCE(SUM(leaf_count), 0) AS events FROM batches"
        ).fetchone()
        if row["n"] == 0:
            raise ValueError("nothing to checkpoint: the ledger is empty")

        cid = int(
            self._conn.execute(
                "SELECT COALESCE(MAX(checkpoint_id), 0) + 1 FROM checkpoints"
            ).fetchone()[0]
        )

        partial = Checkpoint(
            checkpoint_id=cid,
            day=day,
            first_batch=row["lo"],
            last_batch=row["hi"],
            chain_head=self.head,
            batch_count=row["n"],
            event_count=row["events"],
            created_at_ns=time.time_ns(),
            signature="",
            signer="",
        )
        signature = self.checkpoint_key.sign(partial.payload())

        self._conn.execute(
            "INSERT INTO checkpoints (checkpoint_id, day, first_batch, last_batch,"
            " chain_head, batch_count, event_count, created_at_ns, signature, signer)"
            " VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                cid, day, partial.first_batch, partial.last_batch,
                partial.chain_head, partial.batch_count, partial.event_count,
                partial.created_at_ns, signature, self.checkpoint_key.public_hex,
            ),
        )
        self._conn.commit()

        return Checkpoint(
            checkpoint_id=cid,
            day=day,
            first_batch=partial.first_batch,
            last_batch=partial.last_batch,
            chain_head=partial.chain_head,
            batch_count=partial.batch_count,
            event_count=partial.event_count,
            created_at_ns=partial.created_at_ns,
            signature=signature,
            signer=self.checkpoint_key.public_hex,
        )

    def checkpoints(self) -> list[Checkpoint]:
        return [
            Checkpoint(
                checkpoint_id=r["checkpoint_id"],
                day=r["day"],
                first_batch=r["first_batch"],
                last_batch=r["last_batch"],
                chain_head=r["chain_head"],
                batch_count=r["batch_count"],
                event_count=r["event_count"],
                created_at_ns=r["created_at_ns"],
                signature=r["signature"],
                signer=r["signer"],
            )
            for r in self._conn.execute(
                "SELECT * FROM checkpoints ORDER BY checkpoint_id"
            )
        ]

    # ---- verification -----------------------------------------------------

    def verify(
        self,
        *,
        store=None,
        start: int = 1,
        end: int | None = None,
    ) -> VerifyResult:
        """Recompute the chain and report the first divergence.

        With ``store`` supplied, each event's bytes are re-hashed from the raw
        store, so this detects a modified or deleted *event*, not merely a
        modified ledger row.
        """
        result = VerifyResult(ok=True)
        expected_prev = GENESIS if start == 1 else None

        for batch in self.iter_batches(start=start, end=end):
            if expected_prev is not None and batch.prev_root != expected_prev:
                return VerifyResult(
                    ok=False,
                    batches_checked=result.batches_checked,
                    events_checked=result.events_checked,
                    first_divergence=batch.batch_id,
                    reason=(
                        f"prev_root {batch.prev_root[:12]}... does not match the "
                        f"previous batch's root {expected_prev[:12]}..."
                    ),
                )

            leaves_meta = self.leaves_of(batch.batch_id)
            if len(leaves_meta) != batch.leaf_count:
                return VerifyResult(
                    ok=False,
                    batches_checked=result.batches_checked,
                    events_checked=result.events_checked,
                    first_divergence=batch.batch_id,
                    reason=(
                        f"batch claims {batch.leaf_count} leaves but "
                        f"{len(leaves_meta)} are recorded"
                    ),
                )

            leaf_hashes: list[str] = []
            for uid, raw_hash in leaves_meta:
                if store is not None:
                    import uuid as _uuid

                    event = store.get(_uuid.UUID(uid))
                    if event is None:
                        return VerifyResult(
                            ok=False,
                            batches_checked=result.batches_checked,
                            events_checked=result.events_checked,
                            first_divergence=batch.batch_id,
                            reason=f"event {uid} is missing from the raw store",
                        )
                    # Re-hash the bytes themselves, so a substituted payload is
                    # caught even if the stored hash column was edited to match.
                    if not event.verify() or event.raw_hash != raw_hash:
                        return VerifyResult(
                            ok=False,
                            batches_checked=result.batches_checked,
                            events_checked=result.events_checked,
                            first_divergence=batch.batch_id,
                            reason=f"event {uid} no longer hashes to its sealed value",
                        )
                leaf_hashes.append(leaf_for(uid, raw_hash))
                result.events_checked += 1

            inner = MerkleTree(leaf_hashes).root if leaf_hashes else MerkleTree([]).root
            recomputed = MerkleTree([batch.prev_root, inner]).root
            if recomputed != batch.root:
                return VerifyResult(
                    ok=False,
                    batches_checked=result.batches_checked,
                    events_checked=result.events_checked,
                    first_divergence=batch.batch_id,
                    reason=(
                        f"recomputed root {recomputed[:12]}... does not match the "
                        f"sealed root {batch.root[:12]}..."
                    ),
                )

            if batch.signature and batch.signer:
                verifier = KeyPair.from_public_hex(batch.signer, label="batch")
                if not verifier.verify(batch.payload(), batch.signature):
                    return VerifyResult(
                        ok=False,
                        batches_checked=result.batches_checked,
                        events_checked=result.events_checked,
                        first_divergence=batch.batch_id,
                        reason="batch signature does not verify",
                    )

            result.batches_checked += 1
            expected_prev = batch.root

        for checkpoint in self.checkpoints():
            if not (start <= checkpoint.last_batch and
                    (end is None or checkpoint.first_batch <= end)):
                continue
            verifier = KeyPair.from_public_hex(checkpoint.signer, label="checkpoint")
            if not verifier.verify(checkpoint.payload(), checkpoint.signature):
                return VerifyResult(
                    ok=False,
                    batches_checked=result.batches_checked,
                    events_checked=result.events_checked,
                    first_divergence=checkpoint.last_batch,
                    reason=f"checkpoint for {checkpoint.day} does not verify",
                )
            result.checkpoints_checked += 1

        return result

    def close(self) -> None:
        self._conn.close()

    def __enter__(self) -> "Ledger":
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()
