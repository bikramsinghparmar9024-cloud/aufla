"""The ingest pipeline: capture, seal, normalise, persist.

Order matters and is not negotiable:

1. **Capture** the bytes into the raw store.
2. **Seal** them into the ledger.
3. **Normalise**, which may fail, quarantine, or be deferred indefinitely.
4. **Persist** the projection, so the OCSF form is materialised rather than
   recomputed on every read.

Steps 1 and 2 are deterministic and bounded. Step 3 is where mappings, and
eventually a model, get involved -- so it runs last and can fail without
costing a single event. An unrecognised format is a deferred projection, not a
lost log.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Sequence

from .ledger import Ledger
from .mapping import MappingRegistry
from .models import ParseStatus, RawEvent, Transport
from .normalize import NormalizedRecord, Normalizer
from .storage import OCSFStore, RawStore

__all__ = ["Pipeline", "IngestResult"]


@dataclass(slots=True)
class IngestResult:
    """What one ingest call did."""

    submitted: int = 0
    accepted: int = 0
    duplicates: int = 0
    sealed_batches: int = 0
    normalized: int = 0
    partial: int = 0
    quarantined: int = 0
    resolved: int = 0
    records: list[NormalizedRecord] = field(default_factory=list)

    @property
    def coverage(self) -> float:
        """Share of accepted events that normalised fully."""
        return 0.0 if not self.accepted else self.normalized / self.accepted

    def __str__(self) -> str:
        out = (
            f"{self.accepted} accepted ({self.duplicates} duplicate), "
            f"{self.sealed_batches} batches sealed, "
            f"{self.normalized} normalised, {self.partial} partial, "
            f"{self.quarantined} quarantined"
        )
        return out + (f", {self.resolved} resolved" if self.resolved else "")


class Pipeline:
    """Wires the raw store, the ledger, the normaliser and the projection."""

    def __init__(
        self,
        store: RawStore,
        ledger: Ledger,
        registry: MappingRegistry,
        *,
        normalizer: Normalizer | None = None,
        ocsf: OCSFStore | None = None,
    ) -> None:
        self.store = store
        self.ledger = ledger
        self.registry = registry
        self.normalizer = normalizer or Normalizer(registry)
        self.ocsf = ocsf

    def ingest(
        self,
        payloads: Iterable[bytes],
        source_id: str,
        *,
        transport: Transport = Transport.TCP,
        source_ip: str | None = None,
        seal: bool = True,
    ) -> IngestResult:
        """Ingest raw payloads from one source."""
        result = IngestResult()

        events = [
            RawEvent.capture(
                payload, source_id, transport=transport, source_ip=source_ip
            )
            for payload in payloads
        ]
        result.submitted = len(events)
        if not events:
            return result

        # 1. Capture. Deduplication happens here, so only genuinely new events
        #    reach the ledger and the counts stay honest.
        stats = self.store.append(events)
        result.accepted = stats.accepted
        result.duplicates = stats.duplicates

        accepted = self._accepted_only(events) if stats.duplicates else events

        # 2. Seal.
        mapping_set = self.registry.hashes()
        sealed = self.ledger.add(accepted, mapping_set=mapping_set)
        result.sealed_batches = len(sealed)
        if seal and self.ledger._pending:
            self.ledger.seal(mapping_set=mapping_set)
            result.sealed_batches += 1

        # 3. Normalise. Anything here may fail without costing an event.
        for event in accepted:
            record = self.normalizer.normalize(event)
            result.records.append(record)
            if record.parse_status is ParseStatus.FULL:
                result.normalized += 1
            elif record.parse_status is ParseStatus.PARTIAL:
                result.partial += 1
            else:
                result.quarantined += 1

        # 4. Persist the projection.
        if self.ocsf is not None and result.records:
            result.resolved = self.ocsf.upsert(result.records)["resolved"]

        return result

    def _accepted_only(self, events: Sequence[RawEvent]) -> list[RawEvent]:
        """Drop redelivered events so the ledger seals each event once."""
        seen: set[str] = set()
        out: list[RawEvent] = []
        for event in events:
            if event.idem_key in seen:
                continue
            seen.add(event.idem_key)
            if self.ledger.locate(str(event.event_uid)) is None:
                out.append(event)
        return out

    def backfill(self, source_id: str, *, batch: int = 500) -> dict[str, int]:
        """Re-derive projections for one source from the raw store.

        This is the operation that makes a mapping correction safe: rather than
        patching normalised rows, they are rebuilt from the canonical bytes. It
        is only possible because raw is canonical.

        Work is committed in batches so a long backfill cannot hold a single
        transaction open across millions of events.
        """
        self.registry.refresh()
        totals = {"processed": 0, "normalized": 0, "resolved": 0}
        pending: list[NormalizedRecord] = []

        def flush() -> None:
            if not pending or self.ocsf is None:
                pending.clear()
                return
            outcome = self.ocsf.upsert(pending)
            totals["resolved"] += outcome["resolved"]
            pending.clear()

        for event in self.store.iter_events(source_id=source_id):
            record = self.normalizer.normalize(event)
            totals["processed"] += 1
            if record.parse_status is not ParseStatus.QUARANTINED:
                totals["normalized"] += 1
            pending.append(record)
            if len(pending) >= batch:
                flush()

        flush()
        return totals

    def verify(self, **kwargs) -> object:
        """Recompute the chain against the raw store."""
        return self.ledger.verify(store=self.store, **kwargs)
