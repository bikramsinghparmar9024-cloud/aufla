"""The AUFLA dashboard.

Built on the standard library rather than a web framework, for the same reason
the rest of AUFLA is: it has to run on an air-gapped host with nothing
installed. No CDN, no web font, no external asset of any kind, enforced by a
Content-Security-Policy of ``default-src 'self'``.

What the browser may and may not do
-----------------------------------
Every GET route is read-only. Four POST routes exist, and each of them only
ever *adds*:

``/api/live/start`` and ``/api/live/stop``
    control local collection, which appends new events;
``/api/discovery/run``
    proposes mappings for quarantined sources;
``/api/proposals/<id>/approve`` and ``/reject``
    record a named person's decision on a proposal.

Nothing reachable from a browser updates or deletes an existing event or
ledger row. Approving a mapping rewrites the *derived* projection, which is
rebuildable from raw by definition; the evidence underneath is untouched.

Reads come from the materialised OCSF projection, not from re-parsing raw on
every request. Aggregations are SQL. That is the difference between a console
that works on a demo dataset and one that works on a real day's traffic.
"""

from __future__ import annotations

import json
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qs, urlparse

from ..collect import LiveCollector
from ..discovery import CONFIDENCE_BAR, ProposalStore, approve_proposal, run_discovery
from ..ledger import Ledger
from ..ledger.signing import load_or_create_keypair
from ..mapping import MappingRegistry
from ..normalize import Normalizer
from ..ocsf.classes import CATALOG
from ..pipeline import Pipeline
from ..storage import OCSFStore, SQLiteRawStore

__all__ = ["build_server", "serve", "ForensicHandler"]

STATIC = Path(__file__).parent / "index.html"

RANGES: dict[str, int] = {
    "15m": 900, "1h": 3600, "6h": 21600, "24h": 86400, "7d": 604800,
}
DEFAULT_RANGE = "1h"

SEVERITY_NAMES = {
    0: "Unknown", 1: "Informational", 2: "Low", 3: "Medium",
    4: "High", 5: "Critical", 6: "Fatal",
}


class ForensicHandler(BaseHTTPRequestHandler):
    """HTTP surface over the pipeline."""

    server_version = "AUFLA-Dashboard"
    timeout = 20

    def __init__(
        self,
        *args,
        data_dir: Path,
        sources_dir: Path,
        registry: MappingRegistry,
        collector: LiveCollector,
        **kwargs,
    ) -> None:
        self.data_dir = data_dir
        self.sources_dir = sources_dir
        self.registry = registry
        self.collector = collector
        self.normalizer = Normalizer(registry)
        super().__init__(*args, **kwargs)

    @contextmanager
    def _db(self) -> Iterator[tuple[SQLiteRawStore, Ledger, OCSFStore, ProposalStore]]:
        """Connections owned by this request's thread, closed on exit."""
        store = SQLiteRawStore(self.data_dir / "raw.db")
        ledger = Ledger(self.data_dir / "ledger.db")
        ocsf = OCSFStore(self.data_dir / "ocsf.db")
        proposals = ProposalStore(self.data_dir / "proposals.db")
        try:
            yield store, ledger, ocsf, proposals
        finally:
            store.close()
            ledger.close()
            ocsf.close()
            proposals.close()

    def _pipeline(self, store, ledger, ocsf) -> Pipeline:
        return Pipeline(store, ledger, self.registry, ocsf=ocsf)

    # ---- plumbing ---------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:  # pragma: no cover
        return

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Cache-Control", "no-store")
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'; img-src 'self' data:",
        )
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def _json(self, payload: Any, status: int = 200) -> None:
        self._send(
            status,
            json.dumps(payload, default=str).encode("utf-8"),
            "application/json; charset=utf-8",
        )

    def _body(self) -> dict[str, Any]:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            return {}
        if length <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(length).decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            return {}

    # ---- routing ----------------------------------------------------------

    def do_POST(self) -> None:  # noqa: N802
        route = urlparse(self.path).path.rstrip("/") or "/"
        try:
            if route == "/api/live/start":
                self.collector.start()
                self._json(self.collector.status.as_dict())
            elif route == "/api/live/stop":
                self.collector.stop()
                self._json(self.collector.status.as_dict())
            elif route == "/api/discovery/run":
                self._json(self._run_discovery())
            elif route.startswith("/api/proposals/"):
                self._json(self._decide(route))
            else:
                self._json({"error": f"no write route {route}"}, status=405)
        except Exception as exc:  # pragma: no cover - defensive
            self._json({"error": f"{type(exc).__name__}: {exc}"}, status=500)

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlparse(self.path)
        route = parsed.path.rstrip("/") or "/"
        query = parse_qs(parsed.query)

        try:
            if route == "/":
                self._serve_page()
                return
            if route == "/api/sources":
                self._json(self._sources())
                return
            if route == "/api/live/status":
                self._json(
                    {**self.collector.status.as_dict(), "ui_version": _ui_version()}
                )
                return

            with self._db() as (store, ledger, ocsf, proposals):
                if route == "/api/stats":
                    self._json(self._stats(store, ledger, ocsf, proposals))
                elif route == "/api/overview":
                    self._json(self._overview(ocsf, query))
                elif route == "/api/events":
                    self._json(self._events(ocsf, query))
                elif route.startswith("/api/event/"):
                    self._json(
                        self._event(store, ledger, ocsf, route.rsplit("/", 1)[-1])
                    )
                elif route == "/api/quarantine":
                    self._json(self._quarantine(ocsf, proposals))
                elif route == "/api/proposals":
                    self._json(self._proposals(proposals))
                elif route == "/api/integrity":
                    self._json(self._integrity(ledger))
                elif route == "/api/verify":
                    self._json(self._verify(store, ledger))
                else:
                    self._json({"error": f"no route {route}"}, status=404)
        except Exception as exc:  # pragma: no cover - defensive
            self._json({"error": f"{type(exc).__name__}: {exc}"}, status=500)

    def _serve_page(self) -> None:
        self._send(200, STATIC.read_bytes(), "text/html; charset=utf-8")

    # ---- discovery --------------------------------------------------------

    def _run_discovery(self) -> dict[str, Any]:
        with self._db() as (store, ledger, ocsf, proposals):
            pipeline = self._pipeline(store, ledger, ocsf)
            result = run_discovery(pipeline, proposals, self.sources_dir)
            return result.as_dict()

    def _decide(self, route: str) -> dict[str, Any]:
        parts = route.strip("/").split("/")
        if len(parts) != 4:
            return {"error": f"no write route {route}"}
        try:
            proposal_id = int(parts[2])
        except ValueError:
            return {"error": f"not a proposal id: {parts[2]}"}

        action = parts[3]
        payload = self._body()
        who = (payload.get("by") or "").strip()
        if not who:
            # A decision with no name attached is not an audit record. The API
            # refuses rather than inventing an actor.
            return {"error": "an approval must name the person making it"}

        with self._db() as (store, ledger, ocsf, proposals):
            if action == "approve":
                pipeline = self._pipeline(store, ledger, ocsf)
                return approve_proposal(
                    pipeline, proposals, self.sources_dir, proposal_id,
                    approved_by=who, note=payload.get("note"),
                )
            if action == "reject":
                decided = proposals.decide(
                    proposal_id, state="rejected", by=who, note=payload.get("note")
                )
                if decided is None:
                    return {"error": f"no pending proposal {proposal_id}"}
                return {"rejected": decided.source_id, "by": who}
        return {"error": f"unknown action {action}"}

    # ---- data -------------------------------------------------------------

    def _stats(self, store, ledger, ocsf, proposals) -> dict[str, Any]:
        return {
            "raw_events": store.count(),
            "sealed_events": ledger.event_count,
            "batches": ledger.batch_count,
            "checkpoints": len(ledger.checkpoints()),
            "chain_head": ledger.head,
            "mappings": len(self.registry),
            "projected": ocsf.count(),
            "quarantine": ocsf.quarantine_summary(),
            "proposals": proposals.counts(),
        }

    def _window(self, query) -> tuple[str, int | None]:
        window = (query.get("range", [DEFAULT_RANGE])[0] or DEFAULT_RANGE).lower()
        if window != "all" and window not in RANGES:
            window = DEFAULT_RANGE
        seconds = RANGES.get(window)
        since_ms = (
            None if seconds is None else int(time.time() * 1000) - seconds * 1000
        )
        return window, since_ms

    def _overview(self, ocsf, query) -> dict[str, Any]:
        window, since_ms = self._window(query)

        by_class = [
            (CATALOG[k].name if k in CATALOG else str(k), n)
            for k, n in ocsf.counts_by("class_uid", since_ms=since_ms)
        ]
        by_severity = [
            (SEVERITY_NAMES.get(k, str(k)), n)
            for k, n in ocsf.counts_by("severity_id", since_ms=since_ms)
        ]
        status = dict(ocsf.counts_by("parse_status", since_ms=since_ms))

        return {
            "range": window,
            "ranges": [*RANGES, "all"],
            "event_count": ocsf.event_count(since_ms=since_ms),
            "timeline": ocsf.timeline(since_ms=since_ms),
            "by_source": ocsf.counts_by("source_id", since_ms=since_ms),
            "by_status": status,
            "by_class": by_class,
            "by_severity": by_severity,
            "top_talkers": ocsf.counts_by("dst_ip", since_ms=since_ms, limit=8),
            "avg_coverage": ocsf.average_coverage(since_ms=since_ms),
            "findings": [
                {
                    "event_uid": f["event_uid"],
                    "time": _iso_ms(f["observed_time"]),
                    "source": f["source_id"],
                    "title": f["summary"],
                    "severity": f["severity_id"],
                    "severity_name": SEVERITY_NAMES.get(f["severity_id"], "?"),
                }
                for f in ocsf.findings(since_ms=since_ms)
            ],
        }

    def _quarantine(self, ocsf, proposals) -> dict[str, Any]:
        summary = ocsf.quarantine_summary()
        return {
            **summary,
            "bar": CONFIDENCE_BAR,
            "by_source": ocsf.quarantined_sources(),
            "proposals": proposals.counts(),
            "recent": [
                {
                    "source": p.source_id,
                    "state": p.state,
                    "confidence": round(p.confidence, 4),
                    "decided_by": p.decided_by,
                    "decided_ns": p.decided_ns,
                }
                for p in proposals.history(limit=10)
            ],
        }

    def _proposals(self, proposals) -> list[dict[str, Any]]:
        return [p.as_dict() for p in proposals.pending()]

    def _sources(self) -> list[dict[str, Any]]:
        return [
            {
                "source": m.source,
                "format": m.format,
                "version": m.version,
                "ocsf_classes": [
                    {"uid": c, "name": CATALOG[c].name if c in CATALOG else str(c)}
                    for c in m.ocsf_classes
                ],
                "rules": [r.name for r in m.rules],
                "approved_by": m.approved_by,
                "author": m.author,
                "content_hash": m.content_hash(),
                "description": m.description,
            }
            for m in sorted(self.registry, key=lambda m: m.source)
        ]

    def _events(self, ocsf, query) -> list[dict[str, Any]]:
        limit = min(int(query.get("limit", ["300"])[0]), 2000)
        rows = ocsf.query(
            source_id=query.get("source", [None])[0] or None,
            status=query.get("status", [None])[0] or None,
            search=query.get("q", [""])[0] or None,
            limit=limit,
        )
        return [
            {
                "event_uid": r["event_uid"],
                "source_id": r["source_id"],
                "received_at": _iso_ms(r["observed_time"]),
                "parse_status": r["parse_status"],
                "first_status": r["first_status"],
                "resolved": r["resolved"],
                "ocsf_class": r["class_uid"],
                "class_name": CATALOG[r["class_uid"]].name
                if r["class_uid"] in CATALOG else None,
                "severity": r["severity_id"],
                "rule": r["rule_name"],
                "coverage": round(r["mapping_coverage"], 3),
                "warnings": len(r["warnings"]),
                "summary": r["summary"],
            }
            for r in rows
        ]

    def _event(self, store, ledger, ocsf, uid: str) -> dict[str, Any]:
        try:
            event_uid = uuid.UUID(uid)
        except ValueError:
            return {"error": f"not a uuid: {uid}"}

        event = store.get(event_uid)
        if event is None:
            return {"error": f"no event {uid}"}

        projection = ocsf.get(uid)
        # Fall back to deriving on the spot for an event ingested before the
        # projection existed, so no event is ever unviewable.
        record = None if projection else self.normalizer.normalize(event)
        located = ledger.locate(uid)
        batch = ledger.get_batch(located[0]) if located else None

        from ..output import get_adapter

        if projection:
            normalized = {
                "parse_status": projection["parse_status"],
                "first_status": projection["first_status"],
                "resolved": projection["resolved"],
                "observed_time": projection["observed_time"],
                "class_uid": projection["class_uid"],
                "mapping_id": projection["mapping_id"],
                "mapping_version": projection["mapping_version"],
                "rule_name": projection["rule_name"],
                "mapping_coverage": projection["mapping_coverage"],
                **projection["fields"],
            }
            warnings = projection["warnings"]
            notes = projection["notes"]
            exports = {}
            if record is None and projection["class_uid"]:
                live = self.normalizer.normalize(event)
                exports = {
                    "cef": get_adapter("cef").render(live),
                    "leef": get_adapter("leef").render(live),
                }
        else:
            normalized = record.to_dict()
            warnings, notes = record.warnings, record.notes
            exports = (
                {
                    "cef": get_adapter("cef").render(record),
                    "leef": get_adapter("leef").render(record),
                }
                if record.ocsf_class
                else {}
            )

        return {
            "raw": {
                "event_uid": str(event.event_uid),
                "source_id": event.source_id,
                "received_at": event.received_at_iso,
                "transport": event.transport.value,
                "source_ip": event.source_ip,
                "byte_len": event.byte_len,
                "truncated": event.truncated,
                "raw_hash": event.raw_hash,
                "text": event.text(),
                "hex": event.raw_bytes.hex(),
                "hash_verified": event.verify(),
            },
            "normalized": normalized,
            "warnings": warnings,
            "notes": notes,
            "exports": exports,
            "ledger": None
            if batch is None
            else {
                "batch_id": batch.batch_id,
                "leaf_index": located[1],
                "root": batch.root,
                "prev_root": batch.prev_root,
                "signed": bool(batch.signature),
            },
        }

    def _integrity(self, ledger) -> dict[str, Any]:
        batches = [
            {
                "batch_id": b.batch_id,
                "leaf_count": b.leaf_count,
                "root": b.root,
                "prev_root": b.prev_root,
                "sealed_at": datetime.fromtimestamp(
                    b.sealed_at_ns / 1e9, tz=timezone.utc
                ).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "signed": bool(b.signature),
                "mappings": len(b.mapping_set),
            }
            for b in ledger.iter_batches()
        ]
        return {
            "head": ledger.head,
            "batches": batches[-40:],
            "batch_total": len(batches),
            "checkpoints": [
                {
                    "day": c.day,
                    "first_batch": c.first_batch,
                    "last_batch": c.last_batch,
                    "chain_head": c.chain_head,
                    "event_count": c.event_count,
                }
                for c in ledger.checkpoints()
            ],
        }

    def _verify(self, store, ledger) -> dict[str, Any]:
        started = time.perf_counter()
        result = ledger.verify(store=store)
        return {
            "ok": result.ok,
            "text": str(result),
            "batches_checked": result.batches_checked,
            "events_checked": result.events_checked,
            "checkpoints_checked": result.checkpoints_checked,
            "first_divergence": result.first_divergence,
            "reason": result.reason,
            "elapsed_ms": round((time.perf_counter() - started) * 1000, 1),
        }


def _iso_ms(ms: int) -> str:
    return (
        datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
        .strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3]
        + "Z"
    )


def _ui_version() -> str:
    """Identity of the page on disk, so an open tab notices it went stale."""
    try:
        st = STATIC.stat()
        return f"{st.st_mtime_ns}-{st.st_size}"
    except OSError:  # pragma: no cover - defensive
        return "unknown"


def _make_pipeline_factory(data_dir: Path, registry: MappingRegistry):
    """Hand the collector a fresh pipeline per tick, with its own handles."""

    def factory():
        store = SQLiteRawStore(data_dir / "raw.db")
        ledger = Ledger(
            data_dir / "ledger.db",
            batch_key=load_or_create_keypair(data_dir / "keys" / "batch.pem", "batch"),
        )
        ocsf = OCSFStore(data_dir / "ocsf.db")
        pipeline = Pipeline(store, ledger, registry, ocsf=ocsf)

        def closer() -> None:
            store.close()
            ledger.close()
            ocsf.close()

        return pipeline, closer

    return factory


def build_server(
    data_dir: str | Path,
    sources_dir: str | Path,
    registry: MappingRegistry,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    interval: float = 10.0,
) -> ThreadingHTTPServer:
    data = Path(data_dir)
    collector = LiveCollector(
        _make_pipeline_factory(data, registry), interval=interval
    )
    handler = partial(
        ForensicHandler,
        data_dir=data,
        sources_dir=Path(sources_dir),
        registry=registry,
        collector=collector,
    )
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    server.collector = collector  # type: ignore[attr-defined]
    return server


def serve(
    data_dir: str | Path,
    sources_dir: str | Path,
    registry: MappingRegistry,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    interval: float = 10.0,
) -> None:  # pragma: no cover - blocking
    httpd = build_server(
        data_dir, sources_dir, registry, host=host, port=port, interval=interval
    )
    print(f"AUFLA dashboard on http://{host}:{port}")
    print("  reads are read-only; writes append events or record decisions.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        httpd.collector.stop()  # type: ignore[attr-defined]
        httpd.server_close()
