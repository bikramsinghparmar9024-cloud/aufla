"""The AUFLA dashboard: read-only forensics plus append-only live capture.

Built on the standard library rather than a web framework, for the same reason
the rest of AUFLA is: it has to run on an air-gapped host with nothing
installed. No CDN, no web font, no external asset of any kind, enforced by a
Content-Security-Policy of ``default-src 'self'``.

What the browser may and may not do
-----------------------------------
Every GET route is read-only. The only writes the UI can trigger are
``/api/live/start`` and ``/api/live/stop``, which control the local collector.
That collector **only appends**: it captures new events from this host, stores
and seals them. Nothing reachable from a browser can update or delete an
existing event, ledger row, or mapping. The guarantee on existing evidence is
unchanged; the button adds new evidence.

Threading and database handles
------------------------------
Requests are handled on threads, and **each request opens its own SQLite
connections**, because Python reports ``sqlite3.threadsafety == 1`` here: a
connection may not be shared between threads.

Serial handling was tried first and is wrong for a browser client. Browsers
preconnect -- they open speculative sockets and send nothing on them. A
single-threaded server accepts one of those and blocks reading it forever, so
the UI hangs even though every request it did send was answered. ``curl`` never
behaves that way, which is exactly why a curl-based smoke test passes while the
real page hangs.
"""

from __future__ import annotations

import json
import time
import uuid
from collections import Counter, defaultdict
from contextlib import contextmanager
from datetime import datetime, timezone
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qs, urlparse

from ..collect import LiveCollector
from ..ledger import Ledger
from ..ledger.signing import load_or_create_keypair
from ..mapping import MappingRegistry
from ..normalize import Normalizer
from ..ocsf.classes import CATALOG
from ..pipeline import Pipeline
from ..storage import SQLiteRawStore

__all__ = ["build_server", "serve", "ForensicHandler"]

STATIC = Path(__file__).parent / "index.html"

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
        registry: MappingRegistry,
        collector: LiveCollector,
        **kwargs,
    ) -> None:
        self.data_dir = data_dir
        self.registry = registry
        self.collector = collector
        self.normalizer = Normalizer(registry)
        super().__init__(*args, **kwargs)

    @contextmanager
    def _db(self) -> Iterator[tuple[SQLiteRawStore, Ledger]]:
        """Connections owned by this request's thread, closed on exit."""
        store = SQLiteRawStore(self.data_dir / "raw.db")
        ledger = Ledger(self.data_dir / "ledger.db")
        try:
            yield store, ledger
        finally:
            store.close()
            ledger.close()

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
            else:
                self._json(
                    {
                        "error": "read-only: the only writes are "
                        "/api/live/start and /api/live/stop"
                    },
                    status=405,
                )
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
                self._json(self.collector.status.as_dict())
                return

            with self._db() as (store, ledger):
                if route == "/api/stats":
                    self._json(self._stats(store, ledger))
                elif route == "/api/overview":
                    self._json(self._overview(store, ledger))
                elif route == "/api/events":
                    self._json(self._events(store, query))
                elif route.startswith("/api/event/"):
                    self._json(self._event(store, ledger, route.rsplit("/", 1)[-1]))
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

    # ---- data -------------------------------------------------------------

    def _stats(self, store, ledger) -> dict[str, Any]:
        return {
            "raw_events": store.count(),
            "sealed_events": ledger.event_count,
            "batches": ledger.batch_count,
            "checkpoints": len(ledger.checkpoints()),
            "chain_head": ledger.head,
            "mappings": len(self.registry),
        }

    def _overview(self, store, ledger) -> dict[str, Any]:
        """Aggregations for the dashboard charts, computed in one pass."""
        by_source: Counter[str] = Counter()
        by_status: Counter[str] = Counter()
        by_class: Counter[str] = Counter()
        by_severity: Counter[int] = Counter()
        talkers: Counter[str] = Counter()
        timeline: dict[int, Counter[str]] = defaultdict(Counter)
        findings: list[dict[str, Any]] = []
        coverage_sum = 0.0
        counted = 0

        events = list(store.iter_events())
        # Bucket the observed window into ~40 columns so the timeline reads the
        # same whether it covers two minutes of live capture or a whole day.
        times = [e.received_at_ns // 1_000_000 for e in events]
        lo, hi = (min(times), max(times)) if times else (0, 0)
        span = max(hi - lo, 1)
        bucket_ms = max(span // 40, 1000)

        for event in events:
            record = self.normalizer.normalize(event)
            by_source[event.source_id] += 1
            by_status[record.parse_status.value] += 1
            coverage_sum += record.mapping_coverage
            counted += 1

            ms = event.received_at_ns // 1_000_000
            timeline[(ms - lo) // bucket_ms][event.source_id] += 1

            if record.ocsf_class:
                name = CATALOG[record.ocsf_class].name if record.ocsf_class in CATALOG \
                    else str(record.ocsf_class)
                by_class[name] += 1

            severity = record.fields.get("severity_id")
            if isinstance(severity, int):
                by_severity[severity] += 1

            dst = record.fields.get("dst_endpoint.ip")
            if dst:
                talkers[str(dst)] += 1

            title = record.fields.get("finding_info.title")
            if title and isinstance(severity, int) and severity >= 3:
                findings.append(
                    {
                        "event_uid": str(event.event_uid),
                        "time": event.received_at_iso,
                        "source": event.source_id,
                        "title": str(title),
                        "severity": severity,
                        "severity_name": SEVERITY_NAMES.get(severity, "?"),
                    }
                )

        sources = [s for s, _ in by_source.most_common()]
        buckets = sorted(timeline)
        series = [
            {
                "t": lo + b * bucket_ms,
                "total": sum(timeline[b].values()),
                **{s: timeline[b].get(s, 0) for s in sources},
            }
            for b in buckets
        ]

        return {
            "timeline": {"sources": sources, "bucket_ms": bucket_ms, "points": series},
            "by_source": by_source.most_common(),
            "by_status": dict(by_status),
            "by_class": by_class.most_common(),
            "by_severity": [
                [SEVERITY_NAMES.get(k, str(k)), v] for k, v in sorted(by_severity.items())
            ],
            "top_talkers": talkers.most_common(8),
            "avg_coverage": round(coverage_sum / counted, 4) if counted else 0.0,
            "findings": sorted(findings, key=lambda f: -f["severity"])[:12],
        }

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
                "path": m.path,
            }
            for m in sorted(self.registry, key=lambda m: m.source)
        ]

    def _events(self, store, query: dict[str, list[str]]) -> list[dict[str, Any]]:
        limit = min(int(query.get("limit", ["300"])[0]), 2000)
        source = query.get("source", [None])[0] or None
        status = query.get("status", [None])[0] or None
        needle = (query.get("q", [""])[0] or "").lower()

        out: list[dict[str, Any]] = []
        for event in store.iter_events(source_id=source):
            record = self.normalizer.normalize(event)
            if status and record.parse_status.value != status:
                continue
            summary = _summarise(record)
            if needle and needle not in (
                summary + event.source_id + event.text()
            ).lower():
                continue
            out.append(
                {
                    "event_uid": str(event.event_uid),
                    "source_id": event.source_id,
                    "received_at": event.received_at_iso,
                    "byte_len": event.byte_len,
                    "transport": event.transport.value,
                    "parse_status": record.parse_status.value,
                    "ocsf_class": record.ocsf_class,
                    "class_name": CATALOG[record.ocsf_class].name
                    if record.ocsf_class in CATALOG
                    else None,
                    "severity": record.fields.get("severity_id"),
                    "rule": record.rule_name,
                    "coverage": round(record.mapping_coverage, 3),
                    "warnings": len(record.warnings),
                    "summary": summary,
                }
            )
            if len(out) >= limit:
                break
        out.reverse()  # newest first
        return out

    def _event(self, store, ledger, uid: str) -> dict[str, Any]:
        try:
            event_uid = uuid.UUID(uid)
        except ValueError:
            return {"error": f"not a uuid: {uid}"}

        event = store.get(event_uid)
        if event is None:
            return {"error": f"no event {uid}"}

        record = self.normalizer.normalize(event)
        located = ledger.locate(uid)
        batch = ledger.get_batch(located[0]) if located else None

        from ..output import get_adapter

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
            "normalized": record.to_dict(),
            "warnings": record.warnings,
            "errors": record.errors,
            "exports": {
                "cef": get_adapter("cef").render(record),
                "leef": get_adapter("leef").render(record),
            }
            if record.ocsf_class
            else {},
            "ledger": None
            if batch is None
            else {
                "batch_id": batch.batch_id,
                "leaf_index": located[1],
                "root": batch.root,
                "prev_root": batch.prev_root,
                "signed": bool(batch.signature),
                "mapping_set": batch.mapping_set,
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


def _summarise(record) -> str:
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


def _make_pipeline_factory(data_dir: Path, registry: MappingRegistry):
    """Hand the collector a fresh pipeline per tick, with its own handles."""

    def factory():
        store = SQLiteRawStore(data_dir / "raw.db")
        ledger = Ledger(
            data_dir / "ledger.db",
            batch_key=load_or_create_keypair(data_dir / "keys" / "batch.pem", "batch"),
        )
        pipeline = Pipeline(store, ledger, registry)

        def closer() -> None:
            store.close()
            ledger.close()

        return pipeline, closer

    return factory


def build_server(
    data_dir: str | Path,
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
        ForensicHandler, data_dir=data, registry=registry, collector=collector
    )
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    server.collector = collector  # type: ignore[attr-defined]
    return server


def serve(
    data_dir: str | Path,
    registry: MappingRegistry,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
    interval: float = 10.0,
) -> None:  # pragma: no cover - blocking
    httpd = build_server(
        data_dir, registry, host=host, port=port, interval=interval
    )
    print(f"AUFLA dashboard on http://{host}:{port}")
    print("  read-only, except Live Capture (append-only). Ctrl+C to stop.")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopping")
    finally:
        httpd.collector.stop()  # type: ignore[attr-defined]
        httpd.server_close()
