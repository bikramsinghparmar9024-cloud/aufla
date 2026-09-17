"""The Forensic Explorer web UI.

Built on the standard library rather than a web framework, for the same reason
the rest of AUFLA is: it has to run on an air-gapped host with nothing
installed. No CDN, no web font, no external asset of any kind -- the page is a
single self-contained file, which is also what makes it deployable inside a
classified network without an exception request.

**The interface is read-only.** There is no route that writes to the raw store,
the ledger, or a mapping. An investigator can look at evidence and verify it;
nothing reachable from a browser can alter it.

Threading and database handles
------------------------------
Requests are handled on threads, and **each request opens its own SQLite
connections**, because Python reports ``sqlite3.threadsafety == 1`` here: a
connection may not be shared between threads.

Serial handling was tried first and is wrong for a browser client. Browsers
preconnect -- they open speculative sockets and send nothing on them. A
single-threaded server accepts one of those and blocks reading it forever,
so the UI hangs even though every request it did send was answered. ``curl``
never behaves that way, which is exactly why a curl-based smoke test passes
while the real page hangs.

Opening SQLite per request costs well under a millisecond and removes the
shared-handle problem entirely, which is a better trade than a lock around
every read.
"""

from __future__ import annotations

import json
import mimetypes
import uuid
from contextlib import contextmanager
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qs, urlparse

from ..ledger import Ledger
from ..mapping import MappingRegistry
from ..normalize import Normalizer
from ..storage import SQLiteRawStore

__all__ = ["build_server", "serve", "ForensicHandler"]

STATIC = Path(__file__).parent / "index.html"


class ForensicHandler(BaseHTTPRequestHandler):
    """Read-only HTTP surface over the pipeline."""

    server_version = "AUFLA-Forensic-Explorer"
    # Do not let a preconnected-but-silent browser socket hold a thread open
    # indefinitely.
    timeout = 20

    def __init__(
        self,
        *args,
        raw_path: Path,
        ledger_path: Path,
        registry: MappingRegistry,
        **kwargs,
    ) -> None:
        self.raw_path = raw_path
        self.ledger_path = ledger_path
        self.registry = registry
        self.normalizer = Normalizer(registry)
        super().__init__(*args, **kwargs)

    @contextmanager
    def _db(self) -> Iterator[tuple[SQLiteRawStore, Ledger]]:
        """Open connections owned by this request's thread, and close them."""
        store = SQLiteRawStore(self.raw_path)
        ledger = Ledger(self.ledger_path)
        try:
            yield store, ledger
        finally:
            store.close()
            ledger.close()

    # ---- plumbing ---------------------------------------------------------

    def log_message(self, fmt: str, *args: Any) -> None:  # pragma: no cover
        """Quieter than the default, which prints one line per asset."""
        if "/api/" in (args[0] if args else ""):
            super().log_message(fmt, *args)

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        # One request per connection. Threads make this unnecessary for
        # correctness, but it keeps idle browser sockets from holding threads
        # and database handles open for no reason.
        self.send_header("Connection", "close")
        # The page loads nothing external; say so explicitly so a browser
        # cannot be talked into fetching anything either.
        self.send_header(
            "Content-Security-Policy",
            "default-src 'self'; style-src 'self' 'unsafe-inline'; "
            "script-src 'self' 'unsafe-inline'",
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

    def do_POST(self) -> None:  # noqa: N802
        """Nothing here writes. Refused explicitly rather than by omission."""
        self._json({"error": "this interface is read-only"}, status=405)

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

            with self._db() as (store, ledger):
                if route == "/api/stats":
                    self._json(self._stats(store, ledger))
                elif route == "/api/events":
                    self._json(self._events(store, query))
                elif route.startswith("/api/event/"):
                    self._json(
                        self._event(store, ledger, route.rsplit("/", 1)[-1])
                    )
                elif route == "/api/verify":
                    self._json(self._verify(store, ledger))
                else:
                    self._json({"error": f"no route {route}"}, status=404)
        except Exception as exc:  # pragma: no cover - defensive
            self._json({"error": f"{type(exc).__name__}: {exc}"}, status=500)

    def _serve_page(self) -> None:
        body = STATIC.read_bytes()
        ctype = mimetypes.guess_type(str(STATIC))[0] or "text/html"
        self._send(200, body, f"{ctype}; charset=utf-8")

    # ---- data -------------------------------------------------------------

    def _stats(self, store, ledger) -> dict[str, Any]:
        sources: dict[str, int] = {}
        for event in store.iter_events():
            sources[event.source_id] = sources.get(event.source_id, 0) + 1
        return {
            "raw_events": store.count(),
            "sealed_events": ledger.event_count,
            "batches": ledger.batch_count,
            "checkpoints": len(ledger.checkpoints()),
            "chain_head": ledger.head,
            "mappings": len(self.registry),
            "by_source": sources,
        }

    def _sources(self) -> list[dict[str, Any]]:
        return [
            {
                "source": m.source,
                "format": m.format,
                "version": m.version,
                "ocsf_classes": list(m.ocsf_classes),
                "rules": [r.name for r in m.rules],
                "approved_by": m.approved_by,
                "author": m.author,
                "content_hash": m.content_hash(),
                "description": m.description,
            }
            for m in self.registry
        ]

    def _events(self, store, query: dict[str, list[str]]) -> list[dict[str, Any]]:
        limit = int(query.get("limit", ["200"])[0])
        source = query.get("source", [None])[0]

        out: list[dict[str, Any]] = []
        for event in store.iter_events(source_id=source, limit=limit):
            record = self.normalizer.normalize(event)
            out.append(
                {
                    "event_uid": str(event.event_uid),
                    "source_id": event.source_id,
                    "received_at": event.received_at_iso,
                    "byte_len": event.byte_len,
                    "transport": event.transport.value,
                    "truncated": event.truncated,
                    "parse_status": record.parse_status.value,
                    "ocsf_class": record.ocsf_class,
                    "rule": record.rule_name,
                    "coverage": round(record.mapping_coverage, 3),
                    "warnings": len(record.warnings),
                    "summary": _summarise(record),
                }
            )
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
                # The point of the whole system: the exact original bytes,
                # shown as text and as hex.
                "text": event.text(),
                "hex": event.raw_bytes.hex(),
                "hash_verified": event.verify(),
            },
            "normalized": record.to_dict(),
            "warnings": record.warnings,
            "errors": record.errors,
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

    def _verify(self, store, ledger) -> dict[str, Any]:
        result = ledger.verify(store=store)
        return {
            "ok": result.ok,
            "text": str(result),
            "batches_checked": result.batches_checked,
            "events_checked": result.events_checked,
            "checkpoints_checked": result.checkpoints_checked,
            "first_divergence": result.first_divergence,
            "reason": result.reason,
        }


def _summarise(record) -> str:
    """One-line description for the event table."""
    f = record.fields
    src, dst = f.get("src_endpoint.ip"), f.get("dst_endpoint.ip")
    if title := f.get("finding_info.title"):
        return str(title)
    if url := f.get("http_request.url.text"):
        method = f.get("http_request.http_method", "")
        return f"{method} {url}".strip()
    if src and dst:
        port = f.get("dst_endpoint.port")
        return f"{src} -> {dst}" + (f":{port}" if port else "")
    return "-"


def build_server(
    raw_path: str | Path,
    ledger_path: str | Path,
    registry: MappingRegistry,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
) -> ThreadingHTTPServer:
    """Build the server. Paths, not open handles: each request opens its own."""
    handler = partial(
        ForensicHandler,
        raw_path=Path(raw_path),
        ledger_path=Path(ledger_path),
        registry=registry,
    )
    server = ThreadingHTTPServer((host, port), handler)
    # An abandoned browser socket should not keep the process alive.
    server.daemon_threads = True
    return server


def serve(
    raw_path: str | Path,
    ledger_path: str | Path,
    registry: MappingRegistry,
    *,
    host: str = "127.0.0.1",
    port: int = 8000,
) -> None:  # pragma: no cover - blocking
    httpd = build_server(raw_path, ledger_path, registry, host=host, port=port)
    print(f"Forensic Explorer on http://{host}:{port}  (read-only, Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")
    finally:
        httpd.server_close()
