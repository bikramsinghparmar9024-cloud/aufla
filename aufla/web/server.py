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
``/api/event/<uid>/triage``
    record a named person's manual call that a finding is not dangerous.

Nothing reachable from a browser updates or deletes an existing event or
ledger row. Approving a mapping rewrites the *derived* projection, which is
rebuildable from raw by definition; the evidence underneath is untouched.
Triage is the same shape: it adds a judgement beside the derived data (who,
when, and that they called it normal) without touching severity_id or any
other field the mapping produced, so a later re-derivation cannot silently
overrule what a human already decided, and cannot be silently overruled by
one either.

Reads come from the materialised OCSF projection, not from re-parsing raw on
every request. Aggregations are SQL. That is the difference between a console
that works on a demo dataset and one that works on a real day's traffic.
"""

from __future__ import annotations

import html
import json
import platform
import time
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Iterator
from urllib.parse import parse_qs, urlparse

from .. import __version__
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
            elif route.startswith("/api/event/") and route.endswith("/triage"):
                uid = route[len("/api/event/") : -len("/triage")].strip("/")
                with self._db() as (_store, _ledger, ocsf, _proposals):
                    self._json(self._triage(ocsf, uid))
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
                if route == "/api/report":
                    self._serve_report(store, ledger, ocsf, proposals, query)
                    return
                elif route == "/api/logs/report":
                    self._serve_logs_report(ocsf, query)
                    return
                elif route == "/api/stats":
                    self._json(self._stats(store, ledger, ocsf, proposals))
                elif route == "/api/overview":
                    self._json(self._overview(ocsf, query))
                elif route == "/api/events":
                    self._json(self._events(ocsf, query))
                elif route.startswith("/api/event/"):
                    if route.endswith("/dossier"):
                        uid = route[len("/api/event/") : -len("/dossier")]
                        self._serve_event_dossier(store, ledger, ocsf, uid)
                        return
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
        # The version stamped in must be the one this exact response carries,
        # not whatever the server happens to answer on the tab's *first*
        # status poll after load. A tab opened before a restart otherwise
        # makes that first poll after the restart, silently adopts the new
        # version as its own baseline, and never notices it is running old
        # markup -- which is exactly how "Mark as normal" and the sort arrow
        # went missing from an already-open tab despite both being live.
        body = STATIC.read_bytes().replace(
            b"</head>",
            f'<script>window.__AUFLA_UI_VERSION__={json.dumps(_ui_version())};</script></head>'.encode(),
            1,
        )
        self._send(200, body, "text/html; charset=utf-8")

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

    def _window(self, query) -> tuple[str, int | None, int | None]:
        """Parse the time-window from query params.

        Returns ``(label, since_ms, until_ms)``.  The ``from`` and ``to``
        params accept ISO-8601 datetime strings and take precedence over the
        preset range buttons when present.
        """
        from_str = (query.get("from", [None])[0] or "").strip()
        to_str = (query.get("to", [None])[0] or "").strip()

        if from_str or to_str:
            since_ms = self._iso_to_ms(from_str, is_end=False) if from_str else None
            until_ms = self._iso_to_ms(to_str, is_end=True) if to_str else None
            label = "custom"
            return label, since_ms, until_ms

        window = (query.get("range", [DEFAULT_RANGE])[0] or DEFAULT_RANGE).lower()
        if window != "all" and window not in RANGES:
            window = DEFAULT_RANGE
        seconds = RANGES.get(window)
        since_ms = (
            None if seconds is None else int(time.time() * 1000) - seconds * 1000
        )
        return window, since_ms, None

    @staticmethod
    def _iso_to_ms(text: str, is_end: bool = False) -> int | None:
        """Best-effort ISO-8601 or datetime-local string to epoch millis.

        If no timezone offset is provided (e.g. from browser datetime-local),
        treats as Indian Standard Time (IST, UTC+05:30) to match local user time.
        """
        if not text:
            return None
        try:
            from datetime import datetime as _dt
            normalised = text.strip()
            # If user entered just a date YYYY-MM-DD, expand to full start or end of day in IST
            if len(normalised) == 10 and normalised.count("-") == 2:
                normalised += "T23:59:59.999" if is_end else "T00:00:00"
            if normalised.endswith("Z"):
                normalised = normalised[:-1] + "+00:00"
            elif "+" not in normalised and "-" not in normalised[10:]:
                # No timezone offset in input; treat as IST (+05:30)
                normalised += "+05:30"
            dt = _dt.fromisoformat(normalised)
            return int(dt.timestamp() * 1000)
        except (ValueError, IndexError):
            return None

    def _overview(self, ocsf, query) -> dict[str, Any]:
        window, since_ms, until_ms = self._window(query)

        by_class = [
            (CATALOG[k].name if k in CATALOG else str(k), n)
            for k, n in ocsf.counts_by("class_uid", since_ms=since_ms, until_ms=until_ms)
        ]
        by_severity = [
            (SEVERITY_NAMES.get(k, str(k)), n)
            for k, n in ocsf.counts_by("severity_id", since_ms=since_ms, until_ms=until_ms)
        ]
        status = dict(ocsf.counts_by("parse_status", since_ms=since_ms, until_ms=until_ms))

        return {
            "range": window,
            "ranges": [*RANGES, "all"],
            "event_count": ocsf.event_count(since_ms=since_ms, until_ms=until_ms),
            "timeline": ocsf.timeline(since_ms=since_ms, until_ms=until_ms),
            "by_source": ocsf.counts_by("source_id", since_ms=since_ms, until_ms=until_ms),
            "by_status": status,
            "by_class": by_class,
            "by_severity": by_severity,
            "top_talkers": ocsf.counts_by("dst_ip", since_ms=since_ms, until_ms=until_ms, limit=8),
            "avg_coverage": ocsf.average_coverage(since_ms=since_ms, until_ms=until_ms),
            "findings": [
                {
                    "event_uid": f["event_uid"],
                    "time": _iso_ms(f["observed_time"]),
                    "source": f["source_id"],
                    "title": f["summary"],
                    "severity": f["severity_id"],
                    "severity_name": SEVERITY_NAMES.get(f["severity_id"], "?"),
                }
                for f in ocsf.findings(since_ms=since_ms, until_ms=until_ms)
            ],
        }

    def _triage(self, ocsf, uid: str) -> dict[str, Any]:
        payload = self._body()
        by = (payload.get("by") or "").strip()
        if not by:
            # Same audit rule as approving a discovery proposal: a decision
            # with no name attached is not a decision, it is an anonymous
            # edit to evidence-adjacent data. Refused rather than guessed.
            return {"error": "a triage decision must name who made it"}
        try:
            updated = ocsf.set_triage(
                uid, by=by, note=payload.get("note"),
                status=payload.get("status", "normal"),
            )
        except ValueError as exc:
            return {"error": str(exc)}
        if updated is None:
            return {"error": f"no event {uid}"}
        return {
            "event_uid": uid,
            "triage_status": updated["triage_status"],
            "triaged_by": updated["triaged_by"],
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
        from_str = (query.get("from", [None])[0] or "").strip()
        to_str = (query.get("to", [None])[0] or "").strip()
        since_ms = self._iso_to_ms(from_str, is_end=False) if from_str else None
        until_ms = self._iso_to_ms(to_str, is_end=True) if to_str else None

        # Sort direction decides which rows LIMIT keeps, not just their order.
        # Reversing an already-fetched "newest 300" page client-side would
        # show the newest 300 in oldest-first order, not the true oldest 300
        # -- the same mistake fixed once already for the raw store. The sort
        # has to be applied before the LIMIT, at the query.
        newest_first = (query.get("sort", ["desc"])[0] or "desc").lower() != "asc"

        rows = ocsf.query(
            source_id=query.get("source", [None])[0] or None,
            status=query.get("status", [None])[0] or None,
            since_ms=since_ms,
            until_ms=until_ms,
            search=query.get("q", [""])[0] or None,
            limit=limit,
            newest_first=newest_first,
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
                "received_at_ms": event.received_at_ns // 1_000_000,
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

    def _serve_event_dossier(self, store, ledger, ocsf, uid: str) -> None:
        """Generate a complete Section 63 BSA 2023 forensic dossier for a single event."""
        data = self._event(store, ledger, ocsf, uid)
        if data.get("error"):
            self._send(404, f"<h1>Event Not Found: {html.escape(data['error'])}</h1>".encode("utf-8"), "text/html")
            return

        raw = data["raw"]
        norm = data["normalized"]
        ledger_info = data.get("ledger")
        warnings = data.get("warnings", [])
        exports = data.get("exports", {})

        now_dt = datetime.now(timezone.utc)
        now_str = _fmt_ist_utc(int(now_dt.timestamp() * 1000))
        recv_ms = raw.get("received_at_ms")
        recv_str = _fmt_ist_utc(recv_ms) if recv_ms is not None else raw.get("received_at", "")

        def _esc(s: Any) -> str:
            return html.escape(str(s if s is not None else ""))

        # Hex dump
        hex_raw = raw.get("hex", "")
        hex_lines = []
        for i in range(0, len(hex_raw), 32):
            chunk = hex_raw[i : i + 32]
            spaced = " ".join(chunk[j : j + 2] for j in range(0, len(chunk), 2))
            hex_lines.append(f"{i//2:04x}   {spaced}")
        hex_dump = "\n".join(hex_lines[:20])
        if len(hex_lines) > 20:
            hex_dump += f"\n... ({len(hex_lines) - 20} additional lines truncated for display)"

        class_uid = norm.get("class_uid")
        class_name = CATALOG[class_uid].name if class_uid in CATALOG else str(class_uid or "Unknown")
        sev_id = norm.get("severity_id")
        sev_name = SEVERITY_NAMES.get(sev_id, str(sev_id or "Unknown"))

        skip_keys = {"event_uid", "raw_hash", "source_id", "mapping_hash"}
        norm_rows = "".join(
            f"<tr><td class='k' style='width:220px;font-weight:600;color:#4a5568'>{_esc(k)}</td><td class='v mono'>{_esc(v if not isinstance(v, (dict, list)) else json.dumps(v))}</td></tr>"
            for k, v in sorted(norm.items()) if k not in skip_keys
        )

        if ledger_info:
            ledger_block = f"""
        <dl class="kv">
          <dt>Merkle Batch ID</dt><dd><b>Batch #{ledger_info['batch_id']}</b> (Leaf Index: {ledger_info['leaf_index']})</dd>
          <dt>Batch Merkle Root</dt><dd class="mono">{_esc(ledger_info['root'])}</dd>
          <dt>Previous Batch Root</dt><dd class="mono">{_esc(ledger_info['prev_root'])}</dd>
          <dt>Digital Signature</dt><dd><span class="pass">{'Ed25519 Cryptographically Signed' if ledger_info['signed'] else 'Unsigned'}</span></dd>
        </dl>"""
        else:
            ledger_block = "<div style='color:#718096;font-size:12px'>Event ingested in memory / awaiting next batch seal.</div>"

        warn_block = ""
        if warnings:
            warn_block = f"""
<div class="section">
  <div class="section-title">Validation Warnings</div>
  <ul style="margin:4px 0;padding-left:18px;color:#c53030;font-size:12px">
    {"".join(f"<li>{_esc(w)}</li>" for w in warnings)}
  </ul>
</div>"""

        export_block = ""
        if exports:
            export_rows = "".join(
                f"<tr><td style='width:80px;font-weight:600'>{_esc(k.upper())}</td><td><pre class='mono' style='margin:0;font-size:11px'>{_esc(v)}</pre></td></tr>"
                for k, v in exports.items()
            )
            export_block = f"""
<div class="section">
  <div class="section-title">Downstream SIEM Format Lineage</div>
  <table><tbody>{export_rows}</tbody></table>
</div>"""

        doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Forensic Event Dossier — {raw['event_uid']}</title>
<style>
  @page {{
    size: A4 portrait;
    margin: 14mm 12mm 14mm 12mm;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #1a202c;
    background: #fff;
    line-height: 1.45;
    font-size: 12.5px;
    margin: 0;
    padding: 24px;
  }}
  .no-print {{
    margin-bottom: 20px;
    padding: 12px 18px;
    background: #ebf8ff;
    border: 1px solid #bee3f8;
    border-radius: 8px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .no-print button {{
    background: #2b6cb0;
    color: #fff;
    border: 0;
    padding: 8px 16px;
    font-weight: 600;
    font-size: 13px;
    border-radius: 6px;
    cursor: pointer;
  }}
  .no-print button:hover {{ background: #2c5282; }}
  @media print {{
    .no-print {{ display: none !important; }}
    body {{ padding: 0; }}
  }}
  .header {{
    border-bottom: 2px solid #2d3748;
    padding-bottom: 10px;
    margin-bottom: 18px;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
  }}
  .header h1 {{ margin: 0; font-size: 18px; color: #1a202c; letter-spacing: -0.3px; }}
  .header .sub {{ color: #4a5568; font-size: 11.5px; margin-top: 3px; }}
  .header .meta {{ text-align: right; font-size: 11.5px; color: #718096; }}
  .section {{ margin-bottom: 18px; page-break-inside: avoid; }}
  .section-title {{
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: #2b6cb0;
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 3px;
    margin-bottom: 8px;
  }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }}
  .card {{
    background: #f7fafc;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 10px 12px;
  }}
  .kv {{ display: grid; grid-template-columns: 130px 1fr; gap: 4px 8px; font-size: 12px; margin: 0; }}
  .kv dt {{ color: #718096; }}
  .kv dd {{ margin: 0; font-weight: 500; word-break: break-all; }}
  .mono {{ font-family: "Cascadia Mono", Consolas, Menlo, monospace; }}
  pre {{
    margin: 0; padding: 10px; background: #f8fafc; color: #1a202c; border: 1px solid #e2e8f0;
    border-radius: 5px; font-family: "Cascadia Mono", Consolas, monospace; font-size: 11px;
    white-space: pre-wrap; word-break: break-all; max-height: 240px; overflow: hidden;
  }}
  table {{ width: 100%; border-collapse: collapse; font-size: 11.5px; }}
  th {{ text-align: left; background: #edf2f7; color: #4a5568; padding: 5px 8px; font-size: 10.5px; text-transform: uppercase; border: 1px solid #e2e8f0; }}
  td {{ padding: 5px 8px; border: 1px solid #e2e8f0; }}
  .pass {{ color: #22543d; font-weight: 700; background: #c6f6d5; padding: 2px 6px; border-radius: 4px; font-size: 11px; }}
  .fail {{ color: #742a2a; font-weight: 700; background: #fed7d7; padding: 2px 6px; border-radius: 4px; font-size: 11px; }}
  .sig-block {{
    margin-top: 24px;
    border: 1px solid #cbd5e0;
    border-radius: 6px;
    padding: 14px 18px;
    background: #fff;
    page-break-inside: avoid;
  }}
  .sig-lines {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 18px; }}
  .sig-line {{ border-bottom: 1px solid #4a5568; height: 28px; margin-bottom: 4px; }}
  .sig-lbl {{ font-size: 11px; color: #4a5568; text-transform: uppercase; letter-spacing: 0.5px; }}
</style>
</head>
<body>

<div class="no-print">
  <div>
    <b>Section 63 BSA 2023 Individual Event Forensic Dossier</b>
    <div style="font-size:12px;color:#4a5568">Prepared for printing & PDF export. Click the button to print or save as PDF.</div>
  </div>
  <button onclick="window.print()">Print / Save as PDF</button>
</div>

<div class="header">
  <div>
    <h1>ELECTRONIC EVIDENCE DOSSIER</h1>
    <div class="sub">Under Section 63 of Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023)</div>
    <div class="sub">AUFLA Universal Log Pre-processing Framework · SIH 2026 · PS 26156 · NTRO / NCIIPC</div>
  </div>
  <div class="meta">
    <div><b>Dossier Generated:</b> {now_str}</div>
    <div><b>Event UID:</b> <span class="mono">{_esc(raw['event_uid'])}</span></div>
    <div><b>Status:</b> {'PASS (Byte Verified)' if raw['hash_verified'] else 'FAIL (Hash Mismatch)'}</div>
  </div>
</div>

<div class="section">
  <div class="section-title">1. Event Identification & Ingest Metadata</div>
  <div class="grid2">
    <div class="card">
      <dl class="kv">
        <dt>Event UID</dt><dd class="mono">{_esc(raw['event_uid'])}</dd>
        <dt>Source ID</dt><dd><b>{_esc(raw['source_id'])}</b></dd>
        <dt>Ingest Timestamp (IST)</dt><dd class="mono">{_esc(recv_str)}</dd>
        <dt>Transport Type</dt><dd>{_esc(raw['transport'].upper())}</dd>
        <dt>Source Device IP</dt><dd class="mono">{_esc(raw['source_ip'] or 'Local Host')}</dd>
        <dt>Raw Byte Length</dt><dd>{raw['byte_len']} bytes</dd>
      </dl>
    </div>
    <div class="card">
      <dl class="kv">
        <dt>OCSF Class</dt><dd><b>{_esc(class_name)}</b> (Class {_esc(class_uid)})</dd>
        <dt>Severity</dt><dd><b>{_esc(sev_name)}</b> (Level {_esc(sev_id)})</dd>
        <dt>Parse Outcome</dt><dd><span class="pass">{_esc(norm.get('parse_status'))}</span></dd>
        <dt>Rule Name</dt><dd class="mono">{_esc(norm.get('rule_name') or 'Default')}</dd>
        <dt>Mapping Version</dt><dd>v{_esc(norm.get('mapping_version') or '1')}</dd>
        <dt>Field Coverage</dt><dd>{round(float(norm.get('mapping_coverage') or 1.0) * 100, 1)}%</dd>
      </dl>
    </div>
  </div>
</div>

<div class="section">
  <div class="section-title">2. Cryptographic Authenticity & Chain of Custody Proof</div>
  <div class="card">
    <dl class="kv" style="grid-template-columns: 170px 1fr; margin-bottom: 8px">
      <dt>Payload SHA-256 Hash</dt><dd class="mono" style="font-size:11.5px">{_esc(raw['raw_hash'])}</dd>
      <dt>Payload Integrity Check</dt><dd><span class="{'pass' if raw['hash_verified'] else 'fail'}">{'PASS: Byte-exact match against arrival SHA-256' if raw['hash_verified'] else 'FAIL: Hash mismatch detected'}</span></dd>
    </dl>
    {ledger_block}
  </div>
</div>

<div class="section">
  <div class="section-title">3. Original Captured Raw Payload (Canonical Evidence)</div>
  <pre>{_esc(raw['text'])}</pre>
</div>

<div class="section">
  <div class="section-title">4. Hexadecimal Byte Dump</div>
  <pre>{_esc(hex_dump)}</pre>
</div>

<div class="section">
  <div class="section-title">5. Derived OCSF Schema Projection (Normalized Representation)</div>
  <table>
    <thead><tr><th>Schema Field</th><th>Extracted Value</th></tr></thead>
    <tbody>
      {norm_rows}
    </tbody>
  </table>
</div>

{warn_block}
{export_block}

<div class="sig-block">
  <div style="font-weight:700;font-size:12px;text-transform:uppercase;color:#2d3748">
    6. Custodian Declaration & Sign-off Block (Section 63 BSA 2023)
  </div>
  <div style="font-size:11.5px;color:#4a5568;margin-top:4px">
    I hereby certify that the raw byte payload and cryptographic seals above constitute an authentic, untampered record of electronic evidence captured under normal operational parameters.
  </div>
  <div class="sig-lines">
    <div>
      <div class="sig-line"></div>
      <div class="sig-lbl">Custodian Name & Designation</div>
    </div>
    <div>
      <div class="sig-line"></div>
      <div class="sig-lbl">Signature & Official Seal</div>
    </div>
    <div>
      <div class="sig-line"></div>
      <div class="sig-lbl">Organization / Department</div>
    </div>
    <div>
      <div class="sig-line"></div>
      <div class="sig-lbl">Date of Sign-off</div>
    </div>
  </div>
</div>

</body>
</html>"""
        self._send(200, doc.encode("utf-8"), "text/html; charset=utf-8")

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

    def _serve_report(self, store, ledger, ocsf, proposals, query) -> None:
        """Generate a self-contained, print-ready Section 63 BSA 2023 Forensic Evidence Report."""
        window, since_ms, until_ms = self._window(query)
        now_dt = datetime.now(timezone.utc)
        now_str = _fmt_ist_utc(int(now_dt.timestamp() * 1000))

        # Time range bounds
        start_str = _fmt_ist_utc(since_ms) if since_ms is not None else "Epoch Start (Inception)"
        end_str = _fmt_ist_utc(until_ms) if until_ms is not None else "Present (" + now_str + ")"

        # Aggregations in window
        ev_count = ocsf.event_count(since_ms=since_ms, until_ms=until_ms)
        by_source = ocsf.counts_by("source_id", since_ms=since_ms, until_ms=until_ms)
        by_class = [
            (CATALOG[k].name if k in CATALOG else str(k), n)
            for k, n in ocsf.counts_by("class_uid", since_ms=since_ms, until_ms=until_ms)
        ]
        by_severity = [
            (SEVERITY_NAMES.get(k, str(k)), n)
            for k, n in ocsf.counts_by("severity_id", since_ms=since_ms, until_ms=until_ms)
        ]
        by_status = dict(ocsf.counts_by("parse_status", since_ms=since_ms, until_ms=until_ms))
        avg_cov = ocsf.average_coverage(since_ms=since_ms, until_ms=until_ms)
        findings = ocsf.findings(since_ms=since_ms, until_ms=until_ms, limit=15)

        # Integrity & Ledger
        v_res = ledger.verify(store=store)
        batches = ledger.batch_count
        chain_head = ledger.head
        checkpoints = ledger.checkpoints()

        # Storage files
        def _fsize(p: Path) -> str:
            if not p.exists():
                return "0 B"
            sz = p.stat().st_size
            if sz > 1024 * 1024:
                return f"{sz / (1024*1024):.2f} MB"
            return f"{sz / 1024:.1f} KB"

        raw_db_path = self.data_dir / "raw.db"
        ledger_db_path = self.data_dir / "ledger.db"
        ocsf_db_path = self.data_dir / "ocsf.db"
        prop_db_path = self.data_dir / "proposals.db"

        # System info
        host_name = platform.node() or "localhost"
        os_info = f"{platform.system()} {platform.release()} ({platform.machine()})"

        # HTML report rendering
        def _esc(s: Any) -> str:
            return html.escape(str(s or ""))

        src_rows = "".join(
            f"<tr><td><b>{_esc(s)}</b></td><td style='text-align:right'>{n:,}</td></tr>"
            for s, n in by_source
        ) or "<tr><td colspan='2' style='color:#777'>No events in window</td></tr>"

        cls_rows = "".join(
            f"<tr><td>{_esc(c)}</td><td style='text-align:right'>{n:,}</td></tr>"
            for c, n in by_class
        ) or "<tr><td colspan='2' style='color:#777'>No events in window</td></tr>"

        sev_rows = "".join(
            f"<tr><td><span class='badge'>{_esc(s)}</span></td><td style='text-align:right'>{n:,}</td></tr>"
            for s, n in by_severity
        ) or "<tr><td colspan='2' style='color:#777'>No events in window</td></tr>"

        findings_rows = "".join(
            f"<tr><td><span class='mono'>{_esc(f['time'])}</span></td><td>{_esc(f['source_id'])}</td><td>{_esc(f['summary'])}</td><td><b>{_esc(SEVERITY_NAMES.get(f['severity_id'], f['severity_id']))}</b></td></tr>"
            for f in [
                {
                    "time": _fmt_ist(f["observed_time"]),
                    "source_id": f["source_id"],
                    "summary": f["summary"],
                    "severity_id": f["severity_id"],
                }
                for f in findings
            ]
        ) or "<tr><td colspan='4' style='color:#777'>No High/Medium findings in this window</td></tr>"

        map_rows = "".join(
            f"<tr><td><b>{_esc(m.source)}</b></td><td>{_esc(m.format)}</td><td>v{m.version}</td><td>{_esc(m.approved_by or 'UNAPPROVED')}</td><td class='mono' style='font-size:11px'>{_esc(m.content_hash()[:24])}…</td></tr>"
            for m in sorted(self.registry, key=lambda m: m.source)
        )

        doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AUFLA Forensic Evidence Report — Section 63 BSA 2023</title>
<style>
  @page {{
    size: A4;
    margin: 18mm 14mm 18mm 14mm;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #1a202c;
    background: #fff;
    line-height: 1.45;
    font-size: 13px;
    margin: 0;
    padding: 24px;
  }}
  .no-print {{
    margin-bottom: 24px;
    padding: 14px 18px;
    background: #ebf8ff;
    border: 1px solid #bee3f8;
    border-radius: 8px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .no-print button {{
    background: #2b6cb0;
    color: #fff;
    border: 0;
    padding: 9px 18px;
    font-weight: 600;
    font-size: 13px;
    border-radius: 6px;
    cursor: pointer;
  }}
  .no-print button:hover {{ background: #2c5282; }}
  @media print {{
    .no-print {{ display: none !important; }}
    body {{ padding: 0; }}
  }}
  .header {{
    border-bottom: 2px solid #2d3748;
    padding-bottom: 12px;
    margin-bottom: 20px;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
  }}
  .header h1 {{ margin: 0; font-size: 20px; color: #1a202c; letter-spacing: -0.3px; }}
  .header .sub {{ color: #4a5568; font-size: 12px; margin-top: 4px; }}
  .header .meta {{ text-align: right; font-size: 12px; color: #718096; }}
  .section {{ margin-bottom: 22px; page-break-inside: avoid; }}
  .section-title {{
    font-size: 13px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 0.6px;
    color: #2b6cb0;
    border-bottom: 1px solid #e2e8f0;
    padding-bottom: 4px;
    margin-bottom: 10px;
  }}
  .grid2 {{ display: grid; grid-template-columns: 1fr 1fr; gap: 16px; }}
  .grid3 {{ display: grid; grid-template-columns: 1fr 1fr 1fr; gap: 14px; }}
  .card {{
    background: #f7fafc;
    border: 1px solid #e2e8f0;
    border-radius: 6px;
    padding: 12px 14px;
  }}
  .kv {{ display: grid; grid-template-columns: 140px 1fr; gap: 4px 10px; font-size: 12.5px; }}
  .kv dt {{ color: #718096; }}
  .kv dd {{ margin: 0; font-weight: 500; word-break: break-all; }}
  .mono {{ font-family: "Cascadia Mono", Consolas, Menlo, monospace; }}
  table {{ width: 100%; border-collapse: collapse; font-size: 12px; margin-top: 6px; }}
  th {{ text-align: left; background: #edf2f7; color: #4a5568; padding: 6px 8px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.4px; border: 1px solid #e2e8f0; }}
  td {{ padding: 6px 8px; border: 1px solid #e2e8f0; }}
  .pass {{ color: #22543d; font-weight: 700; background: #c6f6d5; padding: 2px 6px; border-radius: 4px; }}
  .fail {{ color: #742a2a; font-weight: 700; background: #fed7d7; padding: 2px 6px; border-radius: 4px; }}
  .badge {{ background: #edf2f7; color: #2d3748; padding: 2px 6px; border-radius: 4px; font-weight: 600; font-size: 11px; }}
  .sig-block {{
    margin-top: 36px;
    border: 1px solid #cbd5e0;
    border-radius: 6px;
    padding: 16px 20px;
    background: #fff;
    page-break-inside: avoid;
  }}
  .sig-lines {{ display: grid; grid-template-columns: 1fr 1fr; gap: 24px; margin-top: 24px; }}
  .sig-line {{ border-bottom: 1px solid #4a5568; height: 32px; margin-bottom: 6px; }}
  .sig-lbl {{ font-size: 11.5px; color: #4a5568; text-transform: uppercase; letter-spacing: 0.5px; }}
</style>
</head>
<body>

<div class="no-print">
  <div>
    <b>Section 63 BSA 2023 Forensic Evidence Report</b>
    <div style="font-size:12px;color:#4a5568">Prepared for printing & PDF export. Click the button to save as PDF.</div>
  </div>
  <button onclick="window.print()">Print / Save as PDF</button>
</div>

<div class="header">
  <div>
    <h1>CERTIFICATE OF ELECTRONIC EVIDENCE</h1>
    <div class="sub">Under Section 63 of the Bharatiya Sakshya Adhiniyam, 2023 (BSA 2023)</div>
    <div class="sub">AUFLA Universal Log Pre-processing Framework · SIH 2026 · PS 26156 · NTRO / NCIIPC</div>
  </div>
  <div class="meta">
    <div><b>Report Generated:</b> {now_str}</div>
    <div><b>System Version:</b> v{__version__}</div>
    <div><b>Mode:</b> Cryptographically Sealed</div>
  </div>
</div>

<div class="section">
  <div class="section-title">1. Particulars of Computer System & Storage Layout</div>
  <div class="grid2">
    <div class="card">
      <dl class="kv">
        <dt>Host Machine</dt><dd class="mono">{_esc(host_name)}</dd>
        <dt>Platform / OS</dt><dd>{_esc(os_info)}</dd>
        <dt>Software Engine</dt><dd>AUFLA Core v{__version__} (Air-gapped)</dd>
        <dt>Taxonomy Standard</dt><dd>OCSF (Open Cybersecurity Schema Framework) 1.5.0</dd>
      </dl>
    </div>
    <div class="card">
      <dl class="kv">
        <dt>Raw Store (Canonical)</dt><dd class="mono">{_esc(raw_db_path.name)} ({_fsize(raw_db_path)})</dd>
        <dt>Merkle Ledger Store</dt><dd class="mono">{_esc(ledger_db_path.name)} ({_fsize(ledger_db_path)})</dd>
        <dt>OCSF Projection Store</dt><dd class="mono">{_esc(ocsf_db_path.name)} ({_fsize(ocsf_db_path)})</dd>
        <dt>Review / Audit Store</dt><dd class="mono">{_esc(prop_db_path.name)} ({_fsize(prop_db_path)})</dd>
      </dl>
    </div>
  </div>
</div>

<div class="section">
  <div class="section-title">2. Audit Period & Event Scope</div>
  <div class="grid3">
    <div class="card">
      <div style="font-size:11px;color:#718096;text-transform:uppercase">Time Window Start</div>
      <div style="font-size:14px;font-weight:600;margin-top:4px" class="mono">{_esc(start_str)}</div>
    </div>
    <div class="card">
      <div style="font-size:11px;color:#718096;text-transform:uppercase">Time Window End</div>
      <div style="font-size:14px;font-weight:600;margin-top:4px" class="mono">{_esc(end_str)}</div>
    </div>
    <div class="card">
      <div style="font-size:11px;color:#718096;text-transform:uppercase">Total Events in Window</div>
      <div style="font-size:18px;font-weight:700;margin-top:2px;color:#2b6cb0">{ev_count:,} events</div>
    </div>
  </div>
</div>

<div class="section">
  <div class="section-title">3. Cryptographic Chain of Custody & Tamper Verification</div>
  <div class="card">
    <dl class="kv" style="grid-template-columns: 160px 1fr; margin-bottom: 8px">
      <dt>Verification Status</dt>
      <dd><span class="{'pass' if v_res.ok else 'fail'}">{_esc(str(v_res))}</span></dd>
      <dt>Merkle Chain Head</dt>
      <dd class="mono" style="font-size:12px">{_esc(chain_head)}</dd>
      <dt>Sealed Merkle Batches</dt>
      <dd>{batches} batches ({v_res.events_checked} raw events re-hashed and verified)</dd>
      <dt>Signed Checkpoints</dt>
      <dd>{len(checkpoints)} daily offline checkpoints validated</dd>
    </dl>
    <div style="font-size:11.5px;color:#4a5568;border-top:1px solid #e2e8f0;padding-top:6px;margin-top:6px">
      * All raw log payloads are hashed with SHA-256 upon initial capture prior to any normalization. Each batch root is cryptographically sealed in an append-only Merkle ledger signed via Ed25519.
    </div>
  </div>
</div>

<div class="section">
  <div class="section-title">4. Ingestion & Normalization Breakdown in Audit Window</div>
  <div class="grid3">
    <div>
      <b style="font-size:11.5px;color:#4a5568">Events by Source</b>
      <table>
        <thead><tr><th>Source</th><th style="text-align:right">Count</th></tr></thead>
        <tbody>{src_rows}</tbody>
      </table>
    </div>
    <div>
      <b style="font-size:11.5px;color:#4a5568">Events by OCSF Class</b>
      <table>
        <thead><tr><th>Class</th><th style="text-align:right">Count</th></tr></thead>
        <tbody>{cls_rows}</tbody>
      </table>
    </div>
    <div>
      <b style="font-size:11.5px;color:#4a5568">Events by Severity</b>
      <table>
        <thead><tr><th>Severity</th><th style="text-align:right">Count</th></tr></thead>
        <tbody>{sev_rows}</tbody>
      </table>
    </div>
  </div>
</div>

<div class="section">
  <div class="section-title">5. High & Medium Security Findings in Window</div>
  <table>
    <thead><tr><th>Observed Time (IST)</th><th>Source</th><th>Finding Title / Summary</th><th>Severity</th></tr></thead>
    <tbody>{findings_rows}</tbody>
  </table>
</div>

<div class="section">
  <div class="section-title">6. Onboarded Mapping Registry (Lineage Audit)</div>
  <table>
    <thead><tr><th>Source ID</th><th>Format</th><th>Version</th><th>Approved By</th><th>Content SHA-256</th></tr></thead>
    <tbody>{map_rows}</tbody>
  </table>
</div>

<div class="sig-block">
  <div style="font-weight:700;font-size:13px;text-transform:uppercase;color:#2d3748">
    7. Custodian Declaration & Sign-off Block (Section 63 BSA 2023)
  </div>
  <div style="font-size:12px;color:#4a5568;margin-top:6px">
    I hereby certify that the electronic records detailed in this report were ingested, cryptographically sealed, and processed under regular operation by the AUFLA log pre-processing system without unrecorded alteration or tampering.
  </div>
  <div class="sig-lines">
    <div>
      <div class="sig-line"></div>
      <div class="sig-lbl">Custodian Name & Designation</div>
    </div>
    <div>
      <div class="sig-line"></div>
      <div class="sig-lbl">Signature & Official Seal</div>
    </div>
    <div>
      <div class="sig-line"></div>
      <div class="sig-lbl">Organization / Department</div>
    </div>
    <div>
      <div class="sig-line"></div>
      <div class="sig-lbl">Date of Sign-off</div>
    </div>
  </div>
</div>

</body>
</html>"""
        self._send(200, doc.encode("utf-8"), "text/html; charset=utf-8")

    def _serve_logs_report(self, ocsf, query) -> None:
        """Generate a print-ready, line-by-line log data export with boundary checking."""
        from_str = (query.get("from", [None])[0] or "").strip()
        to_str = (query.get("to", [None])[0] or "").strip()
        source = (query.get("source", [None])[0] or "").strip() or None
        status = (query.get("status", [None])[0] or "").strip() or None
        search = (query.get("q", [None])[0] or "").strip() or None

        since_ms = self._iso_to_ms(from_str, is_end=False) if from_str else None
        until_ms = self._iso_to_ms(to_str, is_end=True) if to_str else None

        raw_count_str = (query.get("count", ["500"])[0] or "").strip()
        try:
            requested_count = int(raw_count_str) if raw_count_str else 500
        except ValueError:
            requested_count = 500
        requested_count = max(1, requested_count)

        total_available = ocsf.event_count(
            source_id=source,
            status=status,
            since_ms=since_ms,
            until_ms=until_ms,
            search=search,
        )

        is_exceeded = requested_count > total_available
        limit_to_fetch = min(requested_count, total_available) if total_available > 0 else 0

        rows = ocsf.query(
            source_id=source,
            status=status,
            since_ms=since_ms,
            until_ms=until_ms,
            search=search,
            limit=limit_to_fetch,
            newest_first=True,
        ) if limit_to_fetch > 0 else []

        now_dt = datetime.now(timezone.utc)
        now_str = _fmt_ist_utc(int(now_dt.timestamp() * 1000))
        time_from_disp = _fmt_ist_utc(since_ms) if since_ms is not None else "Inception (All History)"
        time_to_disp = _fmt_ist_utc(until_ms) if until_ms is not None else f"Present ({now_str})"

        def _esc(s: Any) -> str:
            return html.escape(str(s or ""))

        # Notice banner styling and message
        time_context = f" between {time_from_disp} and {time_to_disp}" if (since_ms is not None or until_ms is not None) else ""
        if is_exceeded:
            notice_html = f"""
<div class="notice warn">
  <b>Notice:</b> The number of available logs ({total_available:,}){time_context} is less than you entered ({requested_count:,}). Displaying all {len(rows):,} available logs.
</div>"""
        else:
            notice_html = f"""
<div class="notice ok">
  Displaying <b>{len(rows):,}</b> logs (requested {requested_count:,} of {total_available:,} available{time_context}).
</div>"""

        # Table rows
        table_rows = []
        for i, r in enumerate(rows, 1):
            class_name = CATALOG[r["class_uid"]].name if r.get("class_uid") in CATALOG else (r.get("class_uid") or "—")
            src_ip = r.get("src_ip") or ""
            src_port = r.get("src_port")
            dst_ip = r.get("dst_ip") or ""
            dst_port = r.get("dst_port")

            endpoint_str = ""
            if src_ip or dst_ip:
                s_part = f"{src_ip}:{src_port}" if src_port else src_ip
                d_part = f"{dst_ip}:{dst_port}" if dst_port else dst_ip
                endpoint_str = f"{s_part} &rarr; {d_part}" if (s_part and d_part) else (s_part or d_part)

            sev_name = SEVERITY_NAMES.get(r.get("severity_id"), "Unknown")
            obs_time = _fmt_ist(r["observed_time"]) if r.get("observed_time") else "—"

            table_rows.append(f"""
<tr>
  <td class="num" style="text-align:center;color:#718096">{i}</td>
  <td class="mono">{_esc(obs_time)}</td>
  <td><b>{_esc(r.get("source_id"))}</b></td>
  <td style="color:#4a5568">{_esc(class_name)}</td>
  <td><a href="/api/event/{_esc(r.get('event_uid'))}/dossier" target="_blank" style="color:#2b6cb0;text-decoration:none;font-weight:500" title="Open individual Section 63 BSA 2023 forensic dossier">{_esc(r.get("summary"))}</a></td>
  <td class="mono" style="font-size:11px">{endpoint_str}</td>
  <td><span class="sev sev-{sev_name.lower()}">{_esc(sev_name)}</span></td>
  <td><span class="status status-{_esc(r.get('parse_status'))}">{_esc(r.get('parse_status'))}</span></td>
</tr>""")

        tbody_content = "".join(table_rows) if table_rows else "<tr><td colspan='8' style='text-align:center;padding:24px;color:#718096'>No logs found matching your criteria.</td></tr>"

        doc = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>AUFLA Log Data Export ({len(rows):,} records)</title>
<style>
  @page {{
    size: landscape;
    margin: 10mm 8mm 10mm 8mm;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #1a202c;
    background: #fff;
    line-height: 1.4;
    font-size: 12px;
    margin: 0;
    padding: 20px;
  }}
  .no-print {{
    margin-bottom: 18px;
    padding: 12px 18px;
    background: #ebf8ff;
    border: 1px solid #bee3f8;
    border-radius: 8px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}
  .no-print button {{
    background: #2b6cb0;
    color: #fff;
    border: 0;
    padding: 8px 16px;
    font-weight: 600;
    font-size: 13px;
    border-radius: 6px;
    cursor: pointer;
  }}
  .no-print button:hover {{ background: #2c5282; }}
  @media print {{
    .no-print {{ display: none !important; }}
    body {{ padding: 0; }}
  }}
  .header {{
    border-bottom: 2px solid #2d3748;
    padding-bottom: 10px;
    margin-bottom: 14px;
    display: flex;
    justify-content: space-between;
    align-items: flex-end;
  }}
  .header h1 {{ margin: 0; font-size: 18px; color: #1a202c; }}
  .header .sub {{ color: #4a5568; font-size: 11.5px; margin-top: 3px; }}
  .header .meta {{ text-align: right; font-size: 11.5px; color: #718096; }}
  .notice {{
    padding: 10px 14px;
    border-radius: 6px;
    font-size: 12.5px;
    margin-bottom: 14px;
  }}
  .notice.warn {{
    background: #fffaf0;
    border: 1px solid #feebc8;
    color: #9c4221;
  }}
  .notice.ok {{
    background: #f0fff4;
    border: 1px solid #c6f6d5;
    color: #22543d;
  }}
  .filters {{
    display: flex;
    gap: 16px;
    flex-wrap: wrap;
    font-size: 11.5px;
    color: #4a5568;
    margin-bottom: 12px;
    background: #f7fafc;
    padding: 8px 12px;
    border-radius: 6px;
    border: 1px solid #edf2f7;
  }}
  .filters span b {{ color: #2d3748; }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 11px;
  }}
  th {{
    text-align: left;
    background: #edf2f7;
    color: #4a5568;
    padding: 6px 8px;
    font-size: 10.5px;
    text-transform: uppercase;
    letter-spacing: 0.4px;
    border: 1px solid #e2e8f0;
  }}
  td {{
    padding: 5px 8px;
    border: 1px solid #e2e8f0;
    vertical-align: top;
  }}
  tr:nth-child(even) {{ background: #fafafa; }}
  tr {{ page-break-inside: avoid; }}
  .mono {{ font-family: "Cascadia Mono", Consolas, Menlo, monospace; }}
  .sev {{
    padding: 2px 5px;
    border-radius: 3px;
    font-weight: 600;
    font-size: 10px;
    text-transform: uppercase;
  }}
  .sev-fatal, .sev-critical {{ background: #fed7d7; color: #742a2a; }}
  .sev-high {{ background: #feebc8; color: #7b341e; }}
  .sev-medium {{ background: #feefc3; color: #744210; }}
  .sev-low {{ background: #e2e8f0; color: #2d3748; }}
  .sev-informational {{ background: #ebf8ff; color: #2b6cb0; }}
  .sev-unknown {{ background: #edf2f7; color: #4a5568; }}
  .status {{
    padding: 2px 5px;
    border-radius: 3px;
    font-weight: 600;
    font-size: 10px;
  }}
  .status-full {{ background: #c6f6d5; color: #22543d; }}
  .status-partial {{ background: #feebc8; color: #7b341e; }}
  .status-quarantined {{ background: #fed7d7; color: #742a2a; }}
</style>
</head>
<body>

<div class="no-print">
  <div>
    <b>AUFLA Detailed Log Data Export</b>
    <div style="font-size:12px;color:#4a5568">Prepared for printing & PDF export. Click the button to print or save as PDF.</div>
  </div>
  <button onclick="window.print()">Print / Save as PDF</button>
</div>

<div class="header">
  <div>
    <h1>AUFLA LOG DATA EXPORT</h1>
    <div class="sub">Canonical Raw & OCSF Normalized Ingest Projection · SIH 2026 · PS 26156 · NTRO / NCIIPC</div>
  </div>
  <div class="meta">
    <div><b>Export Generated:</b> {now_str}</div>
    <div><b>Requested Logs:</b> {requested_count:,}</div>
    <div><b>Available Matching:</b> {total_available:,}</div>
  </div>
</div>

<div class="filters">
  <span><b>Source:</b> {_esc(source or "All Sources")}</span>
  <span><b>Outcome:</b> {_esc(status or "All Outcomes")}</span>
  <span><b>Date &amp; Time Window (IST):</b> {_esc(time_from_disp)} &rarr; {_esc(time_to_disp)}</span>
  {f"<span><b>Search Query:</b> {_esc(search)}</span>" if search else ""}
  <span><b>Records Shown:</b> {len(rows):,}</span>
</div>

{notice_html}

<table>
  <thead>
    <tr>
      <th style="width:36px;text-align:center">#</th>
      <th style="width:165px">Date &amp; Time (IST)</th>
      <th style="width:120px">Source</th>
      <th style="width:120px">OCSF Class</th>
      <th>Summary / Finding</th>
      <th style="width:220px">Endpoints</th>
      <th style="width:90px">Severity</th>
      <th style="width:80px">Status</th>
    </tr>
  </thead>
  <tbody>
    {tbody_content}
  </tbody>
</table>

</body>
</html>"""
        self._send(200, doc.encode("utf-8"), "text/html; charset=utf-8")




IST = timezone(timedelta(hours=5, minutes=30))


def _fmt_ist(ms: int) -> str:
    """Format millisecond timestamp into IST date and time string."""
    dt_utc = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    return dt_utc.astimezone(IST).strftime("%Y-%m-%d %H:%M:%S IST")


def _fmt_ist_utc(ms: int) -> str:
    """Format millisecond timestamp showing both IST and UTC."""
    dt_utc = datetime.fromtimestamp(ms / 1000, tz=timezone.utc)
    dt_ist = dt_utc.astimezone(IST)
    return f"{dt_ist.strftime('%Y-%m-%d %H:%M:%S')} IST ({dt_utc.strftime('%H:%M:%SZ')})"


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
