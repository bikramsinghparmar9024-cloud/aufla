"""Live collection of real telemetry from the local Windows host.

Two sources, both readable without elevation, both mapping onto OCSF without a
semantic stretch:

``windows_netconn``
    Live TCP connections via ``Get-NetTCPConnection``. A TCP connection *is*
    network activity, so OCSF 4001 is exact rather than approximate.

``windows_eventlog``
    Windows Event Log, System and Application channels, **Level 1-3 only**
    (Critical, Error, Warning), via ``wevtutil ... /f:xml``. Restricting to
    those levels is what makes Detection Finding the honest class: an error
    raised by the OS is a finding; a routine informational event is not, so it
    is never collected rather than being forced into a class it does not fit.

The Security channel (logon events 4624/4625, which would map to OCSF
Authentication) needs administrator rights, so it is not collected by default.

Append-only
-----------
This is the one part of the system a button in the browser can start, and it is
worth being precise about what that permits. The collector **only appends**: it
captures new events, stores them, and seals them. It has no path that updates or
deletes an existing event, a ledger row, or a mapping. The read-only guarantee
on existing evidence is unchanged; what the button adds is new evidence.
"""

from __future__ import annotations

import re
import subprocess
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from ..models import Transport
from ..pipeline import Pipeline

__all__ = ["CollectorStatus", "LiveCollector", "collect_once"]

NETCONN_SOURCE = "windows_netconn"
EVENTLOG_SOURCE = "windows_eventlog"

# PowerShell is invoked with -NonInteractive so it can never block on a prompt,
# and every call carries a timeout so a wedged subprocess cannot stall the
# collector thread.
_PS = ["powershell", "-NoProfile", "-NonInteractive", "-Command"]
_TIMEOUT = 25

_NETCONN_PS = r"""
$ErrorActionPreference='SilentlyContinue'
$now=[DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds()
Get-NetTCPConnection | Where-Object { $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' } |
  ForEach-Object {
    $p=(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName
    "$now,$($_.LocalAddress),$($_.LocalPort),$($_.RemoteAddress),$($_.RemotePort),$($_.State),$p,$($_.OwningProcess)"
  }
"""


def _run(args: list[str], timeout: int = _TIMEOUT) -> str:
    """Run a command and return stdout, or '' if it fails.

    A collector must never take the pipeline down because a shell-out
    misbehaved, so every failure mode here degrades to "no events this tick".
    """
    try:
        done = subprocess.run(
            args,
            capture_output=True,
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except (subprocess.SubprocessError, OSError):
        return ""
    return done.stdout.decode("utf-8", errors="replace")


def collect_netconn() -> list[bytes]:
    """One CSV line per live TCP connection."""
    out = _run([*_PS, _NETCONN_PS])
    return [
        line.strip().encode("utf-8")
        for line in out.splitlines()
        if line.strip() and line.count(",") >= 7
    ]


_RECORD_ID_RE = re.compile(r"<EventRecordID>(\d+)</EventRecordID>")


def collect_eventlog(
    channels: tuple[str, ...],
    count: int = 40,
    *,
    seen: dict[str, int] | None = None,
) -> list[bytes]:
    """Level 1-3 events from the named channels, one XML doc each.

    ``seen`` is a per-channel high-water mark of ``EventRecordID``. Without it
    every poll re-emits the same most-recent events -- ``wevtutil`` has no
    "since" argument, it simply returns the latest N. Those re-emissions would
    be accepted as new events (identical bytes, but a fresh receipt time makes
    a fresh idempotency key), inflating the evidence with duplicates of events
    that happened once.

    A Windows event is a discrete past occurrence identified by its record id,
    so the high-water mark is the correct boundary.
    """
    events: list[bytes] = []
    for channel in channels:
        raw = _run(
            [
                "wevtutil", "qe", channel,
                "/q:*[System[(Level=1 or Level=2 or Level=3)]]",
                f"/c:{count}", "/rd:true", "/f:xml",
            ]
        )
        if not raw:
            continue

        highest = seen.get(channel, 0) if seen is not None else 0
        newest = highest
        # wevtutil concatenates <Event>...</Event> documents with no wrapper.
        for chunk in raw.split("</Event>"):
            chunk = chunk.strip()
            if not chunk.startswith("<Event"):
                continue
            doc = chunk + "</Event>"

            match = _RECORD_ID_RE.search(doc)
            record_id = int(match.group(1)) if match else 0
            if seen is not None:
                if record_id <= highest:
                    continue
                newest = max(newest, record_id)
            events.append(doc.encode("utf-8"))

        if seen is not None:
            # First poll primes the mark without emitting a backlog, so
            # starting capture does not dump the last N historical events in
            # as if they had just happened.
            seen[channel] = newest
    return events


def _connection_key(line: bytes) -> str:
    """Identity of a TCP connection: the 4-tuple, without the timestamp."""
    parts = line.decode("utf-8", errors="replace").split(",")
    return ",".join(parts[1:5]) if len(parts) >= 5 else line.decode(errors="replace")


@dataclass(slots=True)
class CollectorStatus:
    """What the collector is doing, for the UI to poll."""

    running: bool = False
    started_at: float | None = None
    ticks: int = 0
    collected: int = 0
    accepted: int = 0
    duplicates: int = 0
    last_tick_at: float | None = None
    last_error: str = ""
    by_source: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "running": self.running,
            "started_at": self.started_at,
            "uptime_s": None if self.started_at is None else round(
                time.time() - self.started_at, 1
            ),
            "ticks": self.ticks,
            "collected": self.collected,
            "accepted": self.accepted,
            "duplicates": self.duplicates,
            "last_tick_at": self.last_tick_at,
            "last_error": self.last_error,
            "by_source": dict(self.by_source),
        }


def collect_once(
    pipeline: Pipeline,
    *,
    channels: tuple[str, ...] = ("System", "Application"),
    seen_records: dict[str, int] | None = None,
    seen_connections: set[str] | None = None,
) -> dict[str, int]:
    """Collect one round from every source. Returns accepted counts per source.

    Both state arguments exist to record each real-world occurrence once. A
    firewall logs a connection *event*, not a connection's ongoing state, so a
    connection is recorded when first observed rather than re-emitted on every
    poll for as long as it stays open.
    """
    netconn = collect_netconn()
    if seen_connections is not None:
        fresh = []
        for line in netconn:
            key = _connection_key(line)
            if key not in seen_connections:
                seen_connections.add(key)
                fresh.append(line)
        netconn = fresh

    results: dict[str, int] = {}
    for source, payloads in (
        (NETCONN_SOURCE, netconn),
        (EVENTLOG_SOURCE, collect_eventlog(channels, seen=seen_records)),
    ):
        if not payloads:
            results[source] = 0
            continue
        outcome = pipeline.ingest(payloads, source, transport=Transport.FILE)
        results[source] = outcome.accepted

    return results


class LiveCollector:
    """Background poller. Start and stop are both idempotent."""

    def __init__(
        self,
        pipeline_factory: Callable[[], Any],
        *,
        interval: float = 10.0,
        channels: tuple[str, ...] = ("System", "Application"),
    ) -> None:
        self.pipeline_factory = pipeline_factory
        self.interval = interval
        self.channels = channels
        self.status = CollectorStatus()
        # Per-occurrence state, so each real event is recorded once.
        self._seen_records: dict[str, int] = {}
        self._seen_connections: set[str] = set()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()

    # ---- control ----------------------------------------------------------

    def start(self) -> CollectorStatus:
        with self._lock:
            if self.status.running:
                return self.status
            self._stop.clear()
            self._seen_records = {}
            self._seen_connections = set()
            self.status = CollectorStatus(running=True, started_at=time.time())
            self._thread = threading.Thread(
                target=self._loop, name="aufla-live-collector", daemon=True
            )
            self._thread.start()
            return self.status

    def stop(self) -> CollectorStatus:
        with self._lock:
            self._stop.set()
            self.status.running = False
        thread = self._thread
        if thread is not None:
            thread.join(timeout=5)
        self._thread = None
        return self.status

    @property
    def running(self) -> bool:
        return self.status.running

    # ---- loop -------------------------------------------------------------

    def _loop(self) -> None:
        # The first tick runs immediately so a click produces visible data at
        # once rather than after a full interval.
        while not self._stop.is_set():
            self._tick()
            if self._stop.wait(self.interval):
                break

    def _tick(self) -> None:
        pipeline = None
        try:
            # A fresh pipeline per tick: this thread owns its own SQLite
            # handles, which sqlite3.threadsafety == 1 requires.
            pipeline, closer = self.pipeline_factory()
            try:
                results = collect_once(
                    pipeline,
                    channels=self.channels,
                    seen_records=self._seen_records,
                    seen_connections=self._seen_connections,
                )
            finally:
                closer()

            with self._lock:
                self.status.ticks += 1
                self.status.last_tick_at = time.time()
                self.status.last_error = ""
                for source, accepted in results.items():
                    self.status.accepted += accepted
                    self.status.by_source[source] = (
                        self.status.by_source.get(source, 0) + accepted
                    )
        except Exception as exc:  # pragma: no cover - defensive
            with self._lock:
                self.status.ticks += 1
                self.status.last_tick_at = time.time()
                self.status.last_error = f"{type(exc).__name__}: {exc}"
