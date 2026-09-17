"""Following log files as they are written.

This is how AUFLA ingests from anything that writes to disk -- a container, a
daemon, a mounted share, a file dropped by an agent. The producer needs to know
nothing about AUFLA; it logs the way it always would, and the tailer reads what
lands.

Three things a naive ``tail -f`` gets wrong, all handled here:

**Rotation.** A rotated file is a *new* file at the same path. Following the
old handle means silently reading nothing forever while the log fills up
elsewhere. Rotation is detected by inode (or, on Windows, by the file
shrinking) and the tailer reopens from the start.

**Partial lines.** A writer can be interrupted mid-line. Reading to EOF and
splitting on newlines would ingest half an event and then the other half as a
second event. Only complete newline-terminated lines are emitted; a trailing
fragment is held until its newline arrives.

**Restart.** Offsets are persisted, so restarting the collector does not
re-ingest a file from the beginning. Deduplication would catch most of that
anyway, but re-reading gigabytes to discard them is not a real answer.
"""

from __future__ import annotations

import json
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Iterable

from ..models import Transport

__all__ = ["FileTailer", "TailState", "WatchSpec", "default_specs"]


@dataclass(slots=True)
class WatchSpec:
    """One file (or glob) and the source it is ingested as."""

    pattern: str
    source_id: str
    transport: Transport = Transport.FILE
    # Lines to skip, e.g. Zeek's "#fields" header block.
    skip_prefix: str | None = None


# Conventional layout of docker/logs, mapping each product's log to its source.
# A deployment with different paths passes its own specs; this is a default,
# not a constraint.
def default_specs() -> list[WatchSpec]:
    return [
        WatchSpec("nginx/access.log", "nginx_access"),
        WatchSpec("nginx/error.log", "nginx_error"),
        WatchSpec("squid/access.log", "squid_access"),
        WatchSpec("postfix/maillog", "postfix_maillog"),
        WatchSpec("ssh/*.log", "openssh_auth"),
        WatchSpec("suricata/eve.json", "suricata_eve"),
        WatchSpec("zeek/conn.log", "zeek_conn", skip_prefix="#"),
        WatchSpec("netfilter/*.log", "iptables"),
        WatchSpec("auditd/audit.log", "linux_auditd"),
    ]


@dataclass(slots=True)
class TailState:
    """Where the tailer had reached in one file."""

    offset: int = 0
    inode: int | None = None
    size: int = 0
    pending: str = ""          # a partial final line, awaiting its newline


@dataclass(slots=True)
class TailStats:
    files: int = 0
    lines: int = 0
    accepted: int = 0
    rotations: int = 0
    errors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, Any]:
        return {
            "files": self.files,
            "lines": self.lines,
            "accepted": self.accepted,
            "rotations": self.rotations,
            "errors": self.errors[-5:],
        }


class FileTailer:
    """Follows a set of files, feeding complete lines into a pipeline."""

    def __init__(
        self,
        directory: str | Path,
        pipeline_factory: Callable[[], Any],
        *,
        specs: Iterable[WatchSpec] | None = None,
        interval: float = 3.0,
        state_path: str | Path | None = None,
        max_lines_per_read: int = 5000,
    ) -> None:
        self.directory = Path(directory)
        self.pipeline_factory = pipeline_factory
        self.specs = list(specs if specs is not None else default_specs())
        self.interval = interval
        self.state_path = Path(state_path) if state_path else None
        self.max_lines_per_read = max_lines_per_read

        self.states: dict[str, TailState] = {}
        self.stats = TailStats()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._load_state()

    # ---- offset persistence ----------------------------------------------

    def _load_state(self) -> None:
        if not self.state_path or not self.state_path.exists():
            return
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for path, d in raw.items():
            self.states[path] = TailState(
                offset=d.get("offset", 0),
                inode=d.get("inode"),
                size=d.get("size", 0),
            )

    def _save_state(self) -> None:
        if not self.state_path:
            return
        self.state_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {
            p: {"offset": s.offset, "inode": s.inode, "size": s.size}
            for p, s in self.states.items()
        }
        try:
            self.state_path.write_text(json.dumps(payload), encoding="utf-8")
        except OSError as exc:  # pragma: no cover - defensive
            self.stats.errors.append(f"state write failed: {exc}")

    # ---- reading ----------------------------------------------------------

    def _resolve(self, spec: WatchSpec) -> list[Path]:
        if any(ch in spec.pattern for ch in "*?["):
            return sorted(self.directory.glob(spec.pattern))
        path = self.directory / spec.pattern
        return [path] if path.exists() else []

    def read_new_lines(self, path: Path) -> list[str]:
        """Complete lines appended since the last read."""
        key = str(path)
        state = self.states.setdefault(key, TailState())

        try:
            st = path.stat()
        except OSError:
            return []

        inode = getattr(st, "st_ino", None) or None
        rotated = (
            (state.inode is not None and inode is not None and inode != state.inode)
            # Windows reuses inodes, so a file that shrank is the better signal.
            or st.st_size < state.size
        )
        if rotated:
            state.offset = 0
            state.pending = ""
            self.stats.rotations += 1

        state.inode = inode
        state.size = st.st_size

        if st.st_size <= state.offset:
            return []

        try:
            with path.open("rb") as fh:
                fh.seek(state.offset)
                chunk = fh.read()
                state.offset = fh.tell()
        except OSError as exc:
            self.stats.errors.append(f"{path.name}: {exc}")
            return []

        text = state.pending + chunk.decode("utf-8", errors="replace")
        lines = text.split("\n")
        # The final element is whatever came after the last newline: either an
        # empty string, or a line the writer has not finished yet.
        state.pending = lines.pop()
        return [ln.rstrip("\r") for ln in lines if ln.strip()]

    # ---- one pass ---------------------------------------------------------

    def poll_once(self) -> TailStats:
        """Read every watched file once and ingest whatever is new."""
        batches: dict[tuple[str, Transport], list[bytes]] = {}
        seen_files = 0

        for spec in self.specs:
            for path in self._resolve(spec):
                seen_files += 1
                lines = self.read_new_lines(path)[: self.max_lines_per_read]
                if spec.skip_prefix:
                    lines = [ln for ln in lines if not ln.startswith(spec.skip_prefix)]
                if lines:
                    key = (spec.source_id, spec.transport)
                    batches.setdefault(key, []).extend(ln.encode("utf-8") for ln in lines)

        self.stats.files = seen_files
        if not batches:
            self._save_state()
            return self.stats

        pipeline, closer = self.pipeline_factory()
        try:
            for (source_id, transport), payloads in batches.items():
                result = pipeline.ingest(payloads, source_id, transport=transport)
                self.stats.lines += len(payloads)
                self.stats.accepted += result.accepted
        finally:
            closer()

        self._save_state()
        return self.stats

    # ---- background loop --------------------------------------------------

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop.clear()
            self._thread = threading.Thread(
                target=self._loop, name="aufla-file-tailer", daemon=True
            )
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread is not None:
            thread.join(timeout=5)
        self._thread = None

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self.poll_once()
            except Exception as exc:  # pragma: no cover - defensive
                self.stats.errors.append(f"{type(exc).__name__}: {exc}")
            if self._stop.wait(self.interval):
                break
