"""Core event types.

``RawEvent`` is the permanent record. Everything else in AUFLA is derived from
it and can be rebuilt by replaying these rows through a mapping.

The single most important rule in the codebase is enforced here: ``raw_bytes``
is ``bytes``, never ``str``. Decoding at ingest would silently destroy data on
malformed vendor output, and that loss is unrecoverable. Text is produced on
demand by :meth:`RawEvent.text`, which never raises and never mutates the
stored bytes.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from .ids import idempotency_key, now_ns, sha256_hex, uuid7

__all__ = ["Transport", "ParseStatus", "RawEvent"]


class Transport(str, Enum):
    """How an event reached us. Bears on whether loss is possible upstream."""

    TCP = "tcp"
    UDP = "udp"
    RELP = "relp"
    TLS = "tls"
    FILE = "file"
    TEST = "test"


class ParseStatus(str, Enum):
    """Honest reporting of how far normalisation got for an event."""

    FULL = "full"
    PARTIAL = "partial"
    QUARANTINED = "quarantined"


# RFC 3164 mandates a 1024-byte maximum for syslog over UDP. Anything arriving
# at exactly that size over UDP was plausibly cut off by the wire, so we record
# the suspicion rather than silently pretending the event is complete.
RFC3164_MAX_UDP_BYTES = 1024


@dataclass(frozen=True, slots=True)
class RawEvent:
    """One event exactly as it arrived, plus the metadata we observed ourselves.

    Frozen because a raw event is immutable by definition. Anything that wants
    to annotate an event produces a derived record instead of mutating this one.
    """

    event_uid: uuid.UUID
    raw_bytes: bytes
    raw_hash: str
    source_id: str
    received_at_ns: int
    byte_len: int
    idem_key: str
    source_ip: str | None = None
    transport: Transport = Transport.TEST
    charset: str = "unknown"
    truncated: bool = False
    meta: dict[str, Any] = field(default_factory=dict)

    # ---- construction -----------------------------------------------------

    @classmethod
    def capture(
        cls,
        raw_bytes: bytes,
        source_id: str,
        *,
        source_ip: str | None = None,
        transport: Transport = Transport.TEST,
        received_at_ns: int | None = None,
        charset: str = "unknown",
        truncated: bool | None = None,
        meta: dict[str, Any] | None = None,
    ) -> "RawEvent":
        """Capture an event at the ingest boundary.

        This is the only supported way to create a :class:`RawEvent`. It assigns
        the identity triple (uid, hash, idempotency key) so that no other part
        of the system has to decide how identity works.
        """
        if not isinstance(raw_bytes, (bytes, bytearray, memoryview)):
            raise TypeError(
                "raw_bytes must be bytes-like; decoding at ingest loses data. "
                f"got {type(raw_bytes).__name__}"
            )
        payload = bytes(raw_bytes)

        if not source_id:
            raise ValueError("source_id is required")

        ts = now_ns() if received_at_ns is None else received_at_ns

        if truncated is None:
            truncated = (
                transport is Transport.UDP and len(payload) >= RFC3164_MAX_UDP_BYTES
            )

        return cls(
            event_uid=uuid7(ts // 1_000_000),
            raw_bytes=payload,
            raw_hash=sha256_hex(payload),
            source_id=source_id,
            received_at_ns=ts,
            byte_len=len(payload),
            idem_key=idempotency_key(payload, source_id, ts),
            source_ip=source_ip,
            transport=transport,
            charset=charset,
            truncated=truncated,
            meta=dict(meta or {}),
        )

    # ---- derived views ----------------------------------------------------

    def text(self, encoding: str = "utf-8") -> str:
        """Best-effort text view of the payload. Never raises, never mutates.

        Undecodable bytes are replaced, so a parser always gets a usable string
        while the pristine bytes remain available via :attr:`raw_bytes`.
        """
        return self.raw_bytes.decode(encoding, errors="replace")

    def verify(self) -> bool:
        """Recompute the content hash and confirm the bytes are unchanged."""
        return sha256_hex(self.raw_bytes) == self.raw_hash

    @property
    def received_at_iso(self) -> str:
        """Receipt time as an ISO-8601 UTC string, nanosecond precision kept."""
        from datetime import datetime, timezone

        secs, nanos = divmod(self.received_at_ns, 1_000_000_000)
        dt = datetime.fromtimestamp(secs, tz=timezone.utc)
        return f"{dt.strftime('%Y-%m-%dT%H:%M:%S')}.{nanos:09d}Z"

    def __repr__(self) -> str:  # pragma: no cover - debugging aid
        preview = self.raw_bytes[:48]
        return (
            f"RawEvent(uid={self.event_uid}, source={self.source_id!r}, "
            f"len={self.byte_len}, hash={self.raw_hash[:12]}…, "
            f"bytes={preview!r}{'…' if self.byte_len > 48 else ''})"
        )
