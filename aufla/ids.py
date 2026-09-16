"""Identity primitives: event ids, content hashes, idempotency keys.

Every event entering AUFLA gets exactly one identity, assigned here and never
recomputed elsewhere. Three distinct concepts live in this module and must not
be confused:

``event_uid``
    A UUIDv7. Unique per *accepted* event, time-ordered so that it clusters on
    disk by arrival. Two byte-identical events received a second apart get
    different uids -- they are genuinely two events.

``raw_hash``
    SHA-256 of the raw bytes. Identical payloads share a hash by design; this
    is what an investigator recomputes to prove the stored bytes were not
    substituted.

``idempotency_key``
    SHA-256 over (bytes, source, arrival nanosecond). Used only to collapse
    at-least-once redelivery from the streaming buffer. A genuine duplicate
    from a device retry is a *different* event and keeps its own row.
"""

from __future__ import annotations

import hashlib
import os
import time
import uuid

__all__ = [
    "uuid7",
    "uuid7_timestamp_ms",
    "sha256_bytes",
    "sha256_hex",
    "idempotency_key",
    "now_ns",
]


def now_ns() -> int:
    """Wall-clock nanoseconds since the Unix epoch.

    This is the receipt clock -- the only clock AUFLA treats as trustworthy.
    Device-claimed timestamps are parsed separately and never overwrite it.
    """
    return time.time_ns()


def uuid7(timestamp_ms: int | None = None) -> uuid.UUID:
    """Return a UUID version 7 (time-ordered) as specified by RFC 9562.

    Layout::

        unix_ts_ms : 48 bits   big-endian milliseconds since the epoch
        ver        :  4 bits   0b0111
        rand_a     : 12 bits
        var        :  2 bits   0b10
        rand_b     : 62 bits

    Python 3.10 has no ``uuid.uuid7``, so it is built here. Ordering by the
    resulting uid is ordering by arrival time, which is what makes the raw
    table cheap to scan for a forensic time range.
    """
    if timestamp_ms is None:
        timestamp_ms = time.time_ns() // 1_000_000
    if not 0 <= timestamp_ms < (1 << 48):
        raise ValueError(f"timestamp_ms out of range for UUIDv7: {timestamp_ms}")

    rand = os.urandom(10)

    b = bytearray(16)
    b[0:6] = timestamp_ms.to_bytes(6, "big")
    # 4-bit version 0b0111 in the high nibble, 12 bits of randomness below it
    b[6] = 0x70 | (rand[0] & 0x0F)
    b[7] = rand[1]
    # 2-bit variant 0b10 in the top bits, 62 bits of randomness below it
    b[8] = 0x80 | (rand[2] & 0x3F)
    b[9:16] = rand[3:10]

    return uuid.UUID(bytes=bytes(b))


def uuid7_timestamp_ms(value: uuid.UUID) -> int:
    """Recover the embedded millisecond timestamp from a UUIDv7."""
    if value.version != 7:
        raise ValueError(f"not a UUIDv7: version={value.version}")
    return int.from_bytes(value.bytes[0:6], "big")


def sha256_bytes(payload: bytes) -> bytes:
    """SHA-256 digest of ``payload`` as 32 raw bytes."""
    return hashlib.sha256(payload).digest()


def sha256_hex(payload: bytes) -> str:
    """SHA-256 digest of ``payload`` as a 64-character lowercase hex string."""
    return hashlib.sha256(payload).hexdigest()


def idempotency_key(raw_bytes: bytes, source_id: str, received_at_ns: int) -> str:
    """Key used to collapse at-least-once redelivery.

    The source id is length-prefixed so that ``("ab", "c")`` and ``("a", "bc")``
    cannot collide into the same key.
    """
    source = source_id.encode("utf-8")
    h = hashlib.sha256()
    h.update(raw_bytes)
    h.update(b"\x00")
    h.update(len(source).to_bytes(4, "big"))
    h.update(source)
    h.update(received_at_ns.to_bytes(8, "big"))
    return h.hexdigest()
