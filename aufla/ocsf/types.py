"""The OCSF field type system.

Logs arrive as text. OCSF is typed. This module is the boundary between the
two, and it is deliberately strict: a value that cannot be coerced into its
declared type is an error, not a silently-stored string.

That strictness is what closes the gap grammar-constrained decoding leaves
open. GBNF can guarantee a model emits the field name ``dst_endpoint.port``;
only a range check can notice that the value behind it is ``70000``.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any

__all__ = ["FieldType", "TypeError_", "CoerceResult", "coerce"]


class FieldType(str, Enum):
    """Types a mapped OCSF field may hold."""

    STRING = "string"
    INTEGER = "integer"
    LONG = "long"
    FLOAT = "float"
    BOOLEAN = "boolean"
    IP = "ip"
    PORT = "port"
    MAC = "mac"
    TIMESTAMP = "timestamp"   # epoch milliseconds, per OCSF
    HOSTNAME = "hostname"
    URL = "url"
    EMAIL = "email"
    UUID = "uuid"


class TypeError_(ValueError):
    """Raised when a value cannot be coerced into its declared field type."""


@dataclass(frozen=True, slots=True)
class CoerceResult:
    """Outcome of coercing one value."""

    ok: bool
    value: Any = None
    error: str = ""


# --- plausibility bounds -------------------------------------------------

# A syslog line claiming 1970 or 2098 is a clock fault, not evidence. These
# bounds are wide enough for real drift and narrow enough to catch a mapping
# that read the wrong column. The upper bound allows a full day of skew, since
# air-gapped sites cannot reach public NTP.
MIN_PLAUSIBLE_MS = int(datetime(2000, 1, 1, tzinfo=timezone.utc).timestamp() * 1000)
MAX_SKEW = timedelta(hours=25)

PORT_MIN, PORT_MAX = 1, 65535

_MAC_RE = re.compile(r"^(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$")
_MAC_BARE_RE = re.compile(r"^[0-9A-Fa-f]{12}$")
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
    r"(?:\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)
_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s.]+(?:\.[^@\s.]+)+$")
_TRUE = {"true", "t", "yes", "y", "1", "on", "allow", "success"}
_FALSE = {"false", "f", "no", "n", "0", "off", "deny", "failure"}


def _max_plausible_ms() -> int:
    return int((datetime.now(timezone.utc) + MAX_SKEW).timestamp() * 1000)


def _as_text(value: Any) -> str:
    return value.strip() if isinstance(value, str) else str(value)


# --- individual coercions ------------------------------------------------


def _coerce_int(value: Any, field_type: FieldType) -> CoerceResult:
    if isinstance(value, bool):
        return CoerceResult(False, error="boolean is not a valid integer")
    if isinstance(value, int):
        return CoerceResult(True, value)
    text = _as_text(value)
    try:
        return CoerceResult(True, int(text, 10))
    except ValueError:
        return CoerceResult(False, error=f"not an {field_type.value}: {text!r}")


def _coerce_port(value: Any) -> CoerceResult:
    parsed = _coerce_int(value, FieldType.PORT)
    if not parsed.ok:
        return CoerceResult(False, error=f"not a port: {_as_text(value)!r}")
    port = parsed.value
    if not PORT_MIN <= port <= PORT_MAX:
        return CoerceResult(
            False, error=f"port {port} outside {PORT_MIN}-{PORT_MAX}"
        )
    return CoerceResult(True, port)


def _coerce_ip(value: Any) -> CoerceResult:
    text = _as_text(value)
    # Vendors often append the port: 10.0.0.1:443
    if text.count(":") == 1 and "." in text:
        text = text.split(":", 1)[0]
    try:
        return CoerceResult(True, str(ipaddress.ip_address(text)))
    except ValueError:
        return CoerceResult(False, error=f"not an IP address: {text!r}")


def _coerce_mac(value: Any) -> CoerceResult:
    text = _as_text(value)
    if _MAC_RE.match(text):
        return CoerceResult(True, text.replace("-", ":").lower())
    if _MAC_BARE_RE.match(text):
        pairs = [text[i : i + 2] for i in range(0, 12, 2)]
        return CoerceResult(True, ":".join(pairs).lower())
    return CoerceResult(False, error=f"not a MAC address: {text!r}")


def _coerce_timestamp(value: Any) -> CoerceResult:
    parsed = _coerce_int(value, FieldType.TIMESTAMP)
    if not parsed.ok:
        return CoerceResult(False, error=f"not a timestamp: {_as_text(value)!r}")
    ms = parsed.value
    upper = _max_plausible_ms()
    if ms < MIN_PLAUSIBLE_MS:
        return CoerceResult(
            False, error=f"timestamp {ms} is before 2000-01-01; likely a clock fault"
        )
    if ms > upper:
        return CoerceResult(
            False, error=f"timestamp {ms} is more than 25h in the future"
        )
    return CoerceResult(True, ms)


def _coerce_bool(value: Any) -> CoerceResult:
    if isinstance(value, bool):
        return CoerceResult(True, value)
    text = _as_text(value).lower()
    if text in _TRUE:
        return CoerceResult(True, True)
    if text in _FALSE:
        return CoerceResult(True, False)
    return CoerceResult(False, error=f"not a boolean: {text!r}")


def _coerce_float(value: Any) -> CoerceResult:
    if isinstance(value, bool):
        return CoerceResult(False, error="boolean is not a valid float")
    try:
        return CoerceResult(True, float(value))
    except (TypeError, ValueError):
        return CoerceResult(False, error=f"not a float: {_as_text(value)!r}")


def _coerce_pattern(value: Any, pattern: re.Pattern[str], label: str) -> CoerceResult:
    text = _as_text(value)
    if pattern.match(text):
        return CoerceResult(True, text)
    return CoerceResult(False, error=f"not a {label}: {text!r}")


def _coerce_url(value: Any) -> CoerceResult:
    text = _as_text(value)
    if "://" in text and len(text.split("://", 1)[0]) > 0:
        return CoerceResult(True, text)
    return CoerceResult(False, error=f"not a URL: {text!r}")


def _coerce_uuid(value: Any) -> CoerceResult:
    import uuid as _uuid

    text = _as_text(value)
    try:
        return CoerceResult(True, str(_uuid.UUID(text)))
    except ValueError:
        return CoerceResult(False, error=f"not a UUID: {text!r}")


_COERCERS = {
    FieldType.INTEGER: lambda v: _coerce_int(v, FieldType.INTEGER),
    FieldType.LONG: lambda v: _coerce_int(v, FieldType.LONG),
    FieldType.PORT: _coerce_port,
    FieldType.IP: _coerce_ip,
    FieldType.MAC: _coerce_mac,
    FieldType.TIMESTAMP: _coerce_timestamp,
    FieldType.BOOLEAN: _coerce_bool,
    FieldType.FLOAT: _coerce_float,
    FieldType.HOSTNAME: lambda v: _coerce_pattern(v, _HOSTNAME_RE, "hostname"),
    FieldType.EMAIL: lambda v: _coerce_pattern(v, _EMAIL_RE, "email address"),
    FieldType.URL: _coerce_url,
    FieldType.UUID: _coerce_uuid,
}


def coerce(value: Any, field_type: FieldType) -> CoerceResult:
    """Coerce ``value`` into ``field_type``.

    Returns a :class:`CoerceResult` rather than raising, because the caller is
    usually validating a whole record and wants every problem at once, not the
    first one.
    """
    if value is None:
        return CoerceResult(False, error="value is None")

    if field_type is FieldType.STRING:
        text = value if isinstance(value, str) else str(value)
        if text == "":
            return CoerceResult(False, error="empty string")
        return CoerceResult(True, text)

    handler = _COERCERS.get(field_type)
    if handler is None:  # pragma: no cover - defensive
        return CoerceResult(False, error=f"no coercer for {field_type}")
    return handler(value)
