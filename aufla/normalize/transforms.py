"""Transforms and lookup tables available to mappings.

Both registries are closed sets. A mapping naming a transform that does not
exist fails at load rather than at 3am, and -- more importantly -- a model
proposing a mapping cannot invent a transform any more than it can invent an
OCSF field. The set of things a mapping may *do* is as bounded as the set of
fields it may target.
"""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

__all__ = [
    "TransformError",
    "TRANSFORMS",
    "LOOKUPS",
    "apply_transform",
    "apply_lookup",
    "syslog_time_to_ms",
]


class TransformError(ValueError):
    """Raised when a transform cannot be applied to a value."""


# --- time ----------------------------------------------------------------

_SYSLOG_TS_RE = re.compile(
    r"^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})"
)
_MONTHS = {
    m: i
    for i, m in enumerate(
        ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
         "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"],
        start=1,
    )
}


def iso8601(value: Any) -> int:
    """ISO-8601 timestamp to epoch milliseconds."""
    text = str(value).strip()
    # Python's parser wants +HH:MM, while many loggers emit +HHMM.
    normalised = re.sub(r"([+-]\d{2})(\d{2})$", r"\1:\2", text)
    if normalised.endswith("Z"):
        normalised = normalised[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(normalised)
    except ValueError:
        raise TransformError(f"not an ISO-8601 timestamp: {text!r}") from None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def syslog_time_to_ms(value: Any, *, reference: datetime | None = None) -> int:
    """RFC 3164 timestamp to epoch milliseconds.

    RFC 3164 omits the year, so it has to be inferred. The reference clock's
    year is assumed; if that lands more than a day in the future, the previous
    year is used instead. That is the December-to-January rollover case, which
    otherwise silently dates every new-year event twelve months ahead.
    """
    text = str(value).strip()
    m = _SYSLOG_TS_RE.match(text)
    if not m:
        raise TransformError(f"not an RFC 3164 timestamp: {text!r}")

    month_name, day, hour, minute, second = m.groups()
    month = _MONTHS.get(month_name)
    if month is None:
        raise TransformError(f"unknown month {month_name!r}")

    ref = reference or datetime.now(timezone.utc)
    try:
        dt = datetime(
            ref.year, month, int(day), int(hour), int(minute), int(second),
            tzinfo=timezone.utc,
        )
    except ValueError as exc:
        raise TransformError(f"invalid date in {text!r}: {exc}") from None

    if dt - ref > timedelta(days=1):
        dt = dt.replace(year=ref.year - 1)
    return int(dt.timestamp() * 1000)


def epoch_seconds(value: Any) -> int:
    try:
        return int(float(value) * 1000)
    except (TypeError, ValueError):
        raise TransformError(f"not epoch seconds: {value!r}") from None


def epoch_millis(value: Any) -> int:
    try:
        return int(float(value))
    except (TypeError, ValueError):
        raise TransformError(f"not epoch milliseconds: {value!r}") from None


# --- text ----------------------------------------------------------------


def after_slash(value: Any) -> str:
    """``TCP_MISS/200`` to ``200``. Squid and several proxies pack two
    values into one column this way."""
    text = str(value)
    return text.rsplit("/", 1)[-1] if "/" in text else text


def before_slash(value: Any) -> str:
    text = str(value)
    return text.split("/", 1)[0] if "/" in text else text


def strip_quotes(value: Any) -> str:
    return str(value).strip().strip('"').strip("'")


def basename(value: Any) -> str:
    return re.split(r"[\\/]", str(value))[-1]


def lowercase(value: Any) -> str:
    return str(value).lower()


def uppercase(value: Any) -> str:
    return str(value).upper()


def to_int(value: Any) -> int:
    try:
        return int(str(value).strip(), 10)
    except ValueError:
        raise TransformError(f"not an integer: {value!r}") from None


def strip_port(value: Any) -> str:
    """``10.0.0.1:443`` to ``10.0.0.1``, leaving IPv6 untouched."""
    text = str(value).strip()
    return text.split(":", 1)[0] if text.count(":") == 1 and "." in text else text


TRANSFORMS: dict[str, Callable[[Any], Any]] = {
    "iso8601": iso8601,
    "syslog_time": syslog_time_to_ms,
    "epoch_seconds": epoch_seconds,
    "epoch_millis": epoch_millis,
    "after_slash": after_slash,
    "before_slash": before_slash,
    "strip_quotes": strip_quotes,
    "basename": basename,
    "lowercase": lowercase,
    "uppercase": uppercase,
    "to_int": to_int,
    "strip_port": strip_port,
}


# --- lookups -------------------------------------------------------------

# OCSF severity_id: 0 Unknown, 1 Informational, 2 Low, 3 Medium, 4 High,
# 5 Critical, 6 Fatal.
SURICATA_SEVERITY = {"1": 4, "2": 3, "3": 2}

# OCSF HTTP Activity activity_id.
HTTP_METHOD_ACTIVITY = {
    "CONNECT": 1, "DELETE": 2, "GET": 3, "HEAD": 4, "OPTIONS": 5,
    "POST": 6, "PUT": 7, "TRACE": 8, "PATCH": 9,
}

# OCSF disposition_id for common firewall verdicts.
FIREWALL_DISPOSITION = {
    "ALLOW": 1, "PASS": 1, "ACCEPT": 1, "PERMIT": 1,
    "BLOCK": 2, "DENY": 2, "DROP": 2, "REJECT": 2,
}

SYSLOG_SEVERITY_TO_OCSF = {
    "0": 6, "1": 5, "2": 5, "3": 4, "4": 3, "5": 1, "6": 1, "7": 1,
}

LOOKUPS: dict[str, dict[str, Any]] = {
    "suricata_severity": SURICATA_SEVERITY,
    "http_method_activity": HTTP_METHOD_ACTIVITY,
    "firewall_disposition": FIREWALL_DISPOSITION,
    "syslog_severity": SYSLOG_SEVERITY_TO_OCSF,
}


def apply_transform(name: str, value: Any) -> Any:
    fn = TRANSFORMS.get(name)
    if fn is None:
        raise TransformError(
            f"unknown transform {name!r}; known: {', '.join(sorted(TRANSFORMS))}"
        )
    return fn(value)


def apply_lookup(name: str, value: Any, default: Any = None) -> Any:
    """Look ``value`` up in a named table.

    Keys are matched case-insensitively as strings, since vendors are wildly
    inconsistent about casing in the values they emit.
    """
    table = LOOKUPS.get(name)
    if table is None:
        raise TransformError(
            f"unknown lookup {name!r}; known: {', '.join(sorted(LOOKUPS))}"
        )
    key = str(value).strip()
    if key in table:
        return table[key]
    upper = key.upper()
    for candidate, result in table.items():
        if candidate.upper() == upper:
            return result
    return default
