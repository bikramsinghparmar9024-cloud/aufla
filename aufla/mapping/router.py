"""Format detection and discovery-strategy routing.

Not every unknown format needs a language model, and pretending otherwise is
both slower and less defensible. CEF and LEEF are self-describing key-value
formats defined by published specifications; JSON and XML carry their own
structure. Only free-text syslog genuinely requires template mining and a
model proposal.

Routing on detected format means inference is invoked *only where deterministic
parsing actually fails*, which is a far stronger engineering claim than
"the AI handles everything".
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

__all__ = [
    "LogFormat",
    "DiscoveryStrategy",
    "Detection",
    "detect_format",
    "strip_syslog_header",
]


class LogFormat(str, Enum):
    CEF = "cef"
    LEEF = "leef"
    JSON = "json"
    XML = "xml"
    CSV = "csv"
    KEY_VALUE = "key_value"
    SYSLOG_TEXT = "syslog_text"
    UNKNOWN = "unknown"


class DiscoveryStrategy(str, Enum):
    """How an unknown source of this format should be onboarded."""

    SPEC_PARSE = "spec_parse"        # published spec; no inference at all
    SCHEMA_WALK = "schema_walk"      # structure is self-describing
    POSITIONAL = "positional"        # columns, needs header or human hint
    TEMPLATE_MINING = "template_mining"  # Drain3 + model proposal
    NONE = "none"


# Free text is the only path that reaches the model.
_STRATEGY = {
    LogFormat.CEF: DiscoveryStrategy.SPEC_PARSE,
    LogFormat.LEEF: DiscoveryStrategy.SPEC_PARSE,
    LogFormat.KEY_VALUE: DiscoveryStrategy.SPEC_PARSE,
    LogFormat.JSON: DiscoveryStrategy.SCHEMA_WALK,
    LogFormat.XML: DiscoveryStrategy.SCHEMA_WALK,
    LogFormat.CSV: DiscoveryStrategy.POSITIONAL,
    LogFormat.SYSLOG_TEXT: DiscoveryStrategy.TEMPLATE_MINING,
    LogFormat.UNKNOWN: DiscoveryStrategy.TEMPLATE_MINING,
}


@dataclass(frozen=True, slots=True)
class Detection:
    """What the router concluded about one event."""

    format: LogFormat
    strategy: DiscoveryStrategy
    confidence: float
    body: str
    syslog_pri: int | None = None
    syslog_tag: str | None = None
    hints: dict[str, Any] = field(default_factory=dict)

    @property
    def needs_model(self) -> bool:
        return self.strategy is DiscoveryStrategy.TEMPLATE_MINING

    @property
    def severity(self) -> int | None:
        """Syslog severity (0-7) decoded from the priority value."""
        return None if self.syslog_pri is None else self.syslog_pri % 8

    @property
    def facility(self) -> int | None:
        """Syslog facility decoded from the priority value."""
        return None if self.syslog_pri is None else self.syslog_pri // 8


# RFC 3164/5424 priority, e.g. "<134>" or "<134>1 ".
_PRI_RE = re.compile(r"^<(\d{1,3})>(\d\s)?")
# RFC 3164 header: "Mmm dd hh:mm:ss host tag[pid]:"
_RFC3164_RE = re.compile(
    r"^[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+(\S+)\s+"
    r"([A-Za-z0-9_\-./]+)(?:\[\d+\])?:\s*"
)
# RFC 5424 header: version timestamp host app procid msgid
_RFC5424_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T[\d:.+\-Z]+\s+(\S+)\s+(\S+)\s+(\S+)\s+(\S+)\s+"
)
_CEF_RE = re.compile(r"CEF:\d+\|")
_LEEF_RE = re.compile(r"LEEF:\d+\.\d+\|")
_XML_RE = re.compile(r"^\s*<(?:\?xml|[A-Za-z_][\w.\-]*[\s/>])")
_KV_RE = re.compile(r"[A-Za-z_][\w.\-]*=(?:\"[^\"]*\"|\S*)")


def strip_syslog_header(text: str) -> tuple[str, int | None, str | None]:
    """Remove any syslog framing and return ``(body, priority, tag)``.

    Detection runs on the body. A CEF payload wrapped in syslog framing is
    still CEF, and treating it as free text would send it to the model for no
    reason.
    """
    pri: int | None = None
    tag: str | None = None
    body = text.lstrip("﻿").strip()

    m = _PRI_RE.match(body)
    if m:
        value = int(m.group(1))
        # Valid syslog priority is 0-191; anything higher is not a PRI field.
        if value <= 191:
            pri = value
            body = body[m.end() :].lstrip()

    m = _RFC3164_RE.match(body)
    if m:
        tag = m.group(2)
        return body[m.end() :], pri, tag

    m = _RFC5424_RE.match(body)
    if m:
        tag = m.group(2)
        return body[m.end() :], pri, tag

    return body, pri, tag


def _looks_like_csv(body: str) -> tuple[bool, dict[str, Any]]:
    """Comma-separated with enough columns and no free-text prose."""
    if "," not in body:
        return False, {}
    try:
        row = next(csv.reader(io.StringIO(body)))
    except (csv.Error, StopIteration):
        return False, {}
    if len(row) < 4:
        return False, {}
    # Prose contains spaces inside most fields; column data rarely does.
    spacey = sum(1 for cell in row if " " in cell.strip())
    if spacey > len(row) / 2:
        return False, {}
    return True, {"columns": len(row)}


def detect_format(raw: str | bytes) -> Detection:
    """Classify one event and choose its discovery strategy."""
    if isinstance(raw, (bytes, bytearray, memoryview)):
        text = bytes(raw).decode("utf-8", errors="replace")
    else:
        text = raw

    body, pri, tag = strip_syslog_header(text)

    def result(fmt: LogFormat, confidence: float, **hints: Any) -> Detection:
        return Detection(
            format=fmt,
            strategy=_STRATEGY[fmt],
            confidence=confidence,
            body=body,
            syslog_pri=pri,
            syslog_tag=tag,
            hints=hints,
        )

    if not body.strip():
        return result(LogFormat.UNKNOWN, 0.0, reason="empty payload")

    # Published specs first: these are unambiguous and need no inference.
    if _CEF_RE.search(body):
        return result(LogFormat.CEF, 1.0)
    if _LEEF_RE.search(body):
        return result(LogFormat.LEEF, 1.0)

    stripped = body.strip()

    if stripped[0] in "{[":
        try:
            parsed = json.loads(stripped)
        except ValueError:
            pass
        else:
            keys = sorted(parsed)[:20] if isinstance(parsed, dict) else []
            return result(LogFormat.JSON, 1.0, keys=keys)

    if _XML_RE.match(stripped):
        return result(LogFormat.XML, 0.9)

    is_csv, csv_hints = _looks_like_csv(stripped)
    if is_csv:
        return result(LogFormat.CSV, 0.8, **csv_hints)

    # Key-value pairs (sshd, Postfix, many appliances). Self-describing, so
    # still no model required.
    pairs = _KV_RE.findall(stripped)
    if len(pairs) >= 3:
        density = sum(len(p) for p in pairs) / max(len(stripped), 1)
        if density >= 0.4:
            return result(LogFormat.KEY_VALUE, 0.75, pairs=len(pairs))

    return result(LogFormat.SYSLOG_TEXT, 0.6)
