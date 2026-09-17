"""Format parsers.

Each parser turns an event body into a :class:`ParsedEvent`, which exposes two
access modes:

* **positional** -- ``$7``, for ordered formats like CSV and the CEF header
* **named** -- ``$src_ip`` or ``$alert.signature``, for self-describing formats

CEF and LEEF provide both: their header is ordered and their extension section
is key-value. A mapping can therefore reach either part naturally.
"""

from __future__ import annotations

import csv
import io
import json
import re
from dataclasses import dataclass, field
from typing import Any

__all__ = ["ParseError", "ParsedEvent", "parse_body", "PARSERS", "RAW_REF"]

# Reserved name for the unparsed body: `$_raw` in a mapping.
RAW_REF = "_raw"


class ParseError(ValueError):
    """Raised when a body cannot be parsed as its declared format."""


_MISSING = object()


@dataclass(slots=True)
class ParsedEvent:
    """A parsed event body, addressable positionally and by name."""

    positional: list[str] = field(default_factory=list)
    named: dict[str, Any] = field(default_factory=dict)
    format: str = "unknown"
    # The whole body, before splitting. Free-text formats carry their values
    # inside prose rather than in fields, so a regex has to run against the
    # entire message; every format exposes it as `$_raw` so a mapping reaches
    # it the same way regardless of how the body was parsed.
    raw_body: str = ""

    def get_positional(self, index: int) -> Any:
        """1-indexed positional access. Out of range yields ``None``."""
        if index < 1 or index > len(self.positional):
            return None
        value = self.positional[index - 1]
        return None if value == "" else value

    def get_named(self, path: str) -> Any:
        """Named access, dotted for nesting.

        An exact key match wins over path traversal, because vendors do emit
        literal keys containing dots (``src.ip``).
        """
        if path == RAW_REF:
            return self.raw_body
        if path in self.named:
            return self.named[path]

        current: Any = self.named
        for part in path.split("."):
            if isinstance(current, dict):
                current = current.get(part, _MISSING)
            elif isinstance(current, list):
                try:
                    current = current[int(part)]
                except (ValueError, IndexError):
                    return None
            else:
                return None
            if current is _MISSING:
                return None
        return current

    @property
    def field_count(self) -> int:
        return len(self.positional) or len(self.named)


# --- delimited -----------------------------------------------------------


def parse_csv(body: str) -> ParsedEvent:
    try:
        row = next(csv.reader(io.StringIO(body)))
    except (csv.Error, StopIteration) as exc:
        raise ParseError(f"not parseable as CSV: {exc}") from None
    return ParsedEvent(positional=[c.strip() for c in row], format="csv")


def parse_ssv(body: str) -> ParsedEvent:
    """Whitespace-separated values, as used by Squid and many access logs."""
    parts = body.split()
    if not parts:
        raise ParseError("empty whitespace-separated body")
    return ParsedEvent(positional=parts, format="ssv")


def parse_tsv(body: str) -> ParsedEvent:
    parts = body.split("\t")
    return ParsedEvent(positional=[p.strip() for p in parts], format="tsv")


# --- structured ----------------------------------------------------------


def _flatten(
    obj: Any,
    prefix: str = "",
    out: dict[str, Any] | None = None,
    literal: set[str] | None = None,
) -> dict[str, Any]:
    """Flatten nested structures so ``a.b.c`` reaches a leaf directly.

    A key that literally contains a dot always beats the same path synthesised
    by traversal. Without tracking that, ``{"src.ip": x, "src": {"ip": y}}``
    would resolve to whichever key dict iteration happened to reach last.
    """
    out = {} if out is None else out
    literal = set() if literal is None else literal

    def put(path: str, value: Any, is_literal: bool) -> None:
        if is_literal:
            out[path] = value
            literal.add(path)
        elif path not in literal:
            out[path] = value

    if isinstance(obj, dict):
        for key, value in obj.items():
            name = str(key)
            path = f"{prefix}.{name}" if prefix else name
            put(path, value, "." in name)
            _flatten(value, path, out, literal)
    elif isinstance(obj, list):
        for i, value in enumerate(obj):
            path = f"{prefix}.{i}" if prefix else str(i)
            put(path, value, False)
            _flatten(value, path, out, literal)
    return out


def parse_json(body: str) -> ParsedEvent:
    try:
        data = json.loads(body)
    except ValueError as exc:
        raise ParseError(f"not parseable as JSON: {exc}") from None
    if not isinstance(data, dict):
        raise ParseError(f"JSON body must be an object, got {type(data).__name__}")
    return ParsedEvent(named=_flatten(data), format="json")


def parse_xml(body: str) -> ParsedEvent:
    """Parse XML, preserving repeated sibling elements.

    Repeated siblings are the normal shape of real XML logs, not an edge case.
    A Windows Security event carries every field it has as a repeated
    ``<Data Name="TargetUserName">`` element, so a parser that writes each
    sibling to the same path keeps only the last one and silently discards the
    username, the address and everything else.

    Three addressing forms are exposed for a repeated element:

    ``EventData.Data.TargetUserName``
        keyed by its ``Name`` attribute -- the idiomatic way to read Windows
        events, and the only one that is stable when fields are reordered;
    ``EventData.Data.0``
        by position, for repeated elements that carry no identifying attribute;
    ``EventData.Data``
        the first occurrence, so a document with one child still reads simply.
    """
    import xml.etree.ElementTree as ET

    try:
        root = ET.fromstring(body)
    except ET.ParseError as exc:
        raise ParseError(f"not parseable as XML: {exc}") from None

    named: dict[str, Any] = {}

    def put(path: str, value: Any) -> None:
        # First writer wins, so `EventData.Data` stays the first occurrence
        # rather than being overwritten by the last.
        if path not in named:
            named[path] = value

    def walk(node, prefix: str) -> None:
        for key, value in node.attrib.items():
            put(f"{prefix}.@{key}" if prefix else f"@{key}", value)
        text = (node.text or "").strip()
        if text and prefix:
            put(prefix, text)

        # Group children by tag so repeats can be indexed rather than collide.
        buckets: dict[str, list[Any]] = {}
        for child in node:
            tag = child.tag.rsplit("}", 1)[-1]  # drop any namespace
            buckets.setdefault(tag, []).append(child)

        for tag, children in buckets.items():
            base = f"{prefix}.{tag}" if prefix else tag
            for index, child in enumerate(children):
                if len(children) > 1:
                    walk(child, f"{base}.{index}")
                    # A sibling identified by a Name attribute is addressable
                    # by that name, which is how these documents are meant to
                    # be read and survives the fields being reordered.
                    label = child.attrib.get("Name") or child.attrib.get("name")
                    if label:
                        inner = (child.text or "").strip()
                        if inner:
                            put(f"{base}.{label}", inner)
                walk(child, base)

    walk(root, "")
    return ParsedEvent(named=named, format="xml")


# --- key-value and vendor specs -----------------------------------------

_KV_RE = re.compile(r'([A-Za-z_][\w.\-]*)=("([^"]*)"|\S*)')


def _parse_kv_pairs(text: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, quoted, inner in _KV_RE.findall(text):
        out[key] = inner if quoted.startswith('"') else quoted
    return out


def parse_kv(body: str) -> ParsedEvent:
    named = _parse_kv_pairs(body)
    if not named:
        raise ParseError("no key=value pairs found")
    return ParsedEvent(named=named, format="key_value")


def _split_escaped(text: str, delimiter: str) -> list[str]:
    """Split on an unescaped delimiter, honouring backslash escapes."""
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for ch in text:
        if escaped:
            current.append(ch)
            escaped = False
        elif ch == "\\":
            escaped = True
        elif ch == delimiter:
            parts.append("".join(current))
            current = []
        else:
            current.append(ch)
    parts.append("".join(current))
    return parts


def parse_cef(body: str) -> ParsedEvent:
    """ArcSight CEF.

    ``CEF:0|Vendor|Product|Version|SignatureID|Name|Severity|extensions``

    The seven header fields are positional 1-7; extensions are named.
    """
    start = body.find("CEF:")
    if start < 0:
        raise ParseError("no CEF: marker found")
    segments = _split_escaped(body[start:], "|")
    if len(segments) < 8:
        raise ParseError(f"CEF needs 8 segments, found {len(segments)}")

    header = [segments[0].split("CEF:", 1)[1]] + segments[1:7]
    extensions = _parse_kv_pairs("|".join(segments[7:]))
    return ParsedEvent(positional=header, named=extensions, format="cef")


def parse_leef(body: str) -> ParsedEvent:
    """IBM QRadar LEEF 1.0 and 2.0.

    LEEF 2.0 may declare a custom attribute delimiter in a sixth header field;
    LEEF 1.0 always uses a tab.
    """
    start = body.find("LEEF:")
    if start < 0:
        raise ParseError("no LEEF: marker found")
    segments = _split_escaped(body[start:], "|")
    if len(segments) < 6:
        raise ParseError(f"LEEF needs at least 6 segments, found {len(segments)}")

    version = segments[0].split("LEEF:", 1)[1]
    header = [version] + segments[1:5]
    rest = segments[5:]

    delimiter = "\t"
    if version.startswith("2") and len(rest) > 1:
        candidate = rest[0]
        if candidate.startswith("x") or candidate.startswith("0x"):
            try:
                delimiter = chr(int(candidate.lstrip("x").lstrip("0x") or "9", 16))
            except ValueError:
                delimiter = "\t"
            rest = rest[1:]
        elif len(candidate) == 1:
            delimiter = candidate
            rest = rest[1:]

    attributes = "|".join(rest).replace(delimiter, " ")
    return ParsedEvent(
        positional=header, named=_parse_kv_pairs(attributes), format="leef"
    )


def parse_raw(body: str) -> ParsedEvent:
    """No structure at all: the body is the field.

    For sources whose every value lives inside prose -- Cisco ASA, OpenSSH,
    MikroTik -- where splitting buys nothing and each field is reached by its
    own regex instead.
    """
    if not body.strip():
        raise ParseError("empty body")
    return ParsedEvent(positional=[body], named={}, format="raw")


PARSERS = {
    "raw": parse_raw,
    "csv": parse_csv,
    "ssv": parse_ssv,
    "tsv": parse_tsv,
    "json": parse_json,
    "xml": parse_xml,
    "kv": parse_kv,
    "key_value": parse_kv,
    "cef": parse_cef,
    "leef": parse_leef,
}


def parse_body(body: str, fmt: str) -> ParsedEvent:
    """Parse ``body`` as ``fmt``."""
    parser = PARSERS.get(fmt.lower())
    if parser is None:
        raise ParseError(
            f"no parser for format {fmt!r}; known: {', '.join(sorted(PARSERS))}"
        )
    parsed = parser(body)
    parsed.raw_body = body
    return parsed
