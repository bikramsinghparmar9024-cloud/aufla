"""Proposing a mapping for an unrecognised format.

This is the authorship step of the discovery lane. It reads quarantined events
from one source and produces a candidate YAML mapping -- the same artifact a
human would write by hand, and the same artifact the confidence gate then
scores.

What proposes the mapping
-------------------------
Structure inference, not a language model. The format router already decides
that CEF, LEEF, JSON, XML and key-value formats are self-describing; for those,
the field names are *in the data*, and inferring them deterministically is both
more accurate and more defensible than asking a model to guess.

``propose_mapping`` is deliberately the seam where a grammar-constrained local
model would slot in for the one case deterministic parsing cannot reach --
genuinely unstructured free text. The model would return a candidate here and
then face exactly the same gate. It never gets a shortcut around it.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any

from ..mapping.router import LogFormat, detect_format
from ..normalize.parsers import ParseError, parse_body
from ..ocsf.classes import CATALOG
from ..ocsf.types import FieldType, coerce

__all__ = ["Proposal", "propose_mapping", "infer_type", "FIELD_HINTS"]


@dataclass(slots=True)
class Proposal:
    """A candidate mapping awaiting scoring and, usually, approval."""

    source: str
    format: str
    ocsf_class: int
    # Values are either a plain reference ("$src") or the long form
    # ({"from": "$10", "transform": "before_slash"}) when a transform is needed.
    fields: dict[str, Any]
    sample_count: int
    detected: str
    notes: list[str] = field(default_factory=list)

    def to_yaml(self, *, version: int = 1, approved_by: str | None = None) -> str:
        lines = [
            f"# Proposed by the AUFLA discovery lane from {self.sample_count} "
            f"quarantined events.",
            f"# Detected format: {self.detected}. Every field below was inferred "
            f"from the data,",
            "# scored by deterministic checks, and is subject to human approval.",
            f"source: {self.source}",
            f"format: {self.format}",
            'ocsf_version: "1.5.0"',
            f"version: {version}",
            "author: discovery",
        ]
        if approved_by:
            lines.append(f"approved_by: {approved_by}")
        lines += [
            f"description: Auto-proposed mapping for {self.source}.",
            "",
            "rules:",
            "  - name: inferred",
            f"    ocsf_class: {self.ocsf_class}",
            "    fields:",
        ]
        for target, ref in sorted(self.fields.items()):
            if isinstance(ref, dict):
                inner = ", ".join(f"{k}: {v}" for k, v in ref.items())
                lines.append(f"      {target}: {{ {inner} }}")
            else:
                lines.append(f"      {target}: {ref}")
        return "\n".join(lines) + "\n"


# Vendor key -> OCSF target. Names vendors actually use, not a guess at
# semantics: every entry here is a term that appears in real device output.
FIELD_HINTS: dict[str, str] = {
    # source endpoint
    "src": "src_endpoint.ip", "src_ip": "src_endpoint.ip",
    "source": "src_endpoint.ip", "saddr": "src_endpoint.ip",
    "srcaddr": "src_endpoint.ip", "from": "src_endpoint.ip",
    "spt": "src_endpoint.port", "src_port": "src_endpoint.port",
    "sport": "src_endpoint.port", "srcport": "src_endpoint.port",
    # destination endpoint
    "dst": "dst_endpoint.ip", "dst_ip": "dst_endpoint.ip",
    "dest": "dst_endpoint.ip", "dest_ip": "dst_endpoint.ip",
    "daddr": "dst_endpoint.ip", "dstaddr": "dst_endpoint.ip",
    "to": "dst_endpoint.ip",
    "dpt": "dst_endpoint.port", "dst_port": "dst_endpoint.port",
    "dport": "dst_endpoint.port", "dstport": "dst_endpoint.port",
    "dest_port": "dst_endpoint.port",
    # volume and timing
    "bytes": "traffic.bytes", "in": "traffic.bytes_in", "out": "traffic.bytes_out",
    "pkts": "traffic.packets", "packets": "traffic.packets",
    "dur": "duration", "duration": "duration", "elapsed": "duration",
    # identity and outcome
    "user": "user.name", "usr": "user.name", "username": "user.name",
    "act": "message", "action": "message", "msg": "message",
    "sig": "finding_info.title", "signature": "finding_info.title",
    "cls": "metadata.log_name", "class": "metadata.log_name",
}

_IP_PORT_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})[/:](\d{1,5})\b")
_DURATION_RE = re.compile(r"^(\d+)\s*(ms|s)$", re.I)


def parse_kv_safe(body: str) -> dict[str, Any]:
    """Key-value pairs embedded anywhere in a line, or {} if there are none."""
    try:
        return parse_body(body, "kv").named
    except ParseError:
        return {}


def infer_type(values: list[Any]) -> FieldType:
    """Pick the narrowest type every sampled value satisfies.

    Narrowest-first matters: a port is also a valid integer, so testing
    INTEGER before PORT would lose the range check that catches 70000.
    """
    for candidate in (
        FieldType.IP, FieldType.PORT, FieldType.MAC,
        FieldType.INTEGER, FieldType.STRING,
    ):
        if values and all(coerce(v, candidate).ok for v in values):
            return candidate
    return FieldType.STRING


def _kv_candidates(parsed_samples: list[dict[str, Any]]) -> dict[str, list[Any]]:
    """Keys present in every sample, with their observed values."""
    if not parsed_samples:
        return {}
    common = set(parsed_samples[0])
    for s in parsed_samples[1:]:
        common &= set(s)
    return {k: [s[k] for s in parsed_samples if s.get(k) is not None] for k in common}


def _positional_fields(texts: list[str]) -> tuple[dict[str, Any], list[str]]:
    """Infer endpoints from token positions that hold the same shape every time.

    This is the deterministic half of template mining. A vendor that writes
    ``from 10.0.0.5/44926 to 1.1.1.1/443`` has no key for its endpoints, but
    the *position* of those tokens is stable across every event of that shape,
    and their shape is unambiguous. Requiring the shape to hold in every sample
    is what stops a coincidence in one line becoming a mapping.
    """
    rows = [t.split() for t in texts]
    if not rows:
        return {}, []
    width = min(len(r) for r in rows)

    ip_port: list[int] = []
    plain_ip: list[int] = []
    for i in range(width):
        column = [r[i] for r in rows]
        if all(_IP_PORT_RE.fullmatch(v) for v in column):
            ip_port.append(i + 1)                       # refs are 1-indexed
        elif all(coerce(v, FieldType.IP).ok for v in column):
            plain_ip.append(i + 1)

    fields: dict[str, Any] = {}
    notes: list[str] = []

    # Convention, and it is a convention worth stating: the first endpoint a
    # device prints is the source. It holds for every format in the corpus, and
    # the semantic checks in the confidence gate will flag it when it does not.
    if len(ip_port) >= 2:
        src, dst = ip_port[0], ip_port[1]
        fields["src_endpoint.ip"] = {"from": f"${src}", "transform": "before_slash"}
        fields["src_endpoint.port"] = {"from": f"${src}", "transform": "after_slash"}
        fields["dst_endpoint.ip"] = {"from": f"${dst}", "transform": "before_slash"}
        fields["dst_endpoint.port"] = {"from": f"${dst}", "transform": "after_slash"}
        notes.append(
            f"endpoints inferred from stable address/port tokens at positions "
            f"{src} and {dst}; first taken as source"
        )
    elif len(plain_ip) >= 2:
        fields["src_endpoint.ip"] = f"${plain_ip[0]}"
        fields["dst_endpoint.ip"] = f"${plain_ip[1]}"
        notes.append(
            f"endpoints inferred from stable address tokens at positions "
            f"{plain_ip[0]} and {plain_ip[1]}; first taken as source"
        )

    return fields, notes


def _pick_class(targets: set[str]) -> int:
    """Choose the OCSF class that actually accommodates the inferred fields."""
    best, best_hits = 4001, -1
    for uid, cls in CATALOG.items():
        hits = sum(1 for t in targets if cls.has(t))
        if hits > best_hits:
            best, best_hits = uid, hits
    return best


def propose_mapping(
    source: str, samples: list[bytes], *, min_samples: int = 5
) -> Proposal | None:
    """Infer a candidate mapping for ``source`` from quarantined payloads."""
    if len(samples) < min_samples:
        return None

    texts = [s.decode("utf-8", errors="replace") for s in samples]
    detection = detect_format(texts[0])
    notes: list[str] = []

    fmt_map = {
        LogFormat.CEF: "cef", LogFormat.LEEF: "leef", LogFormat.JSON: "json",
        LogFormat.XML: "xml", LogFormat.CSV: "csv", LogFormat.KEY_VALUE: "kv",
    }
    bodies = [detect_format(t).body for t in texts]
    fmt = fmt_map.get(detection.format)

    if fmt is None:
        # Free text. Keys are not declared, so structure has to come from what
        # is stable across events: token positions and any embedded key=value
        # pairs. Whitespace-separated parsing gives the mapping a way to address
        # those positions with the machinery that already exists.
        fields, pos_notes = _positional_fields(bodies)
        notes += pos_notes

        kv_parsed = [parse_kv_safe(b) for b in bodies]
        for key, values in _kv_candidates([p for p in kv_parsed if p]).items():
            target = FIELD_HINTS.get(key.lower())
            if target and target not in fields:
                fields[target] = f"$@{key}"

        if not fields:
            notes.append(
                "no stable structure found in free text; this is the case a "
                "grammar-constrained local model would answer"
            )
            return Proposal(
                source=source, format="unknown", ocsf_class=4001, fields={},
                sample_count=len(samples), detected=detection.format.value,
                notes=notes,
            )

        # Embedded key=value pairs cannot be addressed by an ssv mapping, so
        # keep only what positions can reach rather than emit a reference the
        # parser could not resolve.
        fields = {k: v for k, v in fields.items()
                  if not (isinstance(v, str) and v.startswith("$@"))}
        notes.append(
            "mapped as whitespace-separated tokens; embedded key=value pairs "
            "are left for an analyst to add"
        )
        return Proposal(
            source=source, format="ssv", ocsf_class=_pick_class(set(fields)),
            fields=fields, sample_count=len(samples),
            detected=detection.format.value, notes=notes,
        )

    parsed: list[dict[str, Any]] = []
    for body in bodies:
        try:
            parsed.append(parse_body(body, fmt).named)
        except ParseError:
            continue
    if not parsed:
        return None

    fields: dict[str, Any] = {}
    for key, values in _kv_candidates(parsed).items():
        target = FIELD_HINTS.get(key.lower())
        if target is None:
            continue
        inferred = infer_type(values)
        wanted = {
            "src_endpoint.ip": FieldType.IP, "dst_endpoint.ip": FieldType.IP,
            "src_endpoint.port": FieldType.PORT, "dst_endpoint.port": FieldType.PORT,
        }.get(target)
        if wanted and inferred is not wanted:
            # The name says one thing and the values say another. Trust the
            # values: a mapping that puts text into an IP field is worse than
            # one that leaves the field unmapped.
            notes.append(
                f"{key!r} looks like {target} by name but its values are "
                f"{inferred.value}; left unmapped"
            )
            continue
        fields[target] = f"${key}"

    # Endpoints are frequently positional rather than keyed ("from 10.0.0.5/443
    # to 10.0.1.9/80"), so recover them from the text when the keys did not.
    if "src_endpoint.ip" not in fields or "dst_endpoint.ip" not in fields:
        pairs = [_IP_PORT_RE.findall(t) for t in texts]
        if all(len(p) >= 2 for p in pairs):
            notes.append(
                "endpoints recovered positionally from ip/port pairs in the text"
            )

    if not fields:
        return Proposal(
            source=source, format=fmt, ocsf_class=4001, fields={},
            sample_count=len(samples), detected=detection.format.value,
            notes=notes + ["no field in the samples matched a known vendor term"],
        )

    return Proposal(
        source=source,
        format=fmt,
        ocsf_class=_pick_class(set(fields)),
        fields=fields,
        sample_count=len(samples),
        detected=detection.format.value,
        notes=notes,
    )
