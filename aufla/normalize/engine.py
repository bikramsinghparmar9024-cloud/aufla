"""The normaliser: raw event plus mapping produces the OCSF projection.

Every record this produces carries the lineage needed to answer three
questions without re-running anything:

* which raw event did this come from?      ``event_uid``, ``raw_hash``
* which rule produced it?                  ``mapping_id``, ``mapping_version``,
                                           ``mapping_hash``, ``rule_name``
* how complete is it?                      ``parse_status``, ``mapping_coverage``

Because the projection is derived and raw is canonical, a record can always be
thrown away and rebuilt. Correcting a mapping is therefore a re-derivation,
never a patch.
"""

from __future__ import annotations

import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from ..mapping.router import detect_format, strip_syslog_header
from ..mapping.schema import Condition, ConditionOp, FieldSpec, Mapping, RefKind, Rule
from ..models import ParseStatus, RawEvent
from ..ocsf.validate import validate_record
from .parsers import ParseError, ParsedEvent, parse_body
from .transforms import TransformError, apply_lookup, apply_transform

__all__ = ["NormalizedRecord", "Normalizer"]


@dataclass(slots=True)
class NormalizedRecord:
    """One OCSF record, plus the lineage that ties it to its origin."""

    event_uid: uuid.UUID
    raw_hash: str
    source_id: str
    parse_status: ParseStatus
    observed_time: int
    ocsf_class: int | None = None
    mapping_id: str | None = None
    mapping_version: int | None = None
    mapping_hash: str | None = None
    rule_name: str | None = None
    fields: dict[str, Any] = field(default_factory=dict)
    unmapped: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    mapping_coverage: float = 0.0

    @property
    def is_quarantined(self) -> bool:
        return self.parse_status is ParseStatus.QUARANTINED

    @property
    def event_time(self) -> int | None:
        """Device-claimed time. Untrusted; compare against observed_time."""
        return self.fields.get("time")

    def to_dict(self) -> dict[str, Any]:
        """Flat representation for storage and for export adapters."""
        out: dict[str, Any] = {
            "event_uid": str(self.event_uid),
            "raw_hash": self.raw_hash,
            "source_id": self.source_id,
            "parse_status": self.parse_status.value,
            "observed_time": self.observed_time,
            "class_uid": self.ocsf_class,
            "mapping_id": self.mapping_id,
            "mapping_version": self.mapping_version,
            "mapping_hash": self.mapping_hash,
            "rule_name": self.rule_name,
            "mapping_coverage": round(self.mapping_coverage, 4),
        }
        out.update(self.fields)
        if self.unmapped:
            out["unmapped"] = dict(self.unmapped)
        return out


class Normalizer:
    """Applies mappings to raw events."""

    def __init__(self, registry) -> None:
        self.registry = registry

    # ---- entry point ------------------------------------------------------

    def normalize(self, event: RawEvent) -> NormalizedRecord:
        """Normalise one event. Never raises: a failure quarantines instead.

        Quarantine is a routing decision, not data loss. The event is already
        safely in the raw store; only its projection is deferred until a
        mapping exists.
        """
        record = NormalizedRecord(
            event_uid=event.event_uid,
            raw_hash=event.raw_hash,
            source_id=event.source_id,
            parse_status=ParseStatus.QUARANTINED,
            observed_time=event.received_at_ns // 1_000_000,
        )

        mapping: Mapping | None = self.registry.get(event.source_id)
        if mapping is None:
            detection = detect_format(event.raw_bytes)
            record.warnings.append(
                f"no mapping for source {event.source_id!r}; detected "
                f"{detection.format.value}, strategy {detection.strategy.value}"
            )
            return record

        body, _pri, _tag = strip_syslog_header(event.text())

        try:
            parsed = parse_body(body, mapping.format)
        except ParseError as exc:
            record.mapping_id = mapping.source
            record.mapping_version = mapping.version
            record.warnings.append(f"parse failed: {exc}")
            return record

        rule = self._select_rule(mapping, parsed)
        if rule is None:
            record.mapping_id = mapping.source
            record.mapping_version = mapping.version
            record.warnings.append(
                f"no rule in {mapping.source} matched this event"
            )
            return record

        return self._apply(event, mapping, rule, parsed, record)

    # ---- rule selection ---------------------------------------------------

    def _select_rule(self, mapping: Mapping, parsed: ParsedEvent) -> Rule | None:
        for rule in mapping.rules:
            if rule.match is None or self._matches(rule.match, parsed):
                return rule
        return None

    def _matches(self, condition: Condition, parsed: ParsedEvent) -> bool:
        value = self._resolve_ref(condition.ref, parsed)

        if condition.op is ConditionOp.EXISTS:
            return bool(condition.value) == (value is not None)
        if value is None:
            return False

        text = str(value)
        expected = condition.value

        if condition.op is ConditionOp.EQUALS:
            return text == str(expected)
        if condition.op is ConditionOp.NOT_EQUALS:
            return text != str(expected)
        if condition.op is ConditionOp.CONTAINS:
            return str(expected) in text
        if condition.op is ConditionOp.STARTSWITH:
            return text.startswith(str(expected))
        if condition.op is ConditionOp.IN:
            return text in {str(v) for v in expected}
        if condition.op is ConditionOp.REGEX:
            return re.search(str(expected), text) is not None
        return False  # pragma: no cover - ConditionOp is exhaustive above

    # ---- field resolution -------------------------------------------------

    @staticmethod
    def _resolve_ref(ref, parsed: ParsedEvent) -> Any:
        if ref.kind is RefKind.POSITIONAL:
            return parsed.get_positional(int(ref.value))
        if ref.kind is RefKind.NAMED:
            return parsed.get_named(str(ref.value))
        return ref.value

    def _resolve_spec(
        self, target: str, spec: FieldSpec, parsed: ParsedEvent, record
    ) -> Any:
        value = self._resolve_ref(spec.ref, parsed)

        if value is None:
            return spec.default

        if spec.transform:
            try:
                value = apply_transform(spec.transform, value)
            except TransformError as exc:
                record.warnings.append(f"{target}: {exc}")
                return spec.default

        if spec.lookup:
            try:
                value = apply_lookup(spec.lookup, value, spec.default)
            except TransformError as exc:
                record.warnings.append(f"{target}: {exc}")
                return spec.default

        return spec.default if value is None else value

    # ---- application ------------------------------------------------------

    def _apply(
        self,
        event: RawEvent,
        mapping: Mapping,
        rule: Rule,
        parsed: ParsedEvent,
        record: NormalizedRecord,
    ) -> NormalizedRecord:
        record.mapping_id = mapping.source
        record.mapping_version = mapping.version
        record.mapping_hash = mapping.content_hash()
        record.rule_name = rule.name
        record.ocsf_class = rule.ocsf_class

        candidate: dict[str, Any] = {}
        for target, spec in rule.fields.items():
            value = self._resolve_spec(target, spec, parsed, record)
            if value is not None:
                candidate[target] = value

        # Our receipt clock is always recorded, and is the one a certificate
        # cites. The device's claim goes to `time`.
        candidate["observed_time"] = record.observed_time

        if "time" not in candidate:
            # A device that gave us no parseable time does not get to make the
            # event undatable. Falling back to the receipt clock is honest
            # provided we say so, which the warning does.
            candidate["time"] = record.observed_time
            record.warnings.append(
                "device time not mapped; 'time' falls back to the receipt clock"
            )

        report = validate_record(rule.ocsf_class, candidate)

        record.fields = report.coerced
        record.unmapped = report.unmapped
        record.warnings.extend(report.warnings)
        record.errors.extend(report.errors)
        record.mapping_coverage = report.coverage

        if report.errors:
            # Some fields were produced but not all. The event keeps whatever
            # normalised cleanly rather than being discarded wholesale.
            record.parse_status = (
                ParseStatus.PARTIAL if report.coerced else ParseStatus.QUARANTINED
            )
        else:
            record.parse_status = ParseStatus.FULL

        return record

    # ---- bulk -------------------------------------------------------------

    def normalize_many(self, events) -> list[NormalizedRecord]:
        return [self.normalize(e) for e in events]
