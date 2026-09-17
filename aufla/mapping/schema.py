"""The mapping artifact.

A mapping is a YAML file describing how one source's events become OCSF. It is
the *only* thing that performs normalisation, and it is the only thing the
discovery lane produces.

That matters more than it looks. The model never writes to the event store; it
writes one of these. A file can be read, diffed, version-controlled and signed
off on by a named person. A model's internal state cannot. Automation here
accelerates authorship without displacing accountability.

Field references
----------------
``$7``
    Positional field 7 (1-indexed), for CSV and CEF-style ordered formats.
``$src_ip`` / ``$alert.signature``
    Named lookup, dotted for nesting, for JSON and key-value formats.
``$$literal``
    An escaped literal beginning with a dollar sign.
anything else
    A literal constant.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..ocsf.classes import get_class
from ..ocsf.validate import validate_mapping_targets

__all__ = [
    "MappingError",
    "RefKind",
    "FieldRef",
    "FieldSpec",
    "ConditionOp",
    "Condition",
    "Rule",
    "Mapping",
]


class MappingError(ValueError):
    """Raised when a mapping file is structurally invalid.

    Loud by design: a bad mapping is a configuration bug, and failing at load
    is far better than silently normalising events into the wrong shape.
    """


class RefKind(str, Enum):
    POSITIONAL = "positional"
    NAMED = "named"
    LITERAL = "literal"


_POSITIONAL_RE = re.compile(r"^\$(\d+)$")
# `@` is permitted so a mapping can address an XML attribute, which the XML
# parser exposes as `Parent.@Attr` (e.g. $System.Provider.@Name).
_NAMED_RE = re.compile(r"^\$([A-Za-z_][A-Za-z0-9_.\-@]*)$")


@dataclass(frozen=True, slots=True)
class FieldRef:
    """Where a value comes from in the parsed source event."""

    kind: RefKind
    value: str | int

    @classmethod
    def parse(cls, raw: Any) -> "FieldRef":
        if not isinstance(raw, str):
            # Numbers and booleans in YAML are literal constants.
            return cls(RefKind.LITERAL, raw)

        if raw.startswith("$$"):
            return cls(RefKind.LITERAL, raw[1:])

        m = _POSITIONAL_RE.match(raw)
        if m:
            index = int(m.group(1))
            if index < 1:
                raise MappingError(
                    f"positional reference {raw!r} is invalid; fields are 1-indexed"
                )
            return cls(RefKind.POSITIONAL, index)

        m = _NAMED_RE.match(raw)
        if m:
            return cls(RefKind.NAMED, m.group(1))

        if raw.startswith("$"):
            raise MappingError(
                f"malformed field reference {raw!r}; use $7, $name, or $$literal"
            )

        return cls(RefKind.LITERAL, raw)

    def render(self) -> str:
        if self.kind is RefKind.POSITIONAL:
            return f"${self.value}"
        if self.kind is RefKind.NAMED:
            return f"${self.value}"
        return str(self.value)


@dataclass(frozen=True, slots=True)
class FieldSpec:
    """How one OCSF field is produced."""

    ref: FieldRef
    transform: str | None = None
    lookup: str | None = None
    default: Any = None
    timezone: str | None = None

    @classmethod
    def parse(cls, raw: Any) -> "FieldSpec":
        if isinstance(raw, dict):
            if "from" not in raw:
                raise MappingError(f"field spec {raw!r} is missing 'from'")
            unknown = set(raw) - {"from", "transform", "lookup", "default", "tz"}
            if unknown:
                raise MappingError(
                    f"field spec has unknown keys: {sorted(unknown)}"
                )
            return cls(
                ref=FieldRef.parse(raw["from"]),
                transform=raw.get("transform"),
                lookup=raw.get("lookup"),
                default=raw.get("default"),
                timezone=raw.get("tz"),
            )
        return cls(ref=FieldRef.parse(raw))


class ConditionOp(str, Enum):
    EQUALS = "equals"
    NOT_EQUALS = "not_equals"
    CONTAINS = "contains"
    STARTSWITH = "startswith"
    REGEX = "regex"
    EXISTS = "exists"
    IN = "in"


@dataclass(frozen=True, slots=True)
class Condition:
    """Discriminator selecting which rule applies to an event.

    One device emits many event shapes -- a firewall sends TRAFFIC, THREAT,
    SYSTEM and CONFIG, each a different OCSF class. Conditions are how a single
    mapping file covers all of them.
    """

    ref: FieldRef
    op: ConditionOp
    value: Any = None

    @classmethod
    def parse(cls, raw: Any) -> "Condition":
        if not isinstance(raw, dict):
            raise MappingError(f"match must be an object, got {type(raw).__name__}")
        if "field" not in raw:
            raise MappingError(f"match {raw!r} is missing 'field'")

        ops = [o for o in ConditionOp if o.value in raw]
        if len(ops) > 1:
            raise MappingError(
                f"match names more than one operator: {[o.value for o in ops]}"
            )
        if not ops:
            raise MappingError(
                f"match {raw!r} names no operator; expected one of "
                f"{[o.value for o in ConditionOp]}"
            )

        op = ops[0]
        value = raw[op.value]

        if op is ConditionOp.IN and not isinstance(value, list):
            raise MappingError("'in' requires a list of values")
        if op is ConditionOp.REGEX:
            try:
                re.compile(value)
            except (re.error, TypeError) as exc:
                raise MappingError(f"invalid regex {value!r}: {exc}") from None

        return cls(ref=FieldRef.parse(raw["field"]), op=op, value=value)


@dataclass(frozen=True, slots=True)
class Rule:
    """One event shape within a source."""

    name: str
    ocsf_class: int
    fields: dict[str, FieldSpec]
    match: Condition | None = None

    @classmethod
    def parse(cls, raw: Any, *, source: str) -> "Rule":
        if not isinstance(raw, dict):
            raise MappingError(f"{source}: each rule must be an object")

        name = raw.get("name")
        if not name or not isinstance(name, str):
            raise MappingError(f"{source}: rule is missing a string 'name'")

        if "ocsf_class" not in raw:
            raise MappingError(f"{source}/{name}: rule is missing 'ocsf_class'")
        class_uid = raw["ocsf_class"]
        if not isinstance(class_uid, int) or isinstance(class_uid, bool):
            raise MappingError(
                f"{source}/{name}: ocsf_class must be an integer uid"
            )
        try:
            get_class(class_uid)
        except KeyError as exc:
            raise MappingError(f"{source}/{name}: {exc.args[0]}") from None

        raw_fields = raw.get("fields")
        if not isinstance(raw_fields, dict) or not raw_fields:
            raise MappingError(f"{source}/{name}: 'fields' must be a non-empty object")

        # An unknown OCSF target is a configuration bug, not a vendor extra.
        # Catching it here is what makes "the AI cannot invent fields" true
        # even when a human wrote the file.
        bad = validate_mapping_targets(class_uid, list(raw_fields))
        if bad:
            raise MappingError(
                f"{source}/{name}: not fields of OCSF class {class_uid}: "
                f"{', '.join(sorted(bad))}"
            )

        fields = {}
        for target, spec in raw_fields.items():
            try:
                fields[target] = FieldSpec.parse(spec)
            except MappingError as exc:
                raise MappingError(f"{source}/{name}/{target}: {exc}") from None

        match = Condition.parse(raw["match"]) if raw.get("match") is not None else None
        return cls(name=name, ocsf_class=class_uid, fields=fields, match=match)


@dataclass(frozen=True, slots=True)
class Mapping:
    """A complete source definition."""

    source: str
    format: str
    rules: tuple[Rule, ...]
    ocsf_version: str = "1.5.0"
    version: int = 1
    description: str = ""
    author: str = "human"
    approved_by: str | None = None
    approved_at: str | None = None
    confidence: float | None = None
    path: str | None = None
    raw: dict[str, Any] = field(default_factory=dict, repr=False, compare=False)

    # ---- parsing ----------------------------------------------------------

    @classmethod
    def from_dict(cls, data: Any, *, path: str | None = None) -> "Mapping":
        if not isinstance(data, dict):
            raise MappingError(
                f"{path or 'mapping'}: top level must be an object, "
                f"got {type(data).__name__}"
            )

        source = data.get("source")
        if not source or not isinstance(source, str):
            raise MappingError(f"{path or 'mapping'}: missing a string 'source'")

        fmt = data.get("format")
        if not fmt or not isinstance(fmt, str):
            raise MappingError(f"{source}: missing a string 'format'")

        raw_rules = data.get("rules")
        if not isinstance(raw_rules, list) or not raw_rules:
            raise MappingError(f"{source}: 'rules' must be a non-empty list")

        rules = tuple(Rule.parse(r, source=source) for r in raw_rules)

        names = [r.name for r in rules]
        duplicates = {n for n in names if names.count(n) > 1}
        if duplicates:
            raise MappingError(
                f"{source}: duplicate rule names: {', '.join(sorted(duplicates))}"
            )

        # A catch-all rule (no match) placed before others would shadow them.
        for rule in rules[:-1]:
            if rule.match is None:
                raise MappingError(
                    f"{source}: rule {rule.name!r} has no 'match' but is not last; "
                    "it would shadow every rule after it"
                )

        version = data.get("version", 1)
        if not isinstance(version, int) or isinstance(version, bool) or version < 1:
            raise MappingError(f"{source}: 'version' must be a positive integer")

        confidence = data.get("confidence")
        if confidence is not None:
            if not isinstance(confidence, (int, float)) or isinstance(confidence, bool):
                raise MappingError(f"{source}: 'confidence' must be a number")
            if not 0.0 <= float(confidence) <= 1.0:
                raise MappingError(f"{source}: 'confidence' must be within 0.0-1.0")
            confidence = float(confidence)

        return cls(
            source=source,
            format=fmt.lower(),
            rules=rules,
            ocsf_version=str(data.get("ocsf_version", "1.5.0")),
            version=version,
            description=str(data.get("description", "")),
            author=str(data.get("author", "human")),
            approved_by=data.get("approved_by"),
            approved_at=data.get("approved_at"),
            confidence=confidence,
            path=path,
            raw=data,
        )

    @classmethod
    def from_yaml(cls, text: str, *, path: str | None = None) -> "Mapping":
        import yaml

        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            raise MappingError(f"{path or 'mapping'}: invalid YAML: {exc}") from None
        return cls.from_dict(data, path=path)

    # ---- identity ---------------------------------------------------------

    def content_hash(self) -> str:
        """SHA-256 over the mapping's semantic content.

        Committed to the integrity ledger so that, for any normalised row, you
        can prove *which* mapping version produced it. Comments, key order and
        formatting are excluded, so a cosmetic edit does not read as a change.
        """
        payload = {
            "source": self.source,
            "format": self.format,
            "ocsf_version": self.ocsf_version,
            "version": self.version,
            "rules": [
                {
                    "name": r.name,
                    "ocsf_class": r.ocsf_class,
                    "match": None
                    if r.match is None
                    else {
                        "field": r.match.ref.render(),
                        "op": r.match.op.value,
                        "value": r.match.value,
                    },
                    "fields": {
                        target: {
                            "from": spec.ref.render(),
                            "transform": spec.transform,
                            "lookup": spec.lookup,
                            "default": spec.default,
                            "tz": spec.timezone,
                        }
                        for target, spec in sorted(r.fields.items())
                    },
                }
                for r in self.rules
            ],
        }
        canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    @property
    def is_approved(self) -> bool:
        """A mapping takes effect only once a named person has signed off."""
        return bool(self.approved_by)

    @property
    def ocsf_classes(self) -> tuple[int, ...]:
        return tuple(dict.fromkeys(r.ocsf_class for r in self.rules))

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        return f"{self.source} v{self.version} ({self.format}, {len(self.rules)} rules)"
