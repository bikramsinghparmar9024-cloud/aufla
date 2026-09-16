"""Validation of a normalised record against its OCSF class.

Three layers, in increasing order of cleverness and decreasing order of
certainty:

1. **Structural** -- does the field exist in the class at all?
2. **Type and range** -- is ``dst_endpoint.port`` an integer in 1-65535?
3. **Semantic** -- does the record make *sense*?

Layer 3 is the reason this module exists. Grammar-constrained decoding
guarantees a model emits a real OCSF field name, and layer 2 guarantees the
value fits the declared type. Neither notices a mapping that put the source
address into ``dst_endpoint.ip``. Layer 3 raises warnings for records whose
shape is suspicious, and those warnings feed the mapping confidence gate.

Warnings never reject a record. Real traffic is strange, and a pipeline that
drops odd events is worse than useless in an incident. They downgrade trust in
the *mapping*, which is the thing that might actually be wrong.
"""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any

from .classes import UNMAPPED_FIELD, OCSFClass, get_class
from .types import FieldType, coerce

__all__ = ["ValidationReport", "validate_record", "WELL_KNOWN_MAX", "EPHEMERAL_MIN"]

# IANA port ranges. A server almost always listens on a well-known or
# registered port while a client picks an ephemeral one, so seeing that
# relationship inverted is the clearest cheap signal of a swapped mapping.
WELL_KNOWN_MAX = 1023
EPHEMERAL_MIN = 49152


@dataclass(slots=True)
class ValidationReport:
    """Result of validating one record."""

    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    coerced: dict[str, Any] = field(default_factory=dict)
    unmapped: dict[str, Any] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        """True when nothing structurally or type-wise invalid was found."""
        return not self.errors

    @property
    def coverage(self) -> float:
        """Share of supplied fields that found a home in the OCSF class.

        This is ``mapping_coverage``: the honest metric that keeps the
        normalised view from being quietly lossy.
        """
        total = len(self.coerced) + len(self.unmapped)
        return 1.0 if total == 0 else len(self.coerced) / total

    def __str__(self) -> str:  # pragma: no cover - debugging aid
        bits = [f"{'ok' if self.ok else 'INVALID'} coverage={self.coverage:.0%}"]
        bits += [f"error: {e}" for e in self.errors]
        bits += [f"warning: {w}" for w in self.warnings]
        return "\n".join(bits)


def _is_globally_routable(ip_text: str) -> bool:
    """True when an address is reachable from the public internet.

    ``is_global`` rather than ``not is_private``: Python treats the TEST-NET
    documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and
    other IANA special-purpose blocks as private, so ``is_private`` conflates
    "internal network" with "reserved". Only ``is_global`` answers the question
    this heuristic actually asks -- did this traffic cross a real boundary?
    """
    try:
        return ipaddress.ip_address(ip_text).is_global
    except ValueError:  # pragma: no cover - values are already coerced
        return False


def _check_semantics(values: dict[str, Any], report: ValidationReport) -> None:
    """Layer 3. Flag records whose shape suggests the mapping is wrong."""
    src_ip = values.get("src_endpoint.ip")
    dst_ip = values.get("dst_endpoint.ip")
    src_port = values.get("src_endpoint.port")
    dst_port = values.get("dst_endpoint.port")

    if src_ip and dst_ip and src_ip == dst_ip:
        report.warnings.append(
            f"src_endpoint.ip and dst_endpoint.ip are both {src_ip}; "
            "the mapping may read the same column twice"
        )

    if src_port is not None and dst_port is not None:
        if src_port <= WELL_KNOWN_MAX and dst_port >= EPHEMERAL_MIN:
            report.warnings.append(
                f"src port {src_port} is well-known and dst port {dst_port} is "
                "ephemeral; endpoints may be swapped"
            )

    # Perimeter traffic normally crosses a boundary: one internal side, one
    # external. Two globally routable endpoints usually means the internal
    # address was dropped or the wrong column was read. Two internal endpoints
    # are perfectly normal on a segmentation firewall, so that is not flagged.
    if (
        src_ip
        and dst_ip
        and _is_globally_routable(src_ip)
        and _is_globally_routable(dst_ip)
    ):
        report.warnings.append(
            f"both endpoints ({src_ip}, {dst_ip}) are globally routable; a "
            "perimeter device normally has one internal side"
        )

    total = values.get("traffic.bytes")
    parts = [values.get("traffic.bytes_in"), values.get("traffic.bytes_out")]
    if total is not None and all(p is not None for p in parts):
        summed = sum(parts)  # type: ignore[arg-type]
        if summed > total:
            report.warnings.append(
                f"traffic.bytes_in + traffic.bytes_out ({summed}) exceeds "
                f"traffic.bytes ({total})"
            )

    claimed = values.get("time")
    observed = values.get("observed_time")
    if claimed is not None and observed is not None:
        drift_ms = claimed - observed
        if abs(drift_ms) > 3_600_000:
            hours = drift_ms / 3_600_000
            report.warnings.append(
                f"device clock differs from receipt clock by {hours:+.1f}h; "
                "treat event_time as untrusted"
            )


def validate_record(
    class_uid: int,
    record: dict[str, Any],
    *,
    strict_unknown: bool = False,
) -> ValidationReport:
    """Validate ``record`` against the OCSF class identified by ``class_uid``.

    Parameters
    ----------
    class_uid:
        OCSF class, for example 4001 for Network Activity.
    record:
        Flat mapping of dotted OCSF field name to raw value.
    strict_unknown:
        When True an unrecognised field is an error. Used when checking a
        *mapping* (where an unknown target means the mapping is wrong). Left
        False when normalising events, so that vendor extras route to
        ``unmapped`` instead of failing the event.
    """
    ocsf_class: OCSFClass = get_class(class_uid)
    report = ValidationReport()

    for name, value in record.items():
        if name == UNMAPPED_FIELD:
            if isinstance(value, dict):
                report.unmapped.update(value)
            else:
                report.errors.append(f"{UNMAPPED_FIELD} must be an object")
            continue

        definition = ocsf_class.get(name)
        if definition is None:
            if strict_unknown:
                report.errors.append(
                    f"{name!r} is not a field of {ocsf_class.name} ({class_uid})"
                )
            else:
                report.unmapped[name] = value
            continue

        result = coerce(value, definition.type)
        if result.ok:
            report.coerced[name] = result.value
        else:
            report.errors.append(f"{name}: {result.error}")

    for required in ocsf_class.required_fields:
        if required not in report.coerced:
            report.errors.append(f"{required}: required field is missing or invalid")

    _check_semantics(report.coerced, report)
    return report


def validate_mapping_targets(class_uid: int, field_names: list[str]) -> list[str]:
    """Return the field names that are not valid targets in ``class_uid``.

    Used by the mapping loader, where an unknown target is a configuration
    error rather than a vendor extra.
    """
    ocsf_class = get_class(class_uid)
    return [n for n in field_names if n != UNMAPPED_FIELD and not ocsf_class.has(n)]
