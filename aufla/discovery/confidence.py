"""Scoring a proposed mapping.

A model reporting its own confidence as 0.95 is uncalibrated and means
nothing. Confidence here is computed from deterministic properties of the
proposal applied to real held-out events, so the number is reproducible by
anyone with the same samples -- including an examiner who does not trust the
system that produced it.

Five checks, all of which must pass for a mapping to take effect without a
human:

=========================  ================================================
check                      what it catches
=========================  ================================================
sample support             a one-off treated as a format
field coverage             a mapping that reaches almost none of the data
round-trip fill            a mapping that parses but does not populate
schema validity            output OCSF would reject
semantic sanity            swapped endpoints, impossible ports, clock faults
=========================  ================================================

The last one is the point. Grammar constraints bound which field *names* a
proposal may use; only applying it to real events and inspecting the result
catches a mapping that put the source address into ``dst_endpoint.ip``.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..mapping.schema import Mapping, MappingError
from ..models import ParseStatus, RawEvent, Transport
from ..normalize.engine import Normalizer
from .proposer import Proposal

__all__ = ["CONFIDENCE_BAR", "Check", "ConfidenceReport", "score_proposal"]

# Below this, a human decides. The bar is deliberately high: the cost of an
# analyst spending a minute on a review is far lower than the cost of silently
# normalising a device wrongly for a month.
CONFIDENCE_BAR = 0.95

MIN_SAMPLES = 20
MIN_FIELDS = 3


@dataclass(slots=True)
class Check:
    """One deterministic check and what it measured."""

    name: str
    passed: bool
    score: float
    detail: str

    def as_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "score": round(self.score, 4),
            "detail": self.detail,
        }


@dataclass(slots=True)
class ConfidenceReport:
    """The outcome of scoring one proposal."""

    confidence: float
    checks: list[Check] = field(default_factory=list)
    auto_approve: bool = False
    sample_results: list[dict[str, Any]] = field(default_factory=list)
    error: str = ""

    @property
    def failed(self) -> list[str]:
        return [c.name for c in self.checks if not c.passed]

    def as_dict(self) -> dict[str, Any]:
        return {
            "confidence": round(self.confidence, 4),
            "auto_approve": self.auto_approve,
            "bar": CONFIDENCE_BAR,
            "checks": [c.as_dict() for c in self.checks],
            "failed": self.failed,
            "samples": self.sample_results,
            "error": self.error,
        }


class _OneMapping:
    """Registry holding exactly the mapping under test."""

    def __init__(self, mapping: Mapping) -> None:
        self._mapping = mapping

    def get(self, source: str):
        return self._mapping if source == self._mapping.source else None


def score_proposal(
    proposal: Proposal, samples: list[bytes], *, holdout: int = 20
) -> ConfidenceReport:
    """Apply ``proposal`` to real events and score what came out.

    The events used for scoring are held out from the tail of the sample set,
    so the proposal is measured against data it was not inferred from.
    """
    report = ConfidenceReport(confidence=0.0)

    if not proposal.fields:
        report.checks.append(
            Check("proposal", False, 0.0, "no fields were inferred")
        )
        return report

    try:
        mapping = Mapping.from_yaml(proposal.to_yaml())
    except MappingError as exc:
        # An invalid mapping scores zero rather than raising: an unparseable
        # proposal is a failed candidate, not a broken pipeline.
        report.error = str(exc)
        report.checks.append(Check("schema validity", False, 0.0, str(exc)))
        return report

    normalizer = Normalizer(_OneMapping(mapping))
    tail = samples[-holdout:] if len(samples) > holdout else samples
    records = [
        normalizer.normalize(
            RawEvent.capture(payload, proposal.source, transport=Transport.FILE)
        )
        for payload in tail
    ]

    total = len(records)
    parsed = [r for r in records if r.parse_status is not ParseStatus.QUARANTINED]
    full = [r for r in records if r.parse_status is ParseStatus.FULL]

    # 1. sample support
    support = min(proposal.sample_count / MIN_SAMPLES, 1.0)
    report.checks.append(
        Check(
            "sample support", proposal.sample_count >= MIN_SAMPLES, support,
            f"{proposal.sample_count} events share this shape "
            f"(need {MIN_SAMPLES})",
        )
    )

    # 2. field coverage
    n_fields = len(proposal.fields)
    report.checks.append(
        Check(
            "field coverage", n_fields >= MIN_FIELDS,
            min(n_fields / MIN_FIELDS, 1.0),
            f"{n_fields} OCSF fields mapped (need {MIN_FIELDS})",
        )
    )

    # 3. round-trip fill
    fill = len(parsed) / total if total else 0.0
    report.checks.append(
        Check(
            "round-trip fill", fill >= 0.95, fill,
            f"{len(parsed)}/{total} held-out events normalised",
        )
    )

    # 4. schema validity
    errors = sum(len(r.errors) for r in records)
    valid = len(full) / total if total else 0.0
    report.checks.append(
        Check(
            "schema validity", errors == 0, valid,
            "all fields satisfied OCSF types" if errors == 0
            else f"{errors} type or range violations",
        )
    )

    # 5. semantic sanity
    #
    # Reads `warnings` only. A completeness note -- "this device gave us no
    # timestamp" -- says nothing about whether the mapping is correct, and
    # counting it here would fail almost every honest proposal.
    warned = sum(1 for r in records if r.warnings)
    clean = 1.0 - (warned / total if total else 0)
    sample_warnings = next((r.warnings for r in records if r.warnings), [])
    report.checks.append(
        Check(
            "semantic sanity", warned == 0, clean,
            "no suspicious field relationships" if warned == 0
            else f"{warned}/{total} events raised: {sample_warnings[0]}",
        )
    )

    # The weakest check is the confidence. Averaging would let four strong
    # checks hide one that says the endpoints are swapped.
    report.confidence = min(c.score for c in report.checks)
    report.auto_approve = (
        all(c.passed for c in report.checks) and report.confidence >= CONFIDENCE_BAR
    )

    report.sample_results = [
        {
            "raw": payload.decode("utf-8", errors="replace")[:220],
            "status": record.parse_status.value,
            "fields": record.fields,
            "warnings": record.warnings,
        }
        for payload, record in list(zip(tail, records))[:5]
    ]
    return report
