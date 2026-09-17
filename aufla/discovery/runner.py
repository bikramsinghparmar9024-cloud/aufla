"""Running the discovery lane over the quarantine.

One pass: find sources with quarantined events, propose a mapping for each,
score it, and then take exactly one of two routes.

* **Every check passes and confidence >= the bar.** The mapping is written and
  takes effect, and the quarantined events are backfilled.
* **Anything less.** It goes to the review queue and nothing changes until a
  named person approves it.

There is no third route. A proposal cannot partially apply, and no confidence
short of the bar buys a shortcut -- which is what makes "the model proposes,
the human approves" a property of the code rather than a claim on a slide.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from ..mapping.schema import Mapping, MappingError
from .confidence import CONFIDENCE_BAR, score_proposal
from .proposer import propose_mapping
from .store import ProposalStore

__all__ = ["DiscoveryResult", "run_discovery", "approve_proposal"]

MIN_QUARANTINED = 5


@dataclass(slots=True)
class DiscoveryResult:
    """What one discovery pass did."""

    examined: list[str] = field(default_factory=list)
    auto_approved: list[str] = field(default_factory=list)
    queued: list[dict[str, Any]] = field(default_factory=list)
    skipped: list[dict[str, str]] = field(default_factory=list)
    backfilled: dict[str, int] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "examined": self.examined,
            "auto_approved": self.auto_approved,
            "queued": self.queued,
            "skipped": self.skipped,
            "backfilled": self.backfilled,
        }


def _write_mapping(sources_dir: Path, source: str, yaml_text: str) -> Path:
    """Write the mapping where the ordinary registry will find it.

    Deliberately the same directory a human would use. A mapping the discovery
    lane authored gets no privileged path and no exemption from the load-time
    validation every other mapping faces.
    """
    sources_dir.mkdir(parents=True, exist_ok=True)
    path = sources_dir / f"{source}.yaml"
    path.write_text(yaml_text, encoding="utf-8")
    return path


def run_discovery(
    pipeline,
    proposals: ProposalStore,
    sources_dir: Path,
    *,
    min_quarantined: int = MIN_QUARANTINED,
    sample_limit: int = 60,
) -> DiscoveryResult:
    """Examine every source with quarantined events and propose mappings."""
    result = DiscoveryResult()
    if pipeline.ocsf is None:
        return result

    for source, count in pipeline.ocsf.quarantined_sources():
        if count < min_quarantined:
            result.skipped.append(
                {"source": source, "reason": f"only {count} events, need "
                                             f"{min_quarantined}"}
            )
            continue
        if proposals.has_pending(source):
            result.skipped.append({"source": source, "reason": "awaiting review"})
            continue
        if proposals.was_rejected(source):
            result.skipped.append(
                {"source": source, "reason": "a previous proposal was rejected"}
            )
            continue

        samples = [
            event.raw_bytes
            for event in pipeline.store.iter_events(
                source_id=source, limit=sample_limit, newest_first=True
            )
        ]
        result.examined.append(source)

        proposal = propose_mapping(source, samples)
        if proposal is None or not proposal.fields:
            reason = (
                proposal.notes[0] if proposal and proposal.notes
                else "no candidate mapping could be inferred"
            )
            result.skipped.append({"source": source, "reason": reason})
            continue

        report = score_proposal(proposal, samples)

        if report.auto_approve:
            yaml_text = proposal.to_yaml(approved_by="auto (all checks passed)")
            try:
                Mapping.from_yaml(yaml_text)          # never write an invalid file
            except MappingError as exc:
                result.skipped.append(
                    {"source": source, "reason": f"proposal did not validate: {exc}"}
                )
                continue
            _write_mapping(sources_dir, source, yaml_text)
            pipeline.registry.refresh()
            result.auto_approved.append(source)
            result.backfilled[source] = pipeline.backfill(source)["normalized"]
        else:
            proposal_id = proposals.add(proposal, report)
            result.queued.append(
                {
                    "proposal_id": proposal_id,
                    "source": source,
                    "confidence": round(report.confidence, 4),
                    "failed": report.failed,
                    "bar": CONFIDENCE_BAR,
                }
            )

    return result


def approve_proposal(
    pipeline,
    proposals: ProposalStore,
    sources_dir: Path,
    proposal_id: int,
    *,
    approved_by: str,
    note: str | None = None,
) -> dict[str, Any]:
    """Approve a queued proposal, activate it, and backfill its quarantine."""
    stored = proposals.get(proposal_id)
    if stored is None:
        return {"error": f"no proposal {proposal_id}"}
    if stored.state != "pending":
        return {"error": f"proposal {proposal_id} is already {stored.state}"}

    yaml_text = stored.yaml
    if "approved_by:" not in yaml_text:
        yaml_text = yaml_text.replace(
            "author: discovery", f"author: discovery\napproved_by: {approved_by}"
        )

    try:
        Mapping.from_yaml(yaml_text)
    except MappingError as exc:
        return {"error": f"proposal does not validate: {exc}"}

    _write_mapping(sources_dir, stored.source_id, yaml_text)
    pipeline.registry.refresh()
    proposals.decide(proposal_id, state="approved", by=approved_by, note=note)

    backfill = pipeline.backfill(stored.source_id)
    return {
        "approved": stored.source_id,
        "proposal_id": proposal_id,
        "approved_by": approved_by,
        "confidence": stored.confidence,
        "backfill": backfill,
    }
