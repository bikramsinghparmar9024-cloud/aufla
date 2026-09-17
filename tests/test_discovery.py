"""The OCSF projection, quarantine accounting, and the human-in-the-loop gate."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from aufla.discovery import (
    CONFIDENCE_BAR,
    ProposalStore,
    approve_proposal,
    propose_mapping,
    run_discovery,
    score_proposal,
)
from aufla.ledger import Ledger
from aufla.mapping import MappingRegistry
from aufla.models import ParseStatus, RawEvent, Transport
from aufla.normalize import Normalizer
from aufla.pipeline import Pipeline
from aufla.storage import OCSFStore, SQLiteRawStore

SOURCES = Path(__file__).resolve().parents[1] / "sources"

# A vendor with keyed values and positional endpoints.
ACME = (
    "<190>Sep 17 10:00:{s:02d} ACME-FW v4.2 :: sess={i} act=permit "
    "from 10.0.0.{h}/5{p} to 203.0.113.9/443 proto=tcp cls=web dur=120ms"
)
# The same, but destination first -- a wrong-but-valid mapping waiting to happen.
ORBIT = (
    "<188>Sep 17 10:00:{s:02d} orbit-proxy[{i}]: session={i} verdict=allow "
    "to 203.0.113.9/443 from 10.0.1.{h}/5{p} scheme=https bytes=900"
)


def acme(n: int = 40) -> list[bytes]:
    return [
        ACME.format(s=i % 60, i=1000 + i, h=(i % 50) + 5, p=1000 + i).encode()
        for i in range(n)
    ]


def orbit(n: int = 40) -> list[bytes]:
    return [
        ORBIT.format(s=i % 60, i=2000 + i, h=(i % 50) + 5, p=2000 + i).encode()
        for i in range(n)
    ]


@pytest.fixture()
def parts(tmp_path):
    # An isolated, initially empty sources directory. Both vendors below must
    # start genuinely unknown, so the repository's bundled mappings are not
    # loaded -- and a mapping discovery writes here cannot leak into the repo.
    sources = tmp_path / "sources"
    sources.mkdir()

    registry = MappingRegistry(sources)
    registry.refresh()
    store = SQLiteRawStore(tmp_path / "raw.db")
    ledger = Ledger(tmp_path / "ledger.db", batch_size=10_000)
    ocsf = OCSFStore(tmp_path / "ocsf.db")
    proposals = ProposalStore(tmp_path / "proposals.db")
    pipeline = Pipeline(store, ledger, registry, ocsf=ocsf)

    yield pipeline, ocsf, proposals, sources

    store.close()
    ledger.close()
    ocsf.close()
    proposals.close()


# --- the projection -------------------------------------------------------


def test_ingest_materialises_the_projection(parts):
    pipeline, ocsf, _, _ = parts
    pipeline.ingest(acme(10), "acme_fw")

    assert ocsf.count() == 10
    row = ocsf.query(limit=1)[0]
    assert row["parse_status"] == "quarantined"   # no mapping yet
    assert row["first_status"] == "quarantined"


def test_aggregations_come_from_sql_not_reparsing(parts):
    pipeline, ocsf, _, _ = parts
    pipeline.ingest(acme(30), "acme_fw")
    pipeline.ingest(orbit(20), "orbit_proxy")

    assert dict(ocsf.counts_by("source_id")) == {"acme_fw": 30, "orbit_proxy": 20}
    assert ocsf.event_count() == 50


def test_quarantine_summary_counts_arrivals_and_resolutions(parts):
    pipeline, ocsf, _, _ = parts
    pipeline.ingest(acme(25), "acme_fw")

    summary = ocsf.quarantine_summary()
    assert summary["ever_quarantined"] == 25
    assert summary["pending"] == 25
    assert summary["resolved"] == 0
    assert summary["resolution_rate"] == 0.0


def test_a_resolved_event_keeps_its_quarantined_history(parts, tmp_path):
    # The point of two status columns: after a backfill the event parses, but
    # the record that it once did not must survive, or the "since resolved"
    # figure is unrecoverable.
    pipeline, ocsf, proposals, sources = parts
    pipeline.ingest(acme(30), "acme_fw")

    result = run_discovery(pipeline, proposals, sources)
    assert "acme_fw" in result.auto_approved

    summary = ocsf.quarantine_summary()
    assert summary["ever_quarantined"] == 30
    assert summary["resolved"] == 30
    assert summary["pending"] == 0
    assert summary["resolution_rate"] == 1.0

    row = ocsf.query(limit=1)[0]
    assert row["first_status"] == "quarantined"
    assert row["parse_status"] == "full"
    assert row["resolved"] is True


def test_resolution_is_stamped_once(parts, tmp_path):
    pipeline, ocsf, proposals, sources = parts
    pipeline.ingest(acme(30), "acme_fw")
    run_discovery(pipeline, proposals, sources)

    first = ocsf.query(limit=1)[0]["resolved_at_ns"]
    pipeline.backfill("acme_fw")            # re-derive again
    assert ocsf.query(limit=1)[0]["resolved_at_ns"] == first


# --- the gate -------------------------------------------------------------


def test_a_clean_proposal_passes_every_check():
    samples = acme(40)
    proposal = propose_mapping("acme_fw", samples)
    report = score_proposal(proposal, samples)

    assert report.confidence >= CONFIDENCE_BAR
    assert report.auto_approve
    assert report.failed == []


def test_reversed_endpoints_are_caught_and_sent_to_a_human():
    # Syntactically perfect, semantically backwards. Grammar constraints
    # cannot see this; applying the mapping to real events can.
    samples = orbit(40)
    proposal = propose_mapping("orbit_proxy", samples)
    report = score_proposal(proposal, samples)

    assert not report.auto_approve
    assert report.confidence < CONFIDENCE_BAR
    assert "semantic sanity" in report.failed
    # every other check passed, which is exactly why this case is dangerous
    assert set(report.failed) == {"semantic sanity"}


def test_confidence_is_the_weakest_check_not_an_average():
    samples = orbit(40)
    report = score_proposal(propose_mapping("orbit_proxy", samples), samples)
    assert report.confidence == min(c.score for c in report.checks)


def test_too_few_samples_is_not_a_format(parts):
    assert propose_mapping("tiny", acme(3)) is None


def test_a_completeness_note_does_not_fail_semantic_sanity():
    # "This device gave us no timestamp" says nothing about correctness. If it
    # counted as a semantic warning, almost every honest proposal would fail.
    samples = acme(40)
    report = score_proposal(propose_mapping("acme_fw", samples), samples)
    semantic = next(c for c in report.checks if c.name == "semantic sanity")
    assert semantic.passed


# --- the loop -------------------------------------------------------------


def test_discovery_auto_approves_only_when_every_check_passes(parts):
    pipeline, ocsf, proposals, sources = parts
    pipeline.ingest(acme(30), "acme_fw")
    pipeline.ingest(orbit(30), "orbit_proxy")

    result = run_discovery(pipeline, proposals, sources)

    assert result.auto_approved == ["acme_fw"]
    assert [q["source"] for q in result.queued] == ["orbit_proxy"]
    assert (sources / "acme_fw.yaml").exists()
    assert not (sources / "orbit_proxy.yaml").exists()   # nothing activated


def test_a_queued_proposal_changes_nothing_until_approved(parts):
    pipeline, ocsf, proposals, sources = parts
    pipeline.ingest(orbit(30), "orbit_proxy")
    run_discovery(pipeline, proposals, sources)

    assert ocsf.quarantine_summary()["pending"] == 30
    assert len(proposals.pending()) == 1


def test_approval_requires_a_named_person(parts):
    pipeline, _, proposals, sources = parts
    pipeline.ingest(orbit(30), "orbit_proxy")
    run_discovery(pipeline, proposals, sources)
    pid = proposals.pending()[0].proposal_id

    with pytest.raises(ValueError, match="name"):
        proposals.decide(pid, state="approved", by="")


def test_approving_activates_the_mapping_and_backfills(parts):
    pipeline, ocsf, proposals, sources = parts
    pipeline.ingest(orbit(30), "orbit_proxy")
    run_discovery(pipeline, proposals, sources)
    pid = proposals.pending()[0].proposal_id

    outcome = approve_proposal(
        pipeline, proposals, sources, pid, approved_by="analyst-7"
    )

    assert outcome["approved"] == "orbit_proxy"
    assert outcome["backfill"]["normalized"] == 30
    assert (sources / "orbit_proxy.yaml").exists()
    assert "approved_by: analyst-7" in (sources / "orbit_proxy.yaml").read_text()

    summary = ocsf.quarantine_summary()
    assert summary["resolved"] == 30
    assert summary["pending"] == 0


def test_rejecting_leaves_the_source_quarantined(parts):
    pipeline, ocsf, proposals, sources = parts
    pipeline.ingest(orbit(30), "orbit_proxy")
    run_discovery(pipeline, proposals, sources)
    pid = proposals.pending()[0].proposal_id

    proposals.decide(pid, state="rejected", by="analyst-7", note="endpoints reversed")

    assert proposals.pending() == []
    assert ocsf.quarantine_summary()["pending"] == 30
    assert not (sources / "orbit_proxy.yaml").exists()


def test_a_rejected_source_is_not_re_proposed(parts):
    pipeline, _, proposals, sources = parts
    pipeline.ingest(orbit(30), "orbit_proxy")
    run_discovery(pipeline, proposals, sources)
    proposals.decide(
        proposals.pending()[0].proposal_id, state="rejected", by="analyst-7"
    )

    result = run_discovery(pipeline, proposals, sources)
    assert [s["source"] for s in result.skipped] == ["orbit_proxy"]
    assert result.queued == []


def test_a_decision_is_an_audit_record(parts):
    pipeline, _, proposals, sources = parts
    pipeline.ingest(orbit(30), "orbit_proxy")
    run_discovery(pipeline, proposals, sources)
    pid = proposals.pending()[0].proposal_id

    approve_proposal(pipeline, proposals, sources, pid, approved_by="maj-sharma")
    stored = proposals.get(pid)

    assert stored.state == "approved"
    assert stored.decided_by == "maj-sharma"
    assert stored.decided_ns > 0
    assert stored.confidence < CONFIDENCE_BAR    # what was overridden, recorded


def test_an_approved_mapping_faces_the_same_validation(parts):
    # A discovery-authored mapping is written into the ordinary sources
    # directory and loaded by the ordinary registry. There is no privileged
    # path around load-time validation.
    pipeline, _, proposals, sources = parts
    pipeline.ingest(acme(30), "acme_fw")
    run_discovery(pipeline, proposals, sources)

    reg = MappingRegistry(sources, require_approval=True)
    assert reg.refresh().ok
    assert "acme_fw" in reg
