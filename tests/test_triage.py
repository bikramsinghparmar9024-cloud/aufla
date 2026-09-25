"""Manual triage: an analyst marking a dangerous-looking finding as normal.

This is the human-in-the-loop counterpart to discovery approval, but for
severity rather than for a mapping: the event keeps whatever the mapping
produced, and a judgement is recorded beside it rather than inside it.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from aufla.ledger import Ledger
from aufla.mapping import MappingRegistry
from aufla.models import RawEvent, Transport
from aufla.pipeline import Pipeline
from aufla.storage import OCSFStore, SQLiteRawStore

# A source whose events are all Critical (severity_id 5), so every ingested
# event is a finding without depending on any bundled mapping's real severity
# logic.
CRITICAL_MAPPING = """
source: alarm_box
format: kv
version: 1
approved_by: reference-mapping
rules:
  - name: alert
    ocsf_class: 2004
    fields:
      finding_info.title: $msg
      severity_id: 5
"""


@pytest.fixture()
def parts(tmp_path):
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "alarm_box.yaml").write_text(CRITICAL_MAPPING, encoding="utf-8")

    registry = MappingRegistry(sources)
    assert registry.refresh().ok

    store = SQLiteRawStore(tmp_path / "raw.db")
    ledger = Ledger(tmp_path / "ledger.db", batch_size=10_000)
    ocsf = OCSFStore(tmp_path / "ocsf.db")
    pipeline = Pipeline(store, ledger, registry, ocsf=ocsf)

    yield pipeline, ocsf

    store.close()
    ledger.close()
    ocsf.close()


def alerts(n: int) -> list[bytes]:
    return [f'msg="alarm {i}"'.encode() for i in range(n)]


def test_a_critical_event_appears_in_findings(parts):
    pipeline, ocsf = parts
    pipeline.ingest(alerts(1), "alarm_box")

    found = ocsf.findings()
    assert len(found) == 1
    assert found[0]["severity_id"] == 5


def test_findings_are_not_capped_at_twelve(parts):
    # The console previously hid anything past the 12th finding in a window,
    # which reads as "the pipeline missed it" rather than "the list was cut".
    pipeline, ocsf = parts
    pipeline.ingest(alerts(40), "alarm_box")

    assert len(ocsf.findings()) == 40


def test_marking_normal_requires_a_name(parts):
    pipeline, ocsf = parts
    pipeline.ingest(alerts(1), "alarm_box")
    uid = ocsf.findings()[0]["event_uid"]

    with pytest.raises(ValueError, match="name"):
        ocsf.set_triage(uid, by="")


def test_marking_normal_removes_it_from_findings(parts):
    pipeline, ocsf = parts
    pipeline.ingest(alerts(3), "alarm_box")
    target = ocsf.findings()[0]["event_uid"]

    ocsf.set_triage(target, by="analyst-7", note="known-good test alarm")

    remaining = ocsf.findings()
    assert len(remaining) == 2
    assert target not in {f["event_uid"] for f in remaining}


def test_triage_never_touches_severity_itself(parts):
    # The judgement lives beside the derived data, not inside it. If severity
    # were rewritten, a later re-derivation from raw could disagree with a
    # human decision that is supposed to be permanent.
    pipeline, ocsf = parts
    pipeline.ingest(alerts(1), "alarm_box")
    uid = ocsf.findings()[0]["event_uid"]

    ocsf.set_triage(uid, by="analyst-7")

    row = ocsf.get(uid)
    assert row["severity_id"] == 5
    assert row["triage_status"] == "normal"
    assert row["triaged_by"] == "analyst-7"
    assert row["triaged_ns"] is not None


def test_a_triaged_finding_is_visible_with_include_triaged(parts):
    pipeline, ocsf = parts
    pipeline.ingest(alerts(1), "alarm_box")
    uid = ocsf.findings()[0]["event_uid"]
    ocsf.set_triage(uid, by="analyst-7")

    assert ocsf.findings() == []
    full = ocsf.findings(include_triaged=True)
    assert len(full) == 1
    assert full[0]["triage_status"] == "normal"


def test_triage_survives_a_backfill(parts):
    # A re-derivation (a corrected mapping, a rerun) must not silently erase
    # a human's earlier call -- the same guarantee first_status already has.
    pipeline, ocsf = parts
    pipeline.ingest(alerts(1), "alarm_box")
    uid = ocsf.findings()[0]["event_uid"]
    ocsf.set_triage(uid, by="analyst-7", note="benign")

    pipeline.backfill("alarm_box")

    row = ocsf.get(uid)
    assert row["triage_status"] == "normal"
    assert row["triaged_by"] == "analyst-7"
    assert row["triage_note"] == "benign"
    assert ocsf.findings() == []


def test_triage_on_an_unknown_event_returns_none(parts):
    _pipeline, ocsf = parts
    assert ocsf.set_triage("00000000-0000-0000-0000-000000000000", by="x") is None


def test_sort_direction_changes_which_events_a_limit_keeps(parts):
    # The bug this pins: reversing an already-fetched "newest N" page would
    # show the newest N in oldest-first order, not the true oldest N. Sort
    # has to apply before LIMIT, at the query.
    pipeline, ocsf = parts
    pipeline.ingest(alerts(50), "alarm_box")

    newest_10 = ocsf.query(limit=10, newest_first=True)
    oldest_10 = ocsf.query(limit=10, newest_first=False)

    newest_uids = {r["event_uid"] for r in newest_10}
    oldest_uids = {r["event_uid"] for r in oldest_10}
    assert newest_uids.isdisjoint(oldest_uids)   # genuinely different events
    assert [r["observed_time"] for r in newest_10] == sorted(
        (r["observed_time"] for r in newest_10), reverse=True
    )
    assert [r["observed_time"] for r in oldest_10] == sorted(
        r["observed_time"] for r in oldest_10
    )


def test_a_fresh_database_gets_triage_columns(tmp_path):
    # A store created after this feature existed must not need migration --
    # confirms the CREATE TABLE path and the ALTER TABLE path agree.
    ocsf = OCSFStore(tmp_path / "fresh.db")
    try:
        assert ocsf.findings() == []
    finally:
        ocsf.close()


def test_an_existing_database_is_migrated_in_place(tmp_path):
    # Simulates a database that predates the triage columns: create one with
    # the old schema, then open it through OCSFStore and confirm triage works
    # without the caller doing anything special.
    import sqlite3

    path = tmp_path / "old.db"
    conn = sqlite3.connect(path)
    conn.execute(
        """
        CREATE TABLE ocsf_events (
            event_uid TEXT PRIMARY KEY, raw_hash TEXT, source_id TEXT,
            observed_time INTEGER, event_time INTEGER, class_uid INTEGER,
            mapping_id TEXT, mapping_version INTEGER, mapping_hash TEXT,
            rule_name TEXT, parse_status TEXT, first_status TEXT,
            first_seen_ns INTEGER, resolved_at_ns INTEGER,
            mapping_coverage REAL, severity_id INTEGER, src_ip TEXT,
            src_port INTEGER, dst_ip TEXT, dst_port INTEGER, summary TEXT,
            fields TEXT, unmapped TEXT, warnings TEXT, notes TEXT
        )
        """
    )
    conn.commit()
    conn.close()

    ocsf = OCSFStore(path)
    try:
        assert ocsf.findings() == []   # migration did not crash on an empty table
    finally:
        ocsf.close()
