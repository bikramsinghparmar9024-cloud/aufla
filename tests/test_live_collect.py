"""Live collection from the local host, and the Windows mappings."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from aufla.collect.live import CollectorStatus, LiveCollector, collect_once
from aufla.ledger import Ledger
from aufla.mapping import MappingRegistry
from aufla.models import ParseStatus, RawEvent, Transport
from aufla.normalize import Normalizer
from aufla.pipeline import Pipeline
from aufla.storage import SQLiteRawStore

SOURCES = Path(__file__).resolve().parents[1] / "sources"

NETCONN = b"1789629547597,192.168.1.10,65499,203.0.113.9,443,Established,chrome,7328"
EVENTLOG = (
    b"<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
    b"<System><Provider Name='Microsoft-Windows-DistributedCOM'/>"
    b"<EventID Qualifiers='0'>10016</EventID><Level>3</Level>"
    b"<TimeCreated SystemTime='2026-09-17T07:06:55.4511929Z'/>"
    b"<EventRecordID>381710</EventRecordID><Channel>System</Channel>"
    b"<Computer>LAPTOP-TEST</Computer></System>"
    b"<EventData><Data>some detail</Data></EventData></Event>"
)


@pytest.fixture(scope="module")
def normalizer():
    registry = MappingRegistry(SOURCES)
    assert registry.refresh().ok
    return Normalizer(registry)


def capture(payload: bytes, source: str) -> RawEvent:
    return RawEvent.capture(payload, source, transport=Transport.FILE)


# --- the Windows mappings -------------------------------------------------


def test_netconn_maps_to_network_activity(normalizer):
    record = normalizer.normalize(capture(NETCONN, "windows_netconn"))

    assert record.parse_status is ParseStatus.FULL
    assert record.ocsf_class == 4001
    assert record.fields["src_endpoint.ip"] == "192.168.1.10"
    assert record.fields["dst_endpoint.ip"] == "203.0.113.9"
    assert record.fields["dst_endpoint.port"] == 443
    assert record.fields["activity_id"] == 6      # Established -> Traffic
    assert record.errors == []


def test_eventlog_maps_to_detection_finding(normalizer):
    record = normalizer.normalize(capture(EVENTLOG, "windows_eventlog"))

    assert record.parse_status is ParseStatus.FULL
    assert record.ocsf_class == 2004
    assert record.fields["finding_info.title"] == "Microsoft-Windows-DistributedCOM"
    assert record.fields["finding_info.uid"] == "10016"
    assert record.fields["severity_id"] == 3      # Level 3 Warning -> Medium
    assert record.fields["metadata.log_name"] == "System"


def test_xml_attribute_references_are_expressible():
    # `$System.Provider.@Name` must parse: without '@' in the named-reference
    # pattern no mapping could ever address an XML attribute.
    from aufla.mapping.schema import FieldRef, RefKind

    ref = FieldRef.parse("$System.Provider.@Name")
    assert ref.kind is RefKind.NAMED
    assert ref.value == "System.Provider.@Name"


def test_windows_level_lookup_covers_every_level():
    from aufla.normalize.transforms import apply_lookup

    assert apply_lookup("windows_level", "1") == 5   # Critical
    assert apply_lookup("windows_level", "2") == 4   # Error
    assert apply_lookup("windows_level", "3") == 3   # Warning
    assert apply_lookup("windows_level", "4") == 1   # Information


# --- the collector --------------------------------------------------------


def make_pipeline_factory(tmp_path, registry):
    def factory():
        store = SQLiteRawStore(tmp_path / "raw.db")
        ledger = Ledger(tmp_path / "ledger.db")
        pipeline = Pipeline(store, ledger, registry)

        def closer():
            store.close()
            ledger.close()

        return pipeline, closer

    return factory


def test_collector_start_and_stop_are_idempotent(tmp_path):
    registry = MappingRegistry(SOURCES)
    registry.refresh()
    collector = LiveCollector(
        make_pipeline_factory(tmp_path, registry), interval=30, channels=()
    )

    assert not collector.running
    collector.start()
    assert collector.running
    collector.start()                    # second start is a no-op
    assert collector.running

    collector.stop()
    assert not collector.running
    collector.stop()                     # second stop is a no-op
    assert not collector.running


def test_collector_appends_and_never_deletes(tmp_path):
    # The one write path a browser can trigger must only ever add.
    registry = MappingRegistry(SOURCES)
    registry.refresh()
    factory = make_pipeline_factory(tmp_path, registry)

    pipeline, closer = factory()
    seeded = [capture(NETCONN, "windows_netconn")]
    pipeline.store.append(seeded)
    before = pipeline.store.count()
    closer()

    collector = LiveCollector(factory, interval=30, channels=())
    collector.start()
    time.sleep(1.5)
    collector.stop()

    pipeline, closer = factory()
    try:
        assert pipeline.store.count() >= before          # only grew
        assert pipeline.store.get(seeded[0].event_uid) is not None
    finally:
        closer()


def test_collector_status_serialises(tmp_path):
    status = CollectorStatus(running=True, started_at=time.time(), ticks=2)
    payload = status.as_dict()
    assert payload["running"] is True
    assert payload["ticks"] == 2
    assert payload["uptime_s"] >= 0


def test_eventlog_high_water_mark_stops_re_emitting_the_same_events(monkeypatch):
    # wevtutil has no "since" argument -- it returns the latest N every time.
    # Without a high-water mark the same occurrence is ingested on every poll,
    # each time with a fresh receipt time, so it is accepted as new evidence.
    from aufla.collect import live

    batch1 = "".join(
        f"<Event><System><EventRecordID>{i}</EventRecordID></System></Event>"
        for i in (101, 102, 103)
    )
    monkeypatch.setattr(live, "_run", lambda *a, **k: batch1)

    seen: dict[str, int] = {}
    first = live.collect_eventlog(("System",), seen=seen)
    assert len(first) == 3
    assert seen["System"] == 103

    # Same output again: nothing new happened, so nothing is emitted.
    assert live.collect_eventlog(("System",), seen=seen) == []

    batch2 = batch1 + (
        "<Event><System><EventRecordID>104</EventRecordID></System></Event>"
    )
    monkeypatch.setattr(live, "_run", lambda *a, **k: batch2)
    third = live.collect_eventlog(("System",), seen=seen)
    assert len(third) == 1              # only the genuinely new record
    assert b"104" in third[0]
    assert seen["System"] == 104


def test_eventlog_without_a_mark_emits_everything(monkeypatch):
    from aufla.collect import live

    monkeypatch.setattr(
        live, "_run",
        lambda *a, **k: "<Event><System><EventRecordID>9</EventRecordID></System></Event>",
    )
    assert len(live.collect_eventlog(("System",))) == 1
    assert len(live.collect_eventlog(("System",))) == 1


def test_a_connection_is_recorded_once_not_once_per_poll(monkeypatch):
    # A firewall logs a connection event, not the connection's ongoing state.
    from aufla.collect import live

    line = b"1789629547597,192.168.1.10,65499,203.0.113.9,443,Established,chrome,7328"
    later = b"1789629557600,192.168.1.10,65499,203.0.113.9,443,Established,chrome,7328"

    assert live._connection_key(line) == live._connection_key(later)

    seen: set[str] = set()
    monkeypatch.setattr(live, "collect_netconn", lambda: [line])

    class FakePipeline:
        def __init__(self):
            self.seen = []

        def ingest(self, payloads, source, **kw):
            self.seen.append((source, len(payloads)))

            class R:
                accepted = len(payloads)

            return R()

    p = FakePipeline()
    live.collect_once(p, channels=(), seen_connections=seen)
    monkeypatch.setattr(live, "collect_netconn", lambda: [later])
    live.collect_once(p, channels=(), seen_connections=seen)

    netconn_ingests = [n for s, n in p.seen if s == live.NETCONN_SOURCE]
    assert netconn_ingests == [1]      # first poll only


def test_restarting_capture_clears_the_occurrence_state(tmp_path):
    registry = MappingRegistry(SOURCES)
    registry.refresh()
    collector = LiveCollector(
        make_pipeline_factory(tmp_path, registry), interval=30, channels=()
    )
    collector.start()
    collector._seen_connections.add("stale")
    collector.stop()

    collector.start()
    assert collector._seen_connections == set()
    assert collector._seen_records == {}
    collector.stop()


def test_collect_once_tolerates_no_channels(tmp_path):
    registry = MappingRegistry(SOURCES)
    registry.refresh()
    pipeline, closer = make_pipeline_factory(tmp_path, registry)()
    try:
        results = collect_once(pipeline, channels=())
        assert "windows_eventlog" in results
        assert results["windows_eventlog"] == 0
    finally:
        closer()
