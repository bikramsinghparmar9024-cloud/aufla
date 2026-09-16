"""End-to-end normalisation against the bundled reference mappings."""

from __future__ import annotations

import time
from pathlib import Path

import pytest

from aufla.mapping import MappingRegistry
from aufla.models import ParseStatus, RawEvent, Transport
from aufla.normalize import Normalizer

SOURCES = Path(__file__).resolve().parents[1] / "sources"
NOW_NS = int(time.time() * 1_000_000_000)

PFSENSE_BLOCK = (
    b"<134>Sep 17 10:00:00 fw01 filterlog[1234]: "
    b"5,,,1000000103,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,"
    b"198.18.0.9,10.0.0.5,45332,22,0"
)
PFSENSE_PASS = (
    b"<134>Sep 17 10:00:01 fw01 filterlog[1234]: "
    b"5,,,1000000104,em0,match,pass,out,4,0x0,,64,0,0,DF,6,tcp,120,"
    b"10.0.0.5,203.0.113.9,51514,443,80"
)
SURICATA_ALERT = (
    b'{"timestamp":"2026-09-17T10:00:00.000000+0000","event_type":"alert",'
    b'"src_ip":"198.18.0.9","dest_ip":"10.0.0.5","src_port":45332,'
    b'"dest_port":22,"alert":{"signature":"ET SCAN Potential SSH Scan",'
    b'"signature_id":2001219,"category":"Attempted Recon","severity":2}}'
)
SURICATA_FLOW = (
    b'{"timestamp":"2026-09-17T10:00:05.000000+0000","event_type":"flow",'
    b'"src_ip":"10.0.0.5","dest_ip":"203.0.113.9","src_port":51514,'
    b'"dest_port":443,"flow":{"bytes_toserver":1200,"bytes_toclient":8400,'
    b'"pkts_toserver":9}}'
)
SQUID = (
    b"1789588800.123    342 10.0.0.5 TCP_MISS/200 8431 GET "
    b"http://intranet.test/report - HIER_DIRECT/10.0.1.9 text/html"
)


@pytest.fixture(scope="module")
def normalizer():
    registry = MappingRegistry(SOURCES)
    report = registry.refresh()
    assert report.ok, report.failed
    return Normalizer(registry)


def capture(payload: bytes, source: str) -> RawEvent:
    return RawEvent.capture(
        payload, source, transport=Transport.UDP, received_at_ns=NOW_NS
    )


# --- pfSense -------------------------------------------------------------


def test_pfsense_block_normalises_fully(normalizer):
    record = normalizer.normalize(capture(PFSENSE_BLOCK, "pfsense_filterlog"))

    assert record.parse_status is ParseStatus.FULL
    assert record.ocsf_class == 4001
    assert record.rule_name == "block"
    assert record.fields["src_endpoint.ip"] == "198.18.0.9"
    assert record.fields["dst_endpoint.ip"] == "10.0.0.5"
    assert record.fields["dst_endpoint.port"] == 22
    assert record.fields["disposition_id"] == 2
    assert record.errors == []


def test_pfsense_pass_selects_the_other_rule(normalizer):
    record = normalizer.normalize(capture(PFSENSE_PASS, "pfsense_filterlog"))

    assert record.rule_name == "pass"
    assert record.fields["disposition_id"] == 1
    assert record.fields["src_endpoint.port"] == 51514
    assert record.fields["traffic.bytes"] == 80


def test_syslog_framing_does_not_reach_the_parser(normalizer):
    # If the header were not stripped, column 1 would be "<134>Sep 17 ..."
    record = normalizer.normalize(capture(PFSENSE_BLOCK, "pfsense_filterlog"))
    assert record.fields["connection_info.protocol_num"] == 6


# --- Suricata ------------------------------------------------------------


def test_suricata_alert_becomes_a_detection_finding(normalizer):
    record = normalizer.normalize(capture(SURICATA_ALERT, "suricata_eve"))

    assert record.parse_status is ParseStatus.FULL
    assert record.ocsf_class == 2004
    assert record.fields["finding_info.title"] == "ET SCAN Potential SSH Scan"
    assert record.fields["finding_info.uid"] == "2001219"
    assert record.fields["severity_id"] == 3        # suricata 2 -> medium
    assert record.fields["time"] > 0


def test_suricata_flow_becomes_network_activity(normalizer):
    record = normalizer.normalize(capture(SURICATA_FLOW, "suricata_eve"))

    assert record.ocsf_class == 4001
    assert record.rule_name == "flow"
    assert record.fields["traffic.bytes_in"] == 1200
    assert record.fields["traffic.bytes_out"] == 8400


def test_one_mapping_covers_two_event_shapes(normalizer):
    alert = normalizer.normalize(capture(SURICATA_ALERT, "suricata_eve"))
    flow = normalizer.normalize(capture(SURICATA_FLOW, "suricata_eve"))
    assert alert.ocsf_class != flow.ocsf_class
    assert alert.mapping_id == flow.mapping_id


# --- Squid ---------------------------------------------------------------


def test_squid_normalises_with_transforms(normalizer):
    record = normalizer.normalize(capture(SQUID, "squid_access"))

    assert record.parse_status is ParseStatus.FULL
    assert record.ocsf_class == 4002
    assert record.fields["http_response.code"] == 200      # after_slash
    assert record.fields["http_request.http_method"] == "GET"
    assert record.fields["activity_id"] == 3               # GET -> 3
    assert record.fields["http_response.length"] == 8431


# --- lineage -------------------------------------------------------------


def test_every_record_carries_full_lineage(normalizer):
    event = capture(SURICATA_ALERT, "suricata_eve")
    record = normalizer.normalize(event)

    assert record.event_uid == event.event_uid       # back to the raw event
    assert record.raw_hash == event.raw_hash          # and provably unchanged
    assert record.mapping_id == "suricata_eve"
    assert record.mapping_version == 1
    assert len(record.mapping_hash) == 64             # which version exactly
    assert record.rule_name == "alert"


def test_observed_time_is_our_clock_not_the_devices(normalizer):
    event = capture(SURICATA_ALERT, "suricata_eve")
    record = normalizer.normalize(event)

    assert record.observed_time == event.received_at_ns // 1_000_000
    assert record.event_time != record.observed_time


def test_to_dict_is_flat_and_carries_lineage(normalizer):
    record = normalizer.normalize(capture(PFSENSE_PASS, "pfsense_filterlog"))
    d = record.to_dict()

    assert d["event_uid"] == str(record.event_uid)
    assert d["class_uid"] == 4001
    assert d["mapping_version"] == 1
    assert d["src_endpoint.ip"] == "10.0.0.5"


# --- quarantine ----------------------------------------------------------


def test_an_unmapped_source_is_quarantined_not_lost(normalizer):
    record = normalizer.normalize(capture(b"whatever this is", "unknown_device"))

    assert record.is_quarantined
    assert record.ocsf_class is None
    # The raw event is already stored; only its projection is deferred.
    assert record.event_uid is not None
    assert any("no mapping" in w for w in record.warnings)


def test_quarantine_reports_the_detected_format_for_triage(normalizer):
    record = normalizer.normalize(
        capture(b'{"a":1,"b":2,"c":3}', "unknown_device")
    )
    assert any("json" in w for w in record.warnings)


def test_an_unparseable_body_quarantines_with_a_reason(normalizer):
    record = normalizer.normalize(capture(b"{broken json", "suricata_eve"))
    assert record.is_quarantined
    assert any("parse failed" in w for w in record.warnings)
    assert record.mapping_id == "suricata_eve"


def test_an_event_matching_no_rule_is_quarantined(normalizer):
    unmatched = (
        b'{"timestamp":"2026-09-17T10:00:00Z","event_type":"stats","x":1}'
    )
    record = normalizer.normalize(capture(unmatched, "suricata_eve"))
    assert record.is_quarantined
    assert any("no rule" in w for w in record.warnings)


def test_normalisation_never_raises(normalizer):
    for payload in (b"", b"\xff\xfe\x00", b"," * 500, b"{" * 100):
        for source in ("suricata_eve", "pfsense_filterlog", "nope"):
            record = normalizer.normalize(capture(payload, source))
            assert record.event_uid is not None


# --- time fallback -------------------------------------------------------


def test_a_missing_device_time_falls_back_to_the_receipt_clock(normalizer):
    # pfSense's mapping does not map `time`, and `time` is required. Falling
    # back to our own clock keeps the event usable, and the warning keeps it
    # honest.
    record = normalizer.normalize(capture(PFSENSE_BLOCK, "pfsense_filterlog"))

    assert record.parse_status is ParseStatus.FULL
    assert record.fields["time"] == record.observed_time
    assert any("falls back" in w for w in record.warnings)


# --- coverage ------------------------------------------------------------


def test_mapping_coverage_is_reported(normalizer):
    record = normalizer.normalize(capture(SURICATA_ALERT, "suricata_eve"))
    assert 0.0 < record.mapping_coverage <= 1.0


def test_batch_normalisation(normalizer):
    events = [
        capture(PFSENSE_BLOCK, "pfsense_filterlog"),
        capture(SURICATA_ALERT, "suricata_eve"),
        capture(SQUID, "squid_access"),
    ]
    records = normalizer.normalize_many(events)
    assert [r.parse_status for r in records] == [ParseStatus.FULL] * 3
