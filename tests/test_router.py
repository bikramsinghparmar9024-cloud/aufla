"""Format detection decides whether a model is needed at all."""

from __future__ import annotations

import pytest

from aufla.mapping.router import (
    DiscoveryStrategy,
    LogFormat,
    detect_format,
    strip_syslog_header,
)

CEF = (
    "CEF:0|Palo Alto Networks|PAN-OS|10.2|traffic|TRAFFIC|3|"
    "src=10.0.0.5 dst=203.0.113.9 spt=51514 dpt=443"
)
LEEF = "LEEF:1.0|Lancope|StealthWatch|1.0|alert|src=10.0.0.5\tdst=1.2.3.4"
EVE = (
    '{"timestamp":"2026-09-17T10:00:00.000000+0000","event_type":"alert",'
    '"src_ip":"10.0.0.5","dest_ip":"203.0.113.9","alert":{"signature":"ET SCAN"}}'
)
FILTERLOG = (
    "5,,,1000000103,em0,match,block,in,4,0x0,,64,0,0,DF,6,tcp,60,"
    "198.18.0.9,10.0.0.5,45332,22,0"
)
SSHD = "Failed password for invalid user admin from 10.0.0.9 port 52344 ssh2"
KV = 'user=admin action=deny rule="block all" src=10.0.0.1 dst=10.0.0.2'


# --- syslog framing ------------------------------------------------------


def test_priority_is_stripped_and_decoded():
    body, pri, tag = strip_syslog_header("<134>hello")
    assert body == "hello"
    assert pri == 134


def test_rfc3164_header_yields_the_tag():
    line = "<134>Sep 17 10:00:00 fw01 filterlog[1234]: " + FILTERLOG
    body, pri, tag = strip_syslog_header(line)
    assert tag == "filterlog"
    assert body == FILTERLOG


def test_rfc5424_header_yields_the_app_name():
    line = "<134>1 2026-09-17T10:00:00Z fw01 suricata 1234 ID47 - " + EVE
    body, pri, tag = strip_syslog_header(line)
    assert tag == "suricata"
    assert body.endswith("}")


def test_an_angle_bracket_number_above_191_is_not_a_priority():
    # <999> cannot be a syslog PRI; treating it as one would eat real content.
    body, pri, _ = strip_syslog_header("<999>payload")
    assert pri is None
    assert body == "<999>payload"


def test_a_line_without_framing_is_returned_unchanged():
    body, pri, tag = strip_syslog_header(SSHD)
    assert body == SSHD
    assert pri is None and tag is None


# --- detection -----------------------------------------------------------


@pytest.mark.parametrize(
    "payload,expected",
    [
        (CEF, LogFormat.CEF),
        (LEEF, LogFormat.LEEF),
        (EVE, LogFormat.JSON),
        ("<?xml version='1.0'?><Event><System/></Event>", LogFormat.XML),
        (FILTERLOG, LogFormat.CSV),
        (KV, LogFormat.KEY_VALUE),
        (SSHD, LogFormat.SYSLOG_TEXT),
    ],
)
def test_formats_are_detected(payload, expected):
    assert detect_format(payload).format is expected


def test_detection_sees_through_syslog_framing():
    # A CEF payload wrapped in syslog is still CEF. Treating it as free text
    # would send it to the model for no reason at all.
    wrapped = "<134>Sep 17 10:00:00 fw01 CEF-forwarder: " + CEF
    assert detect_format(wrapped).format is LogFormat.CEF


def test_bytes_input_is_accepted():
    assert detect_format(EVE.encode()).format is LogFormat.JSON


def test_undecodable_bytes_do_not_crash_detection():
    assert detect_format(b"\xff\xfe broken \x00 bytes").format is not None


def test_empty_payload_is_unknown():
    d = detect_format("   ")
    assert d.format is LogFormat.UNKNOWN
    assert d.confidence == 0.0


# --- strategy routing ----------------------------------------------------


@pytest.mark.parametrize("payload", [CEF, LEEF, KV])
def test_self_describing_formats_never_reach_the_model(payload):
    d = detect_format(payload)
    assert d.strategy is DiscoveryStrategy.SPEC_PARSE
    assert d.needs_model is False


def test_json_uses_schema_walk_not_the_model():
    d = detect_format(EVE)
    assert d.strategy is DiscoveryStrategy.SCHEMA_WALK
    assert d.needs_model is False


def test_csv_is_positional_not_the_model():
    assert detect_format(FILTERLOG).strategy is DiscoveryStrategy.POSITIONAL


def test_only_free_text_reaches_the_model():
    d = detect_format(SSHD)
    assert d.strategy is DiscoveryStrategy.TEMPLATE_MINING
    assert d.needs_model is True


# --- hints ---------------------------------------------------------------


def test_json_detection_reports_top_level_keys():
    d = detect_format(EVE)
    assert "event_type" in d.hints["keys"]


def test_csv_detection_reports_column_count():
    assert detect_format(FILTERLOG).hints["columns"] == 23


def test_syslog_severity_and_facility_are_decoded():
    d = detect_format("<134>" + SSHD)
    assert d.syslog_pri == 134
    assert d.facility == 16   # local0
    assert d.severity == 6    # informational


def test_severity_is_none_without_a_priority():
    assert detect_format(SSHD).severity is None


def test_prose_with_commas_is_not_mistaken_for_csv():
    prose = (
        "Sep 17 10:00:00 host app: connection failed, retrying in 5 seconds, "
        "attempt 2 of 3, giving up soon"
    )
    assert detect_format(prose).format is not LogFormat.CSV
