"""The raw event is the permanent record. These tests defend that claim."""

from __future__ import annotations

import pytest

from aufla.models import RawEvent, Transport


def test_capture_assigns_the_full_identity_triple():
    e = RawEvent.capture(b"hello", "fw01")
    assert e.event_uid.version == 7
    assert len(e.raw_hash) == 64
    assert len(e.idem_key) == 64
    assert e.byte_len == 5


def test_capture_refuses_str_because_decoding_loses_data():
    with pytest.raises(TypeError, match="bytes-like"):
        RawEvent.capture("already decoded", "fw01")  # type: ignore[arg-type]


def test_capture_requires_a_source_id():
    with pytest.raises(ValueError):
        RawEvent.capture(b"x", "")


def test_undecodable_bytes_survive_capture_intact():
    # A latin-1 byte that is illegal UTF-8. A naive pipeline destroys this.
    payload = b"user=jos\xe9 action=deny"
    e = RawEvent.capture(payload, "fw01")

    assert e.raw_bytes == payload          # pristine
    assert e.verify()                       # hash still matches
    assert "�" in e.text()             # text view degrades, bytes do not
    assert e.raw_bytes == payload           # and the view did not mutate them


def test_raw_event_is_immutable():
    e = RawEvent.capture(b"x", "fw01")
    with pytest.raises(Exception):
        e.source_id = "other"  # type: ignore[misc]


def test_verify_detects_substituted_bytes():
    import dataclasses

    e = RawEvent.capture(b"original", "fw01")
    tampered = dataclasses.replace(e, raw_bytes=b"tampered")
    assert e.verify()
    assert not tampered.verify()


def test_udp_at_the_rfc3164_limit_is_flagged_as_possibly_truncated():
    e = RawEvent.capture(b"a" * 1024, "fw01", transport=Transport.UDP)
    assert e.truncated is True


def test_tcp_at_the_same_size_is_not_flagged():
    e = RawEvent.capture(b"a" * 1024, "fw01", transport=Transport.TCP)
    assert e.truncated is False


def test_explicit_truncation_flag_overrides_inference():
    e = RawEvent.capture(b"short", "fw01", transport=Transport.UDP, truncated=True)
    assert e.truncated is True


def test_two_identical_payloads_are_two_distinct_events():
    a = RawEvent.capture(b"same", "fw01", received_at_ns=1_000)
    b = RawEvent.capture(b"same", "fw01", received_at_ns=2_000)
    assert a.event_uid != b.event_uid       # distinct events
    assert a.raw_hash == b.raw_hash          # identical content
    assert a.idem_key != b.idem_key          # not redelivery


def test_received_at_iso_keeps_nanosecond_precision():
    e = RawEvent.capture(b"x", "fw01", received_at_ns=1_757_000_000_123_456_789)
    assert e.received_at_iso.endswith(".123456789Z")
    assert e.received_at_iso.startswith("2025-")
