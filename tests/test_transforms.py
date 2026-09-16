"""Transforms and lookups are closed sets, so a mapping cannot invent one."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from aufla.normalize.transforms import (
    TransformError,
    apply_lookup,
    apply_transform,
    syslog_time_to_ms,
)


def test_iso8601_with_offset_and_z():
    a = apply_transform("iso8601", "2026-09-17T10:00:00+00:00")
    b = apply_transform("iso8601", "2026-09-17T10:00:00Z")
    assert a == b


def test_iso8601_accepts_offset_without_a_colon():
    # Suricata emits +0000, which datetime.fromisoformat rejects on 3.10.
    assert apply_transform("iso8601", "2026-09-17T10:00:00.000000+0000") == (
        apply_transform("iso8601", "2026-09-17T10:00:00Z")
    )


def test_naive_iso8601_is_treated_as_utc():
    assert apply_transform("iso8601", "2026-09-17T10:00:00") > 0


def test_bad_iso8601_raises():
    with pytest.raises(TransformError, match="ISO-8601"):
        apply_transform("iso8601", "yesterday")


def test_epoch_seconds_becomes_milliseconds():
    assert apply_transform("epoch_seconds", "1758100000.5") == 1758100000500


def test_syslog_time_infers_the_current_year():
    ref = datetime(2026, 9, 17, 12, 0, tzinfo=timezone.utc)
    ms = syslog_time_to_ms("Sep 17 10:00:00", reference=ref)
    assert datetime.fromtimestamp(ms / 1000, timezone.utc).year == 2026


def test_syslog_time_handles_the_new_year_rollover():
    # On 2 January, a "Dec 31" line is from last year. Assuming the reference
    # year would date it twelve months in the future.
    ref = datetime(2026, 1, 2, 3, 0, tzinfo=timezone.utc)
    ms = syslog_time_to_ms("Dec 31 23:50:00", reference=ref)
    assert datetime.fromtimestamp(ms / 1000, timezone.utc).year == 2025


def test_syslog_time_rejects_nonsense():
    with pytest.raises(TransformError, match="RFC 3164"):
        syslog_time_to_ms("not a date")


def test_syslog_time_rejects_an_impossible_day():
    with pytest.raises(TransformError, match="invalid date"):
        syslog_time_to_ms("Feb 30 10:00:00")


def test_after_slash_extracts_the_squid_status():
    assert apply_transform("after_slash", "TCP_MISS/200") == "200"
    assert apply_transform("after_slash", "200") == "200"


def test_strip_port_leaves_ipv6_alone():
    assert apply_transform("strip_port", "10.0.0.1:443") == "10.0.0.1"
    assert apply_transform("strip_port", "2001:db8::1") == "2001:db8::1"


def test_unknown_transform_lists_the_known_ones():
    with pytest.raises(TransformError, match="known:"):
        apply_transform("teleport", "x")


def test_lookup_maps_suricata_severity_to_ocsf():
    assert apply_lookup("suricata_severity", "1") == 4   # high
    assert apply_lookup("suricata_severity", 3) == 2     # low


def test_lookup_is_case_insensitive():
    assert apply_lookup("http_method_activity", "get") == 3
    assert apply_lookup("http_method_activity", "GET") == 3


def test_lookup_miss_returns_the_default():
    assert apply_lookup("http_method_activity", "BREW", default=0) == 0
    assert apply_lookup("http_method_activity", "BREW") is None


def test_unknown_lookup_lists_the_known_ones():
    with pytest.raises(TransformError, match="known:"):
        apply_lookup("astrology", "x")


def test_firewall_dispositions_cover_common_verdicts():
    for allowed in ("allow", "pass", "accept", "permit"):
        assert apply_lookup("firewall_disposition", allowed) == 1
    for blocked in ("block", "deny", "drop", "reject"):
        assert apply_lookup("firewall_disposition", blocked) == 2
