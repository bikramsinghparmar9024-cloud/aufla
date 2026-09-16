"""Validation: structure, types, and the semantic checks that catch swaps."""

from __future__ import annotations

import time

import pytest

from aufla.ocsf import get_class, validate_record
from aufla.ocsf.classes import CATALOG, OCSF_VERSION
from aufla.ocsf.validate import validate_mapping_targets

NOW_MS = int(time.time() * 1000)


def base(**overrides):
    record = {"time": NOW_MS}
    record.update(overrides)
    return record


# --- catalogue -----------------------------------------------------------


def test_catalogue_pins_a_version_and_the_four_perimeter_classes():
    assert OCSF_VERSION == "1.5.0"
    assert set(CATALOG) == {4001, 4002, 3002, 2004}


def test_unknown_class_fails_loudly_and_lists_what_is_supported():
    with pytest.raises(KeyError, match="4001"):
        get_class(9999)


def test_every_class_requires_a_time():
    for uid in CATALOG:
        assert "time" in get_class(uid).required_fields


# --- structure and types -------------------------------------------------


def test_a_clean_record_validates():
    report = validate_record(
        4001,
        base(**{
            "src_endpoint.ip": "10.0.0.5",
            "src_endpoint.port": "51514",
            "dst_endpoint.ip": "203.0.113.9",
            "dst_endpoint.port": "443",
            "traffic.bytes": "2048",
        }),
    )
    assert report.ok
    assert report.warnings == []
    assert report.coerced["dst_endpoint.port"] == 443
    assert report.coerced["traffic.bytes"] == 2048
    assert report.coverage == 1.0


def test_missing_required_time_is_an_error():
    report = validate_record(4001, {"src_endpoint.ip": "10.0.0.1"})
    assert not report.ok
    assert any("time" in e for e in report.errors)


def test_bad_port_is_reported_with_its_field_name():
    report = validate_record(4001, base(**{"dst_endpoint.port": "70000"}))
    assert not report.ok
    assert any(e.startswith("dst_endpoint.port") for e in report.errors)


def test_all_errors_are_collected_not_just_the_first():
    report = validate_record(
        4001,
        base(**{"dst_endpoint.port": "70000", "src_endpoint.ip": "999.1.1.1"}),
    )
    assert len(report.errors) == 2


# --- unmapped and coverage ----------------------------------------------


def test_vendor_extras_route_to_unmapped_rather_than_failing():
    report = validate_record(
        4001, base(**{"src_endpoint.ip": "10.0.0.1", "panos_rule_uuid": "abc"})
    )
    assert report.ok
    assert report.unmapped == {"panos_rule_uuid": "abc"}


def test_coverage_reports_the_share_that_found_an_ocsf_home():
    report = validate_record(
        4001, base(**{"src_endpoint.ip": "10.0.0.1", "vendor_x": 1, "vendor_y": 2})
    )
    # time + src ip mapped, two vendor fields not
    assert report.coverage == pytest.approx(0.5)


def test_explicit_unmapped_object_is_merged():
    report = validate_record(4001, base(unmapped={"foo": "bar"}))
    assert report.ok
    assert report.unmapped == {"foo": "bar"}


def test_unmapped_must_be_an_object():
    report = validate_record(4001, base(unmapped="oops"))
    assert not report.ok


def test_strict_mode_rejects_unknown_fields():
    report = validate_record(
        4001, base(**{"not_a_real_field": 1}), strict_unknown=True
    )
    assert not report.ok
    assert any("not_a_real_field" in e for e in report.errors)


def test_validate_mapping_targets_finds_bad_targets():
    bad = validate_mapping_targets(4001, ["src_endpoint.ip", "made.up.field"])
    assert bad == ["made.up.field"]


# --- semantics: the checks GBNF cannot perform ---------------------------


def test_identical_endpoints_warn_about_reading_one_column_twice():
    report = validate_record(
        4001,
        base(**{"src_endpoint.ip": "10.0.0.7", "dst_endpoint.ip": "10.0.0.7"}),
    )
    assert report.ok  # valid, but suspicious
    assert any("twice" in w for w in report.warnings)


def test_inverted_port_roles_warn_about_swapped_endpoints():
    # A server on an ephemeral port talking to a client on port 443 is the
    # signature of a mapping that read the columns backwards.
    report = validate_record(
        4001,
        base(**{
            "src_endpoint.ip": "10.0.0.5",
            "src_endpoint.port": 443,
            "dst_endpoint.ip": "203.0.113.9",
            "dst_endpoint.port": 51514,
        }),
    )
    assert report.ok
    assert any("swapped" in w for w in report.warnings)


def test_correct_port_roles_produce_no_swap_warning():
    report = validate_record(
        4001,
        base(**{
            "src_endpoint.ip": "10.0.0.5",
            "src_endpoint.port": 51514,
            "dst_endpoint.ip": "203.0.113.9",
            "dst_endpoint.port": 443,
        }),
    )
    assert not any("swapped" in w for w in report.warnings)


def test_two_globally_routable_endpoints_warn_at_a_perimeter_device():
    report = validate_record(
        4001,
        base(**{"src_endpoint.ip": "8.8.8.8", "dst_endpoint.ip": "1.1.1.1"}),
    )
    assert any("globally routable" in w for w in report.warnings)


def test_two_internal_endpoints_do_not_warn():
    # Normal on a segmentation firewall; only a missing internal side is odd.
    report = validate_record(
        4001,
        base(**{"src_endpoint.ip": "10.0.0.5", "dst_endpoint.ip": "10.0.1.9"}),
    )
    assert not any("globally routable" in w for w in report.warnings)


def test_documentation_ranges_are_not_treated_as_internal():
    # ipaddress.is_private is True for TEST-NET blocks, which would make this
    # heuristic silently wrong. is_global is the correct primitive.
    from aufla.ocsf.validate import _is_globally_routable

    assert not _is_globally_routable("203.0.113.9")   # TEST-NET-3
    assert not _is_globally_routable("10.0.0.1")      # RFC 1918
    assert _is_globally_routable("8.8.8.8")


def test_byte_counts_that_do_not_add_up_warn():
    report = validate_record(
        4001,
        base(**{
            "traffic.bytes": 100,
            "traffic.bytes_in": 90,
            "traffic.bytes_out": 90,
        }),
    )
    assert any("exceeds" in w for w in report.warnings)


def test_device_clock_drift_is_flagged():
    report = validate_record(
        4001,
        {"time": NOW_MS - 6 * 3_600_000, "observed_time": NOW_MS},
    )
    assert report.ok
    assert any("clock differs" in w for w in report.warnings)


def test_small_clock_drift_is_tolerated():
    report = validate_record(
        4001, {"time": NOW_MS - 60_000, "observed_time": NOW_MS}
    )
    assert report.warnings == []


def test_warnings_never_reject_a_record():
    # Real traffic is strange; dropping odd events during an incident is worse
    # than useless. Warnings downgrade trust in the mapping, not the event.
    report = validate_record(
        4001,
        base(**{
            "src_endpoint.ip": "10.0.0.7",
            "dst_endpoint.ip": "10.0.0.7",
            "src_endpoint.port": 80,
            "dst_endpoint.port": 60000,
        }),
    )
    assert report.ok
    assert len(report.warnings) >= 2


# --- other classes -------------------------------------------------------


def test_http_activity_fields():
    report = validate_record(
        4002,
        base(**{
            "http_request.url.text": "https://intranet.test/x",
            "http_request.http_method": "GET",
            "http_response.code": "200",
        }),
    )
    assert report.ok
    assert report.coerced["http_response.code"] == 200


def test_authentication_fields():
    report = validate_record(
        3002, base(**{"user.name": "bsingh", "is_mfa": "yes"})
    )
    assert report.ok
    assert report.coerced["is_mfa"] is True


def test_detection_finding_fields():
    report = validate_record(
        2004, base(**{"finding_info.title": "Port scan", "risk_level_id": "3"})
    )
    assert report.ok
    assert report.coerced["risk_level_id"] == 3
