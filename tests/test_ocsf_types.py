"""Type coercion is the range check that GBNF cannot perform."""

from __future__ import annotations

import time

import pytest

from aufla.ocsf.types import FieldType, coerce


# --- ports ---------------------------------------------------------------


@pytest.mark.parametrize("raw,expected", [("443", 443), (443, 443), (" 80 ", 80)])
def test_valid_ports_coerce(raw, expected):
    result = coerce(raw, FieldType.PORT)
    assert result.ok
    assert result.value == expected
    assert result.error == ""


@pytest.mark.parametrize("bad", ["70000", "0", "-1", "https", "44 3", ""])
def test_invalid_ports_are_rejected(bad):
    result = coerce(bad, FieldType.PORT)
    assert not result.ok
    assert result.error


def test_port_error_names_the_range():
    # This is the check that catches a model confidently writing 70000.
    assert "1-65535" in coerce("70000", FieldType.PORT).error


# --- addresses -----------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("10.0.0.1", "10.0.0.1"),
        ("10.0.0.1:443", "10.0.0.1"),        # vendors append the port
        ("2001:db8::1", "2001:db8::1"),
        ("::1", "::1"),
    ],
)
def test_valid_ips_coerce(raw, expected):
    assert coerce(raw, FieldType.IP).value == expected


@pytest.mark.parametrize("bad", ["999.1.1.1", "10.0.0", "not-an-ip", ""])
def test_invalid_ips_are_rejected(bad):
    assert not coerce(bad, FieldType.IP).ok


@pytest.mark.parametrize(
    "raw", ["AA:BB:CC:DD:EE:FF", "aa-bb-cc-dd-ee-ff", "aabbccddeeff"]
)
def test_mac_formats_normalise_to_one_form(raw):
    assert coerce(raw, FieldType.MAC).value == "aa:bb:cc:dd:ee:ff"


@pytest.mark.parametrize("bad", ["AA:BB:CC:DD:EE", "ZZ:BB:CC:DD:EE:FF", "1234"])
def test_invalid_macs_are_rejected(bad):
    assert not coerce(bad, FieldType.MAC).ok


# --- timestamps ----------------------------------------------------------


def test_plausible_timestamp_is_accepted():
    now_ms = int(time.time() * 1000)
    assert coerce(now_ms, FieldType.TIMESTAMP).ok


def test_epoch_zero_is_rejected_as_a_clock_fault():
    result = coerce(0, FieldType.TIMESTAMP)
    assert not result.ok
    assert "2000-01-01" in result.error


def test_far_future_timestamp_is_rejected():
    far = int((time.time() + 86_400 * 365) * 1000)
    result = coerce(far, FieldType.TIMESTAMP)
    assert not result.ok
    assert "future" in result.error


def test_seconds_mistaken_for_milliseconds_is_caught():
    # A mapping that forgot to multiply by 1000 yields a 1970s date.
    assert not coerce(int(time.time()), FieldType.TIMESTAMP).ok


# --- scalars -------------------------------------------------------------


def test_booleans_accept_vendor_vocabulary():
    for yes in ("true", "yes", "1", "allow", "SUCCESS"):
        assert coerce(yes, FieldType.BOOLEAN).value is True
    for no in ("false", "no", "0", "deny", "FAILURE"):
        assert coerce(no, FieldType.BOOLEAN).value is False


def test_bool_is_not_silently_an_integer():
    assert not coerce(True, FieldType.INTEGER).ok


def test_integers_reject_floats_and_text():
    assert coerce("42", FieldType.INTEGER).value == 42
    assert not coerce("4.2", FieldType.INTEGER).ok
    assert not coerce("many", FieldType.INTEGER).ok


def test_strings_reject_empty_but_keep_whitespace_content():
    assert not coerce("", FieldType.STRING).ok
    assert coerce("  padded  ", FieldType.STRING).value == "  padded  "


def test_hostname_and_email_and_url():
    assert coerce("host.example.com", FieldType.HOSTNAME).ok
    assert not coerce("-bad.example.com", FieldType.HOSTNAME).ok
    assert coerce("a@b.com", FieldType.EMAIL).ok
    assert not coerce("a@b", FieldType.EMAIL).ok
    assert coerce("https://x.test/a", FieldType.URL).ok
    assert not coerce("/just/a/path", FieldType.URL).ok


def test_none_is_always_invalid():
    for ft in FieldType:
        assert not coerce(None, ft).ok
