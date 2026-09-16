"""Parsers expose positional and named access over every supported format."""

from __future__ import annotations

import pytest

from aufla.normalize.parsers import ParseError, parse_body


def test_csv_is_one_indexed():
    p = parse_body("a,b,c", "csv")
    assert p.get_positional(1) == "a"
    assert p.get_positional(3) == "c"


def test_csv_out_of_range_is_none_not_an_error():
    p = parse_body("a,b", "csv")
    assert p.get_positional(9) is None
    assert p.get_positional(0) is None


def test_csv_empty_field_reads_as_none():
    # pfSense leaves many columns empty; "" is absence, not a value.
    p = parse_body("a,,c", "csv")
    assert p.get_positional(2) is None


def test_csv_honours_quoting():
    p = parse_body('a,"b,still b",c', "csv")
    assert p.get_positional(2) == "b,still b"


def test_ssv_splits_on_whitespace_runs():
    p = parse_body("1758100000.123    42 10.0.0.5  TCP_MISS/200", "ssv")
    assert p.get_positional(1) == "1758100000.123"
    assert p.get_positional(4) == "TCP_MISS/200"


def test_json_flattens_for_dotted_access():
    body = '{"event_type":"alert","alert":{"signature":"ET SCAN","severity":2}}'
    p = parse_body(body, "json")
    assert p.get_named("event_type") == "alert"
    assert p.get_named("alert.signature") == "ET SCAN"
    assert p.get_named("alert.severity") == 2


def test_json_array_indexing():
    p = parse_body('{"ips":["10.0.0.1","10.0.0.2"]}', "json")
    assert p.get_named("ips.1") == "10.0.0.2"


def test_json_missing_path_is_none():
    p = parse_body('{"a":{"b":1}}', "json")
    assert p.get_named("a.z") is None
    assert p.get_named("nope.at.all") is None


def test_json_literal_dotted_key_wins_over_traversal():
    # Vendors really do emit keys containing dots.
    p = parse_body('{"src.ip":"10.0.0.1","src":{"ip":"10.0.0.9"}}', "json")
    assert p.get_named("src.ip") == "10.0.0.1"


def test_json_must_be_an_object():
    with pytest.raises(ParseError, match="must be an object"):
        parse_body("[1,2,3]", "json")


def test_invalid_json_raises_parse_error():
    with pytest.raises(ParseError, match="JSON"):
        parse_body("{not json", "json")


def test_key_value_pairs_with_quotes():
    p = parse_body('user=admin rule="block all" src=10.0.0.1', "kv")
    assert p.get_named("user") == "admin"
    assert p.get_named("rule") == "block all"
    assert p.get_named("src") == "10.0.0.1"


def test_key_value_requires_at_least_one_pair():
    with pytest.raises(ParseError):
        parse_body("no pairs here", "kv")


def test_cef_header_is_positional_and_extensions_named():
    body = (
        "CEF:0|Palo Alto Networks|PAN-OS|10.2|traffic|TRAFFIC|3|"
        "src=10.0.0.5 dst=203.0.113.9 spt=51514 dpt=443"
    )
    p = parse_body(body, "cef")
    assert p.get_positional(1) == "0"          # CEF version
    assert p.get_positional(2) == "Palo Alto Networks"
    assert p.get_positional(6) == "TRAFFIC"    # Name
    assert p.get_positional(7) == "3"          # Severity
    assert p.get_named("dpt") == "443"


def test_cef_honours_escaped_pipes_in_the_name():
    body = "CEF:0|V|P|1.0|100|deny\\|drop|5|src=10.0.0.1"
    p = parse_body(body, "cef")
    assert p.get_positional(6) == "deny|drop"
    assert p.get_named("src") == "10.0.0.1"


def test_cef_with_too_few_segments_is_rejected():
    with pytest.raises(ParseError, match="8 segments"):
        parse_body("CEF:0|V|P|1.0", "cef")


def test_leef_v1_uses_tab_delimited_attributes():
    body = "LEEF:1.0|Lancope|StealthWatch|1.0|alert|src=10.0.0.5\tdst=1.2.3.4"
    p = parse_body(body, "leef")
    assert p.get_positional(2) == "Lancope"
    assert p.get_named("src") == "10.0.0.5"
    assert p.get_named("dst") == "1.2.3.4"


def test_leef_v2_custom_delimiter():
    body = "LEEF:2.0|V|P|1.0|evt|^|src=10.0.0.5^dst=1.2.3.4"
    p = parse_body(body, "leef")
    assert p.get_named("dst") == "1.2.3.4"


def test_xml_attributes_and_text():
    body = (
        "<Event><System><EventID>4625</EventID>"
        "<Provider Name='Security'/></System></Event>"
    )
    p = parse_body(body, "xml")
    assert p.get_named("System.EventID") == "4625"
    assert p.get_named("System.Provider.@Name") == "Security"


def test_xml_namespaces_are_dropped():
    body = "<e xmlns='urn:x'><a>1</a></e>"
    assert parse_body(body, "xml").get_named("a") == "1"


def test_invalid_xml_raises_parse_error():
    with pytest.raises(ParseError, match="XML"):
        parse_body("<unclosed>", "xml")


def test_unknown_format_names_the_known_ones():
    with pytest.raises(ParseError, match="known:"):
        parse_body("x", "sqlite")
