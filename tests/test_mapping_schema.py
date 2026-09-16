"""The mapping artifact: parsing, validation, and content identity."""

from __future__ import annotations

import pytest

from aufla.mapping.schema import (
    Condition,
    ConditionOp,
    FieldRef,
    FieldSpec,
    Mapping,
    MappingError,
    RefKind,
)

MINIMAL = """
source: demo
format: csv
rules:
  - name: only
    ocsf_class: 4001
    fields:
      src_endpoint.ip: $1
"""


# --- field references ----------------------------------------------------


def test_positional_reference():
    ref = FieldRef.parse("$7")
    assert ref.kind is RefKind.POSITIONAL
    assert ref.value == 7


def test_named_reference_supports_dots():
    ref = FieldRef.parse("$alert.signature")
    assert ref.kind is RefKind.NAMED
    assert ref.value == "alert.signature"


def test_bare_text_is_a_literal():
    assert FieldRef.parse("pfSense") == FieldRef(RefKind.LITERAL, "pfSense")


def test_numbers_are_literals():
    assert FieldRef.parse(4001).value == 4001


def test_double_dollar_escapes_a_literal():
    assert FieldRef.parse("$$7") == FieldRef(RefKind.LITERAL, "$7")


def test_zero_index_is_rejected_because_fields_are_one_indexed():
    with pytest.raises(MappingError, match="1-indexed"):
        FieldRef.parse("$0")


def test_malformed_reference_is_rejected():
    with pytest.raises(MappingError, match="malformed"):
        FieldRef.parse("$ bad")


# --- field specs ---------------------------------------------------------


def test_long_form_field_spec():
    spec = FieldSpec.parse({"from": "$2", "transform": "iso8601", "tz": "UTC"})
    assert spec.ref.value == 2
    assert spec.transform == "iso8601"
    assert spec.timezone == "UTC"


def test_field_spec_requires_from():
    with pytest.raises(MappingError, match="missing 'from'"):
        FieldSpec.parse({"transform": "iso8601"})


def test_field_spec_rejects_unknown_keys():
    with pytest.raises(MappingError, match="unknown keys"):
        FieldSpec.parse({"from": "$1", "tranfsorm": "typo"})


# --- conditions ----------------------------------------------------------


def test_condition_parses_operator():
    cond = Condition.parse({"field": "$7", "equals": "block"})
    assert cond.op is ConditionOp.EQUALS
    assert cond.value == "block"


def test_condition_rejects_two_operators():
    with pytest.raises(MappingError, match="more than one operator"):
        Condition.parse({"field": "$7", "equals": "a", "contains": "b"})


def test_condition_rejects_no_operator():
    with pytest.raises(MappingError, match="no operator"):
        Condition.parse({"field": "$7"})


def test_condition_validates_regex_at_parse_time():
    with pytest.raises(MappingError, match="invalid regex"):
        Condition.parse({"field": "$7", "regex": "([unclosed"})


def test_in_requires_a_list():
    with pytest.raises(MappingError, match="list"):
        Condition.parse({"field": "$7", "in": "not-a-list"})


# --- mappings ------------------------------------------------------------


def test_minimal_mapping_parses():
    m = Mapping.from_yaml(MINIMAL)
    assert m.source == "demo"
    assert m.format == "csv"
    assert len(m.rules) == 1
    assert m.ocsf_version == "1.5.0"


def test_unknown_ocsf_target_is_rejected():
    # This is what makes "fields cannot be invented" true even for a human
    # author, not only for the grammar-constrained model.
    bad = MINIMAL.replace("src_endpoint.ip", "src_endpoint.ipv4")
    with pytest.raises(MappingError, match="not fields of OCSF class 4001"):
        Mapping.from_yaml(bad)


def test_unknown_ocsf_class_is_rejected():
    bad = MINIMAL.replace("4001", "9999")
    with pytest.raises(MappingError, match="9999"):
        Mapping.from_yaml(bad)


def test_missing_source_is_rejected():
    with pytest.raises(MappingError, match="source"):
        Mapping.from_yaml("format: csv\nrules: []\n")


def test_empty_rules_is_rejected():
    with pytest.raises(MappingError, match="non-empty"):
        Mapping.from_yaml("source: d\nformat: csv\nrules: []\n")


def test_duplicate_rule_names_are_rejected():
    dup = """
source: demo
format: csv
rules:
  - name: same
    match: { field: $1, equals: a }
    ocsf_class: 4001
    fields: { src_endpoint.ip: $2 }
  - name: same
    ocsf_class: 4001
    fields: { src_endpoint.ip: $2 }
"""
    with pytest.raises(MappingError, match="duplicate rule names"):
        Mapping.from_yaml(dup)


def test_a_catch_all_rule_may_not_shadow_later_rules():
    shadowing = """
source: demo
format: csv
rules:
  - name: catch_all
    ocsf_class: 4001
    fields: { src_endpoint.ip: $1 }
  - name: never_reached
    match: { field: $7, equals: block }
    ocsf_class: 4001
    fields: { src_endpoint.ip: $1 }
"""
    with pytest.raises(MappingError, match="shadow"):
        Mapping.from_yaml(shadowing)


def test_invalid_yaml_is_reported_clearly():
    with pytest.raises(MappingError, match="invalid YAML"):
        Mapping.from_yaml("source: [unclosed\n")


def test_version_must_be_a_positive_integer():
    with pytest.raises(MappingError, match="positive integer"):
        Mapping.from_yaml(MINIMAL + "version: 0\n")


def test_confidence_must_be_within_range():
    with pytest.raises(MappingError, match="0.0-1.0"):
        Mapping.from_yaml(MINIMAL + "confidence: 1.4\n")


def test_approval_gates_effectiveness():
    assert not Mapping.from_yaml(MINIMAL).is_approved
    assert Mapping.from_yaml(MINIMAL + "approved_by: analyst-7\n").is_approved


# --- content hashing -----------------------------------------------------


def test_content_hash_is_stable():
    a = Mapping.from_yaml(MINIMAL)
    b = Mapping.from_yaml(MINIMAL)
    assert a.content_hash() == b.content_hash()


def test_content_hash_ignores_comments_and_key_order():
    reordered = """
# a comment that should not matter
format: csv
source: demo
rules:
  - fields:
      src_endpoint.ip: $1
    ocsf_class: 4001
    name: only
"""
    assert Mapping.from_yaml(MINIMAL).content_hash() == (
        Mapping.from_yaml(reordered).content_hash()
    )


def test_content_hash_changes_when_semantics_change():
    base = Mapping.from_yaml(MINIMAL).content_hash()
    changed = Mapping.from_yaml(MINIMAL.replace("$1", "$2")).content_hash()
    assert base != changed


def test_content_hash_tracks_version():
    base = Mapping.from_yaml(MINIMAL).content_hash()
    bumped = Mapping.from_yaml(MINIMAL + "version: 2\n").content_hash()
    assert base != bumped


def test_ocsf_classes_are_deduplicated_in_order():
    multi = """
source: demo
format: json
rules:
  - name: a
    match: { field: $t, equals: x }
    ocsf_class: 2004
    fields: { finding_info.title: $s }
  - name: b
    match: { field: $t, equals: y }
    ocsf_class: 4001
    fields: { src_endpoint.ip: $ip }
  - name: c
    ocsf_class: 2004
    fields: { finding_info.title: $s }
"""
    assert Mapping.from_yaml(multi).ocsf_classes == (2004, 4001)
