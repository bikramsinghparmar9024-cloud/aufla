"""Identity primitives must be correct, or every guarantee above them fails."""

from __future__ import annotations

import uuid

from aufla.ids import (
    idempotency_key,
    sha256_hex,
    uuid7,
    uuid7_timestamp_ms,
)


def test_uuid7_has_correct_version_and_variant():
    u = uuid7()
    assert u.version == 7
    # RFC 9562 variant is 0b10xxxxxx in byte 8
    assert (u.bytes[8] & 0xC0) == 0x80


def test_uuid7_roundtrips_its_timestamp():
    ts = 1_757_000_000_000
    assert uuid7_timestamp_ms(uuid7(ts)) == ts


def test_uuid7_is_time_ordered_as_a_string():
    early = uuid7(1_000_000_000_000)
    late = uuid7(2_000_000_000_000)
    # Lexical order must match temporal order, which is what makes the raw
    # table cheap to range-scan.
    assert str(early) < str(late)


def test_uuid7_is_unique_within_the_same_millisecond():
    ts = 1_757_000_000_000
    ids = {uuid7(ts) for _ in range(5_000)}
    assert len(ids) == 5_000


def test_uuid7_rejects_out_of_range_timestamps():
    import pytest

    with pytest.raises(ValueError):
        uuid7(-1)
    with pytest.raises(ValueError):
        uuid7(1 << 48)


def test_uuid7_timestamp_rejects_other_versions():
    import pytest

    with pytest.raises(ValueError):
        uuid7_timestamp_ms(uuid.uuid4())


def test_sha256_matches_known_vector():
    # Standard NIST test vector for the empty string.
    assert sha256_hex(b"") == (
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    )


def test_idempotency_key_is_stable_for_identical_input():
    a = idempotency_key(b"payload", "fw01", 1234)
    b = idempotency_key(b"payload", "fw01", 1234)
    assert a == b


def test_idempotency_key_separates_every_component():
    base = idempotency_key(b"payload", "fw01", 1234)
    assert idempotency_key(b"payload!", "fw01", 1234) != base
    assert idempotency_key(b"payload", "fw02", 1234) != base
    assert idempotency_key(b"payload", "fw01", 1235) != base


def test_idempotency_key_cannot_be_confused_by_source_boundaries():
    # Without length-prefixing the source id, ("ab","c") and ("a","bc") could
    # hash identically. They must not.
    assert idempotency_key(b"x", "ab", 1) != idempotency_key(b"x", "a", 1)
