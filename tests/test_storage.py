"""The raw store is append-only and race-free on redelivery."""

from __future__ import annotations

import uuid

import pytest

from aufla.models import RawEvent, Transport
from aufla.storage import SQLiteRawStore


@pytest.fixture()
def store():
    s = SQLiteRawStore(":memory:")
    yield s
    s.close()


def test_append_and_read_back_exactly(store):
    e = RawEvent.capture(b"deny 10.0.0.1", "fw01", transport=Transport.TCP)
    stats = store.append([e])

    assert stats.accepted == 1
    assert stats.duplicates == 0

    got = store.get(e.event_uid)
    assert got is not None
    assert got.raw_bytes == e.raw_bytes
    assert got.raw_hash == e.raw_hash
    assert got.verify()


def test_binary_payload_survives_a_storage_round_trip(store):
    # Bytes that are not valid UTF-8 and include a NUL, which naive text
    # storage would truncate at.
    payload = bytes(range(256))
    e = RawEvent.capture(payload, "weird01")
    store.append([e])

    got = store.get(e.event_uid)
    assert got is not None
    assert got.raw_bytes == payload
    assert got.byte_len == 256


def test_redelivery_is_deduplicated(store):
    e = RawEvent.capture(b"same", "fw01", received_at_ns=1_000)

    first = store.append([e])
    second = store.append([e])  # the buffer replayed it

    assert first.accepted == 1
    assert second.accepted == 0
    assert second.duplicates == 1
    assert store.count() == 1


def test_duplicates_within_a_single_batch_are_collapsed(store):
    e = RawEvent.capture(b"same", "fw01", received_at_ns=1_000)
    stats = store.append([e, e, e])

    assert stats.accepted == 1
    assert stats.duplicates == 2
    assert store.count() == 1


def test_identical_payloads_at_different_times_are_both_kept(store):
    a = RawEvent.capture(b"repeat", "fw01", received_at_ns=1_000)
    b = RawEvent.capture(b"repeat", "fw01", received_at_ns=2_000)
    stats = store.append([a, b])

    assert stats.accepted == 2
    assert store.count() == 2


def test_empty_append_is_a_no_op(store):
    stats = store.append([])
    assert stats.accepted == 0
    assert stats.duplicates == 0
    assert store.count() == 0


def test_get_missing_event_returns_none(store):
    assert store.get(uuid.uuid4()) is None


def test_iteration_is_in_arrival_order(store):
    events = [
        RawEvent.capture(f"event-{i}".encode(), "fw01", received_at_ns=i * 1_000)
        for i in range(10)
    ]
    store.append(reversed(events))  # inserted out of order on purpose

    seen = [e.raw_bytes for e in store.iter_events()]
    assert seen == [e.raw_bytes for e in events]


def test_iteration_filters_by_source_and_time(store):
    store.append(
        [
            RawEvent.capture(b"a", "fw01", received_at_ns=1_000),
            RawEvent.capture(b"b", "fw02", received_at_ns=2_000),
            RawEvent.capture(b"c", "fw01", received_at_ns=3_000),
        ]
    )

    assert len(list(store.iter_events(source_id="fw01"))) == 2
    assert len(list(store.iter_events(since_ns=2_000))) == 2
    assert len(list(store.iter_events(since_ns=2_000, until_ns=3_000))) == 1
    assert len(list(store.iter_events(limit=1))) == 1


def test_metadata_round_trips(store):
    e = RawEvent.capture(
        b"x",
        "fw01",
        source_ip="10.1.2.3",
        transport=Transport.RELP,
        charset="utf-8",
    )
    store.append([e])

    got = store.get(e.event_uid)
    assert got is not None
    assert got.source_ip == "10.1.2.3"
    assert got.transport is Transport.RELP
    assert got.charset == "utf-8"


def test_store_works_as_a_context_manager(tmp_path):
    db = tmp_path / "nested" / "aufla.db"
    with SQLiteRawStore(db) as s:
        s.append([RawEvent.capture(b"persisted", "fw01")])
        assert s.count() == 1
    assert db.exists()


def test_data_persists_across_reopen(tmp_path):
    db = tmp_path / "aufla.db"
    e = RawEvent.capture(b"durable", "fw01")

    with SQLiteRawStore(db) as s:
        s.append([e])

    with SQLiteRawStore(db) as s:
        got = s.get(e.event_uid)
        assert got is not None
        assert got.raw_bytes == b"durable"
        # and redelivery is still caught after a restart
        assert s.append([e]).duplicates == 1
