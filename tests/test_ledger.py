"""The ledger: chaining, signing, and detection of real tampering."""

from __future__ import annotations

import sqlite3

import pytest

from aufla.ledger import Ledger
from aufla.ledger.ledger import GENESIS
from aufla.ledger.signing import KeyPair, SigningError
from aufla.models import RawEvent
from aufla.storage import SQLiteRawStore


def events(n: int, start: int = 0) -> list[RawEvent]:
    return [
        RawEvent.capture(
            f"event number {i}".encode(), "fw01", received_at_ns=1_000 + i
        )
        for i in range(start, start + n)
    ]


@pytest.fixture()
def keys():
    return KeyPair.generate("batch"), KeyPair.generate("checkpoint")


@pytest.fixture()
def ledger(keys):
    batch_key, checkpoint_key = keys
    led = Ledger(
        ":memory:", batch_key=batch_key, checkpoint_key=checkpoint_key, batch_size=10
    )
    yield led
    led.close()


# --- signing -------------------------------------------------------------


def test_signature_round_trips():
    kp = KeyPair.generate("t")
    payload = {"b": 2, "a": 1}
    assert kp.verify(payload, kp.sign(payload))


def test_signature_is_key_order_independent():
    kp = KeyPair.generate("t")
    sig = kp.sign({"a": 1, "b": 2})
    assert kp.verify({"b": 2, "a": 1}, sig)


def test_signature_fails_on_altered_payload():
    kp = KeyPair.generate("t")
    sig = kp.sign({"a": 1})
    assert not kp.verify({"a": 2}, sig)


def test_a_public_only_key_cannot_sign():
    kp = KeyPair.generate("t")
    verify_only = KeyPair.from_public_hex(kp.public_hex)
    assert verify_only.verify({"a": 1}, kp.sign({"a": 1}))
    with pytest.raises(SigningError, match="verify-only"):
        verify_only.sign({"a": 1})


def test_keys_persist_to_disk(tmp_path):
    from aufla.ledger.signing import load_or_create_keypair

    path = tmp_path / "keys" / "batch.pem"
    first = load_or_create_keypair(path, "batch")
    again = load_or_create_keypair(path, "batch")
    assert first.public_hex == again.public_hex


def test_a_malformed_public_key_is_rejected():
    with pytest.raises(SigningError, match="hex"):
        KeyPair.from_public_hex("nothex")


# --- chaining ------------------------------------------------------------


def test_first_batch_chains_to_genesis(ledger):
    ledger.add(events(3))
    batch = ledger.seal()
    assert batch.batch_id == 1
    assert batch.prev_root == GENESIS
    assert batch.leaf_count == 3


def test_each_batch_chains_to_the_previous_root(ledger):
    ledger.add(events(2))
    first = ledger.seal()
    ledger.add(events(2, start=100))
    second = ledger.seal()
    assert second.prev_root == first.root
    assert ledger.head == second.root


def test_batches_seal_automatically_at_the_size_threshold(ledger):
    sealed = ledger.add(events(25))    # batch_size is 10
    assert len(sealed) == 2
    assert ledger.batch_count == 2
    assert ledger.event_count == 20    # five still pending


def test_batches_are_signed(ledger, keys):
    ledger.add(events(3))
    batch = ledger.seal()
    assert batch.signature
    assert KeyPair.from_public_hex(batch.signer).verify(batch.payload(), batch.signature)


def test_mapping_hashes_are_committed_into_the_batch(ledger):
    # This is what makes the derivation provable: for any normalised row you
    # can show which mapping version was in force when its event was sealed.
    ledger.add(events(2), mapping_set={"pfsense": "a" * 64})
    batch = ledger.seal(mapping_set={"pfsense": "a" * 64})
    assert batch.mapping_set == {"pfsense": "a" * 64}
    assert ledger.get_batch(1).mapping_set == {"pfsense": "a" * 64}


def test_events_can_be_located_in_the_chain(ledger):
    evs = events(5)
    ledger.add(evs)
    ledger.seal()
    located = ledger.locate(str(evs[2].event_uid))
    assert located == (1, 2)


def test_an_unsealed_event_is_not_located(ledger):
    assert ledger.locate(str(events(1)[0].event_uid)) is None


# --- verification --------------------------------------------------------


def test_an_untouched_chain_verifies(ledger):
    for i in range(4):
        ledger.add(events(5, start=i * 5))
        ledger.seal()

    result = ledger.verify()
    assert result.ok
    assert result.batches_checked == 4
    assert result.events_checked == 20
    assert "PASS" in str(result)


def test_verification_against_the_raw_store(ledger):
    store = SQLiteRawStore(":memory:")
    evs = events(6)
    store.append(evs)
    ledger.add(evs)
    ledger.seal()

    assert ledger.verify(store=store).ok
    store.close()


def test_a_deleted_event_is_detected(ledger):
    # The headline demo: delete one row, re-run verify, watch it fail.
    store = SQLiteRawStore(":memory:")
    evs = events(6)
    store.append(evs)
    ledger.add(evs)
    ledger.seal()

    store._conn.execute(
        "DELETE FROM raw_events WHERE event_uid = ?", (str(evs[3].event_uid),)
    )
    store._conn.commit()

    result = ledger.verify(store=store)
    assert not result.ok
    assert result.first_divergence == 1
    assert "missing" in result.reason
    assert "FAIL" in str(result)
    store.close()


def test_a_modified_event_body_is_detected(ledger):
    store = SQLiteRawStore(":memory:")
    evs = events(4)
    store.append(evs)
    ledger.add(evs)
    ledger.seal()

    store._conn.execute(
        "UPDATE raw_events SET raw_bytes = ? WHERE event_uid = ?",
        (b"tampered payload", str(evs[1].event_uid)),
    )
    store._conn.commit()

    result = ledger.verify(store=store)
    assert not result.ok
    assert "no longer hashes" in result.reason
    store.close()


def test_a_modified_body_with_a_matching_hash_is_still_detected(ledger):
    # An attacker who updates both the bytes and the hash column still fails,
    # because the sealed leaf commits to the original hash.
    store = SQLiteRawStore(":memory:")
    evs = events(4)
    store.append(evs)
    ledger.add(evs)
    ledger.seal()

    forged = b"tampered payload"
    from aufla.ids import sha256_hex

    store._conn.execute(
        "UPDATE raw_events SET raw_bytes = ?, raw_hash = ? WHERE event_uid = ?",
        (forged, sha256_hex(forged), str(evs[1].event_uid)),
    )
    store._conn.commit()

    assert not ledger.verify(store=store).ok
    store.close()


def test_an_edited_ledger_row_is_detected(ledger):
    ledger.add(events(5))
    ledger.seal()
    ledger.add(events(5, start=50))
    ledger.seal()

    ledger._conn.execute("UPDATE batches SET root = ? WHERE batch_id = 1", ("f" * 64,))
    ledger._conn.commit()

    result = ledger.verify()
    assert not result.ok
    assert result.first_divergence == 1


def test_breaking_the_chain_link_is_detected(ledger):
    for i in range(3):
        ledger.add(events(3, start=i * 3))
        ledger.seal()

    ledger._conn.execute(
        "UPDATE batches SET prev_root = ? WHERE batch_id = 3", ("0" * 64,)
    )
    ledger._conn.commit()

    result = ledger.verify()
    assert not result.ok
    assert result.first_divergence == 3
    assert "prev_root" in result.reason


def test_a_removed_leaf_row_is_detected(ledger):
    ledger.add(events(5))
    ledger.seal()
    ledger._conn.execute("DELETE FROM batch_leaves WHERE leaf_index = 2")
    ledger._conn.commit()

    result = ledger.verify()
    assert not result.ok
    assert "leaves" in result.reason


def test_a_forged_signature_is_detected(ledger):
    ledger.add(events(3))
    ledger.seal()
    ledger._conn.execute("UPDATE batches SET signature = ? WHERE batch_id = 1", ("ab" * 32,))
    ledger._conn.commit()

    result = ledger.verify()
    assert not result.ok
    assert "signature" in result.reason


# --- checkpoints ---------------------------------------------------------


def test_a_checkpoint_anchors_the_chain_head(ledger):
    ledger.add(events(6))
    ledger.seal()
    checkpoint = ledger.create_checkpoint("2026-09-17")

    assert checkpoint.chain_head == ledger.head
    assert checkpoint.batch_count == 1
    assert checkpoint.event_count == 6
    assert checkpoint.signature


def test_checkpoints_are_verified_during_a_chain_check(ledger):
    ledger.add(events(6))
    ledger.seal()
    ledger.create_checkpoint("2026-09-17")

    result = ledger.verify()
    assert result.ok
    assert result.checkpoints_checked == 1


def test_a_tampered_checkpoint_is_detected(ledger):
    ledger.add(events(6))
    ledger.seal()
    ledger.create_checkpoint("2026-09-17")

    ledger._conn.execute("UPDATE checkpoints SET event_count = 999")
    ledger._conn.commit()

    result = ledger.verify()
    assert not result.ok
    assert "checkpoint" in result.reason


def test_checkpointing_an_empty_ledger_is_refused(ledger):
    with pytest.raises(ValueError, match="empty"):
        ledger.create_checkpoint("2026-09-17")


def test_a_checkpoint_needs_a_signing_key():
    led = Ledger(":memory:", batch_size=10)
    led.add(events(2))
    led.seal()
    with pytest.raises(ValueError, match="signing checkpoint key"):
        led.create_checkpoint("2026-09-17")
    led.close()


# --- persistence ---------------------------------------------------------


def test_the_ledger_survives_a_restart(tmp_path, keys):
    batch_key, checkpoint_key = keys
    path = tmp_path / "ledger.db"

    with Ledger(path, batch_key=batch_key, checkpoint_key=checkpoint_key) as led:
        led.add(events(4))
        led.seal()
        head = led.head

    with Ledger(path, batch_key=batch_key, checkpoint_key=checkpoint_key) as led:
        assert led.head == head
        assert led.batch_count == 1
        assert led.verify().ok
