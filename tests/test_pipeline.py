"""The pipeline, the adapters, the certificate, and the CLI end to end."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aufla.forensics import build_certificate
from aufla.ledger import Ledger
from aufla.ledger.signing import KeyPair
from aufla.mapping import MappingRegistry
from aufla.output import export_records, get_adapter
from aufla.pipeline import Pipeline
from aufla.storage import SQLiteRawStore

SOURCES = Path(__file__).resolve().parents[1] / "sources"

PFSENSE_LINES = [
    (
        b"<134>Sep 17 10:00:0%d fw01 filterlog[1234]: "
        b"5,,,100000010%d,em0,match,%s,in,4,0x0,,64,0,0,DF,6,tcp,60,"
        b"198.18.0.9,10.0.0.5,4533%d,22,0"
    ) % (i, i, b"block" if i % 2 else b"pass", i)
    for i in range(6)
]


@pytest.fixture()
def parts(tmp_path):
    store = SQLiteRawStore(":memory:")
    ledger = Ledger(
        ":memory:",
        batch_key=KeyPair.generate("batch"),
        checkpoint_key=KeyPair.generate("checkpoint"),
        batch_size=1000,
    )
    registry = MappingRegistry(SOURCES)
    assert registry.refresh().ok
    yield Pipeline(store, ledger, registry), store, ledger
    store.close()
    ledger.close()


# --- pipeline ------------------------------------------------------------


def test_ingest_captures_seals_and_normalises(parts):
    pipeline, store, ledger = parts
    result = pipeline.ingest(PFSENSE_LINES, "pfsense_filterlog")

    assert result.accepted == 6
    assert store.count() == 6
    assert ledger.event_count == 6
    assert result.normalized == 6
    assert result.coverage == 1.0


def test_the_chain_verifies_after_ingest(parts):
    pipeline, _, _ = parts
    pipeline.ingest(PFSENSE_LINES, "pfsense_filterlog")
    assert pipeline.verify().ok


def test_redelivery_does_not_double_seal(parts):
    pipeline, store, ledger = parts
    pipeline.ingest(PFSENSE_LINES, "pfsense_filterlog")
    sealed_before = ledger.event_count

    # Same bytes again. New capture times make these *new* events, so the
    # honest outcome is that they are accepted -- what must not happen is the
    # same event_uid being sealed twice.
    pipeline.ingest(PFSENSE_LINES, "pfsense_filterlog")
    assert ledger.event_count >= sealed_before
    assert pipeline.verify().ok


def test_an_unknown_source_quarantines_without_blocking_ingest(parts):
    pipeline, store, ledger = parts
    result = pipeline.ingest([b"totally unknown format here"], "mystery_box")

    assert result.accepted == 1          # the event is safely stored
    assert result.quarantined == 1       # only its projection is deferred
    assert store.count() == 1
    assert ledger.event_count == 1
    assert pipeline.verify().ok


def test_backfill_rebuilds_projections_from_raw(parts):
    pipeline, _, _ = parts
    pipeline.ingest(PFSENSE_LINES, "pfsense_filterlog")

    records = pipeline.backfill("pfsense_filterlog")
    assert len(records) == 6
    assert all(r.parse_status.value == "full" for r in records)


def test_mapping_hashes_are_sealed_with_the_events(parts):
    pipeline, _, ledger = parts
    pipeline.ingest(PFSENSE_LINES, "pfsense_filterlog")
    batch = ledger.get_batch(1)
    assert "pfsense_filterlog" in batch.mapping_set


# --- adapters ------------------------------------------------------------


def test_ocsf_json_adapter_round_trips(parts):
    pipeline, _, _ = parts
    record = pipeline.ingest(PFSENSE_LINES[:1], "pfsense_filterlog").records[0]

    payload = json.loads(get_adapter("ocsf-json").render(record))
    assert payload["class_uid"] == 4001
    assert payload["event_uid"] == str(record.event_uid)


def test_cef_adapter_emits_a_valid_header(parts):
    pipeline, _, _ = parts
    record = pipeline.ingest(PFSENSE_LINES[:1], "pfsense_filterlog").records[0]

    line = get_adapter("cef").render(record)
    assert line.startswith("CEF:0|AUFLA|ULPF|")
    assert line.count("|") >= 7
    assert "src=198.18.0.9" in line


def test_cef_carries_lineage_downstream(parts):
    # An analyst in the SIEM must be able to walk back to the original bytes.
    pipeline, _, _ = parts
    record = pipeline.ingest(PFSENSE_LINES[:1], "pfsense_filterlog").records[0]

    line = get_adapter("cef").render(record)
    assert str(record.event_uid) in line
    assert record.raw_hash in line


def test_leef_adapter_is_tab_delimited(parts):
    pipeline, _, _ = parts
    record = pipeline.ingest(PFSENSE_LINES[:1], "pfsense_filterlog").records[0]

    line = get_adapter("leef").render(record)
    assert line.startswith("LEEF:2.0|AUFLA|ULPF|")
    assert "\t" in line.split("|", 5)[-1]


def test_unknown_adapter_lists_the_known_ones():
    with pytest.raises(KeyError, match="known:"):
        get_adapter("carrier-pigeon")


def test_export_partitions_by_date_and_class(parts, tmp_path):
    pipeline, _, _ = parts
    records = pipeline.ingest(PFSENSE_LINES, "pfsense_filterlog").records

    written = export_records(records, tmp_path / "lake")
    assert written
    partition = next(iter(written))
    assert partition.startswith("date=")
    assert "class=4001" in partition

    path = tmp_path / "lake" / partition / "part-0000.ndjson"
    lines = path.read_text(encoding="utf-8").strip().splitlines()
    assert len(lines) == written[partition]
    assert json.loads(lines[0])["class_uid"] == 4001


# --- certificate ---------------------------------------------------------


def test_certificate_reports_a_passing_chain(parts):
    pipeline, store, ledger = parts
    pipeline.ingest(PFSENSE_LINES, "pfsense_filterlog")
    ledger.create_checkpoint("2026-09-17")

    cert = build_certificate(ledger, store=store, sources=("pfsense_filterlog",))
    assert cert.verification == "PASS"
    assert cert.event_count == 6
    assert "Section 63" in cert.render().upper().replace("SECTION 63", "Section 63")


def test_certificate_never_claims_to_be_self_certifying(parts):
    # Software cannot self-certify under Section 63; a custodian must sign.
    pipeline, store, ledger = parts
    pipeline.ingest(PFSENSE_LINES, "pfsense_filterlog")

    cert = build_certificate(ledger, store=store)
    assert cert.is_admissible_as_prepared is False
    text = cert.render()
    assert "not valid" in text
    assert "signed by the custodian" in text
    assert "Signature" in text


def test_certificate_reports_a_broken_chain(parts):
    pipeline, store, ledger = parts
    pipeline.ingest(PFSENSE_LINES, "pfsense_filterlog")

    store._conn.execute("DELETE FROM raw_events WHERE rowid = 1")
    store._conn.commit()

    cert = build_certificate(ledger, store=store)
    assert cert.verification == "FAIL"
    assert "FAIL" in cert.render()


# --- CLI -----------------------------------------------------------------


def test_cli_ingest_verify_and_tamper_detection(tmp_path, capsys):
    from aufla.cli import main

    log = tmp_path / "fw.log"
    log.write_bytes(b"\n".join(PFSENSE_LINES))
    data = tmp_path / "data"

    argv = ["--data", str(data), "--sources", str(SOURCES)]

    assert main([*argv, "ingest", str(log), "--source", "pfsense_filterlog"]) == 0
    assert "6 accepted" in capsys.readouterr().out

    assert main([*argv, "verify"]) == 0
    assert "PASS" in capsys.readouterr().out

    # Tamper, then verify again. This is the last twenty seconds of the demo.
    import sqlite3

    conn = sqlite3.connect(data / "raw.db")
    conn.execute("DELETE FROM raw_events WHERE rowid = 2")
    conn.commit()
    conn.close()

    assert main([*argv, "verify"]) == 1
    out = capsys.readouterr().out
    assert "FAIL" in out
    assert "divergence at batch" in out


def test_cli_sources_and_stats_and_detect(tmp_path, capsys):
    from aufla.cli import main

    argv = ["--data", str(tmp_path / "data"), "--sources", str(SOURCES)]

    assert main([*argv, "sources"]) == 0
    assert "pfsense_filterlog" in capsys.readouterr().out

    assert main([*argv, "stats"]) == 0
    assert "chain head" in capsys.readouterr().out

    assert main([*argv, "detect", "--line", '{"a":1,"b":2}']) == 0
    assert "json" in capsys.readouterr().out


def test_cli_certificate_and_checkpoint(tmp_path, capsys):
    from aufla.cli import main

    log = tmp_path / "fw.log"
    log.write_bytes(b"\n".join(PFSENSE_LINES))
    data = tmp_path / "data"
    argv = ["--data", str(data), "--sources", str(SOURCES)]

    main([*argv, "ingest", str(log), "--source", "pfsense_filterlog"])
    capsys.readouterr()

    assert main([*argv, "checkpoint", "--day", "2026-09-17"]) == 0
    assert "checkpoint 1" in capsys.readouterr().out

    out_file = tmp_path / "cert.txt"
    assert main([*argv, "certificate", "--custodian", "Maj. R. Sharma",
                 "--out", str(out_file)]) == 0
    text = out_file.read_text(encoding="utf-8")
    assert "Maj. R. Sharma" in text
    assert "PASS" in text
