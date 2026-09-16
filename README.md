# AUFLA — Universal Log Pre-processing Framework

Smart India Hackathon 2026 · Problem Statement 26156 · NTRO / NCIIPC

AUFLA ingests logs from any perimeter device, in any format, and converts them to
standard OCSF for any SIEM or data lake — without losing a byte, and without
granting an AI any authority over the result.

## The core idea

The raw event is the permanent record. The normalised OCSF record is a
**derived projection** that can be deleted and rebuilt at any time.

Losslessness therefore stops being a promise about parser quality and becomes a
property of the storage layout.

## Status

Under construction. See `docs/BUILD_LOG.md` for what is implemented and verified.

## Layout

```
aufla/
  config.py          settings
  ids.py             UUIDv7, SHA-256, idempotency keys
  models.py          RawEvent and friends
  storage/           raw store (SQLite dev backend, ClickHouse later)
  mapping/           YAML source definitions, loader, router, normaliser
  ocsf/              OCSF class + field catalogue and validation
sources/             YAML mapping files (human- or AI-authored)
tests/               pytest suite
```

## Quick start

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
pytest -q
```
