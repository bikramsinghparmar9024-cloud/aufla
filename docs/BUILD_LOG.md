# Build log

Each step is committed only when its tests pass. Nothing is built on an
unverified layer.

## Step 1 — The raw-canonical core ✅

The architectural inversion that everything else depends on: raw bytes are the
permanent record, and identity is assigned once at the ingest boundary.

**Implemented**

| Module | What it does |
| --- | --- |
| `aufla/ids.py` | UUIDv7 (RFC 9562, hand-built — Python 3.10 has no `uuid.uuid7`), SHA-256 helpers, idempotency keys |
| `aufla/models.py` | `RawEvent` — frozen, bytes-only, self-verifying |
| `aufla/storage/base.py` | `RawStore` interface: append, get, count, iterate. No update, no delete |
| `aufla/storage/sqlite_store.py` | SQLite backend mirroring the ClickHouse schema |

**Guarantees now enforced by code rather than by intention**

- `RawEvent.capture()` raises `TypeError` on `str` input. Decoding at ingest is
  impossible, so malformed vendor bytes cannot be destroyed.
- `raw_bytes` is a BLOB; the full 0–255 byte range round-trips through storage.
- Dedupe is a `UNIQUE` constraint on `idem_key`, not a check-then-insert, so it
  is race-free across concurrent workers.
- Two identical payloads received at different times remain two distinct events.
  Redelivery of the *same* event is collapsed. These are different things and
  the identity design separates them.
- UUIDv7 is lexically time-ordered, making forensic range scans cheap.
- UDP payloads at the RFC 3164 limit of 1024 bytes are flagged `truncated`
  rather than silently presented as complete.

**Verified:** 33 tests passing.

## Step 2 — OCSF catalogue and validation ⏳

Next: the field catalogue, type and range validation, and the semantic checks
that catch a mapping putting a source IP into `dst_endpoint.ip`.

## Step 3 — YAML mappings, loader, format router ⏳

## Step 4 — Normaliser and the OCSF projection ⏳

## Step 5 — Merkle ledger, signing, `ulpf verify` ⏳

## Step 6 — Output adapters and Parquet export ⏳
