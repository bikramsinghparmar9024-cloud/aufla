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

## Step 2 — OCSF catalogue and validation ✅

The layer that closes the gap grammar-constrained decoding leaves open. GBNF
guarantees a model emits a real field *name*; only this can tell whether the
*value* behind it makes sense.

**Implemented**

| Module | What it does |
| --- | --- |
| `aufla/ocsf/types.py` | 13 field types with coercion: IP, PORT, MAC, TIMESTAMP, HOSTNAME, EMAIL, URL, UUID, scalars |
| `aufla/ocsf/classes.py` | Catalogue pinned to **OCSF 1.5.0** — 4001 Network Activity, 4002 HTTP Activity, 3002 Authentication, 2004 Detection Finding |
| `aufla/ocsf/validate.py` | Three-layer validation plus `mapping_coverage` |

**Three validation layers**

1. *Structural* — is this a field of the class at all?
2. *Type and range* — `dst_endpoint.port = 70000` is rejected; epoch 0 and
   far-future timestamps are rejected as clock faults; seconds mistaken for
   milliseconds is caught.
3. *Semantic* — the checks that catch a wrong-but-valid mapping:
   - identical src and dst address → the mapping may read one column twice
   - well-known source port with ephemeral destination port → endpoints swapped
   - both endpoints globally routable → the internal side was probably dropped
   - `bytes_in + bytes_out > bytes` → inconsistent counters
   - device clock more than an hour from the receipt clock → `event_time` untrusted

**Design decisions worth keeping**

- Warnings never reject a record. Real traffic is strange, and dropping odd
  events during an incident is worse than useless. Warnings downgrade trust in
  the *mapping*, which is the thing that might actually be wrong — this is what
  will feed the confidence gate in Step 4.
- Vendor extras route to `unmapped` instead of failing the event, and
  `mapping_coverage` reports the share that found an OCSF home, so the
  normalised view is never *quietly* lossy.
- `strict_unknown=True` is used when checking a *mapping*, where an unknown
  target is a configuration bug rather than a vendor extra.

**Bug found and fixed during this step.** The "is this internal traffic?"
heuristic first used `ipaddress.is_private`, which returns `True` for the
TEST-NET documentation ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)
and other IANA special-purpose blocks. That conflates "internal network" with
"reserved" and would have made the check silently wrong on real traffic.
Switched to `is_global`, which asks the question the heuristic actually means.
Regression test added.

**Verified:** 93 tests passing.

## Step 3 — YAML mappings, loader, format router ⏳

## Step 4 — Normaliser and the OCSF projection ⏳

## Step 5 — Merkle ledger, signing, `ulpf verify` ⏳

## Step 6 — Output adapters and Parquet export ⏳
