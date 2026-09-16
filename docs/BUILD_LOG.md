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

## Step 3 — YAML mappings, loader, format router ✅

The artifact the discovery lane produces: a file a person can read, diff and
sign off on. The model never writes to the event store.

| Module | What it does |
| --- | --- |
| `aufla/mapping/schema.py` | Field references, specs, conditions, rules, mappings, content hashing |
| `aufla/mapping/router.py` | Format detection and discovery-strategy routing |
| `aufla/mapping/loader.py` | Directory registry with hot reload |
| `sources/*.yaml` | pfSense filterlog, Suricata EVE, Squid access |

**Routing — only free text reaches the model**

| Detected | Strategy | Model? |
| --- | --- | --- |
| CEF, LEEF, key-value | spec parse | no |
| JSON, XML | schema walk | no |
| CSV | positional | no |
| free-text syslog | template mining | **yes** |

Syslog framing is stripped before detection, so CEF wrapped in syslog is still
recognised as CEF rather than being sent to the model for nothing.

**Rejected at load:** unknown OCSF targets and classes, duplicate rule names,
and a catch-all rule placed where it would shadow later rules. A broken edit
leaves the previous version serving rather than dropping the source.

**Bug found:** the catalogue omitted `duration`, `traffic.bytes` and
`disposition_id` from HTTP Activity (4002). Caught by the target validator
refusing the bundled Squid mapping.

**Verified:** 163 tests.

## Step 4 — Normaliser and the OCSF projection ✅

| Module | What it does |
| --- | --- |
| `aufla/normalize/parsers.py` | CSV, SSV, TSV, JSON, XML, key-value, CEF, LEEF |
| `aufla/normalize/transforms.py` | Closed registries of transforms and lookups |
| `aufla/normalize/engine.py` | Rule selection, field resolution, validation, lineage |

Transforms and lookups are closed sets, so a mapping can no more invent a
transform than it can invent an OCSF field. `syslog_time` infers the year RFC
3164 omits and handles the new-year rollover, which otherwise dates every
January event twelve months ahead.

Normalisation never raises. An unmapped source, an unparseable body or an
unmatched rule quarantines with a reason. A device supplying no parseable time
falls back to the receipt clock, with a warning rather than silently.

**Bug found:** `_flatten` let a synthesised path overwrite a literal dotted
key, so `{"src.ip": x, "src": {"ip": y}}` resolved by dict iteration order.
Literal keys now always win, verified in both orders.

**Verified:** 220 tests.

## Step 5 — Merkle ledger, two-tier signing, `ulpf verify` ✅

| Module | What it does |
| --- | --- |
| `aufla/ledger/merkle.py` | Merkle trees with domain separation and inclusion proofs |
| `aufla/ledger/signing.py` | Ed25519 via `cryptography`, batch and checkpoint tiers |
| `aufla/ledger/ledger.py` | Chained batches, checkpoints, verification |
| `aufla/forensics/certificate.py` | Section 63 BSA 2023 certificate preparation |
| `aufla/pipeline.py` | capture → seal → normalise, in that order |
| `aufla/cli.py` | `ulpf` command line |

**Two classic Merkle mistakes avoided.** Leaves are hashed `0x00 ‖ data` and
nodes `0x01 ‖ l ‖ r`, so an internal node cannot be presented as a leaf. Odd
levels **promote** the last node rather than duplicating it — duplication is
CVE-2012-2459, where two distinct trees share a root.

**Signing is two-tier** because one offline key cannot sign a root every
second. An online key signs each batch; an offline root key signs a daily
checkpoint. Stealing the online key buys forgery only within the current day.

**What the chain seals:** the raw stream. The OCSF projection is re-buildable
and therefore not evidence. Mapping hashes are committed into each batch, so
the derivation stays provable.

**Detected by `verify`:** deleted events, modified bodies, modified bodies
*with* a matching forged hash column, edited ledger rows, broken chain links,
removed leaf rows, forged signatures, tampered checkpoints.

**Bug found:** the leaf function used when verifying without the raw store
computed `sha256(0x00 ‖ hash)` while sealing used `sha256(0x00 ‖ bytes)` — so
store-free verification could never reproduce a root. Leaves now bind
`uid ‖ content hash` consistently, which also stops two byte-identical events
being swapped without changing the root.

## Step 6 — Output adapters and export ✅

| Module | What it does |
| --- | --- |
| `aufla/output/adapters.py` | OCSF JSON, NDJSON, CEF, LEEF |
| `aufla/output/export.py` | Partitioned NDJSON for data-lake staging |

This is what makes AUFLA a *pre-processor* rather than another SIEM. Every
adapter carries `event_uid` and `raw_hash` downstream, so an analyst in Splunk
or QRadar can walk back to the exact original bytes.

Export partitions as `date=YYYY-MM-DD/class=NNNN`, matching what a Parquet
writer would produce — switching formats later is a writer change, not a
layout migration. NDJSON is the default because pyarrow is a large dependency
and unavailable on a genuinely air-gapped host without a wheel mirror.

**Verified:** 295 tests, plus the CLI exercised end to end outside pytest.
