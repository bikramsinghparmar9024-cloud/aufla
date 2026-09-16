# AUFLA — Universal Log Pre-processing Framework

**Smart India Hackathon 2026 · Problem Statement 26156 · NTRO / NCIIPC**

AUFLA ingests logs from any perimeter device, in any format, and converts them
to standard OCSF for any SIEM or data lake — without losing a byte, and without
granting an AI any authority over the result.

## The core idea

Conventional pipelines keep the *parsed* record and discard the original.
AUFLA inverts that: **the raw event is the permanent record, and the OCSF
version is a derived projection that can be deleted and rebuilt at any time.**

Losslessness therefore stops being a promise about parser quality and becomes a
property of the storage layout.

> Other frameworks ask you to trust their parser. AUFLA keeps the original
> forever, so you never have to.

## Quick start

No daemon, no container, no network. Python 3.10 or newer.

```bash
pip install -r requirements.txt
python -m pytest
```

Then run the pipeline against the sample firewall log:

```bash
python -m aufla.cli ingest samples/pfsense.log --source pfsense_filterlog
```

```bash
python -m aufla.cli verify
```

## The tamper demo

```bash
python -m aufla.cli verify
# PASS - 1 batches, 8 events, chain intact, 1 checkpoints valid
```

Delete one row directly from the database, then verify again:

```bash
python -c "import sqlite3;c=sqlite3.connect('data/raw.db');c.execute('DELETE FROM raw_events WHERE rowid=3');c.commit()"
```

```bash
python -m aufla.cli verify
# FAIL - divergence at batch 1: event 01a0abe3-... is missing from the raw store
```

Exit code is 1 on failure, so it drops straight into a monitoring check.

## Commands

| Command | Purpose |
| --- | --- |
| `ingest FILE --source NAME` | Capture, seal and normalise a file of log lines |
| `verify` | Recompute the chain from raw and report the first divergence |
| `sources` | List loaded mappings with versions, classes and content hashes |
| `detect --line '...'` | Show the detected format and whether a model is needed |
| `export --format cef\|leef\|ocsf-json\|ndjson` | Render records downstream |
| `certificate --custodian NAME` | Prepare a Section 63 BSA 2023 certificate |
| `checkpoint --day YYYY-MM-DD` | Sign a daily offline checkpoint |
| `stats` | Store and ledger counters |

## Architecture

```
perimeter devices
      |
      v
  raw_events          immutable, byte-exact, deduplicated   <-- canonical
      |
      +---> Merkle ledger ---> signed batches ---> daily checkpoint
      |
      v
  fast lane: YAML mapping -> OCSF projection (derived, rebuildable)
      |
      +---> quarantine (no mapping yet; the event is already safe)
      |
      v
  output adapters: Splunk HEC, Elastic, CEF, LEEF, Kafka, NDJSON/Parquet
```

### Three principles

1. **Raw is canonical, OCSF is derived.** `RawEvent.capture()` refuses `str`
   input, so decoding at ingest — which destroys malformed vendor bytes
   irrecoverably — is impossible rather than merely discouraged.
2. **The AI authors, the human approves, the machine verifies.** The model
   writes a YAML mapping file. A person approves it. Deterministic checks score
   it. The model never touches the event store.
3. **The fast lane is never blocked.** An unrecognised format costs nothing at
   ingest; only its projection is deferred.

### Only free text reaches a model

| Detected format | Strategy | Model needed |
| --- | --- | --- |
| CEF, LEEF, key-value | published spec parse | no |
| JSON, XML | schema walk | no |
| CSV | positional | no |
| free-text syslog | Drain3 + model proposal | **yes** |

CEF and LEEF are self-describing by specification. Inferring them would be
slower and less defensible than parsing them.

## Onboarding a source

Drop a YAML file into `sources/`. No restart, no code change.

```yaml
source: palo_alto_panos
format: csv
ocsf_version: "1.5.0"
version: 1
approved_by: analyst-7

rules:
  - name: traffic
    match: { field: $4, equals: "TRAFFIC" }
    ocsf_class: 4001                    # Network Activity
    fields:
      src_endpoint.ip:   $8
      dst_endpoint.ip:   $9
      dst_endpoint.port: $25
      traffic.bytes:     $32
```

Unknown OCSF targets, unknown classes, duplicate rule names and shadowing
catch-all rules are all rejected at load. The same validation applies whether a
human or the model wrote the file.

## Requirements coverage

| | Requirement | Where |
| --- | --- | --- |
| a | Preserve raw without loss | `aufla/storage/` — raw is canonical and immutable |
| b | Parse source-specific attributes | `aufla/normalize/parsers.py` |
| c | Normalise to a common taxonomy | `aufla/ocsf/` — OCSF 1.5.0 |
| d | Traceability both directions | `event_uid`, `raw_hash`, `mapping_version` on every record |
| e | Plug-and-play onboarding | `aufla/mapping/loader.py` — hot reload |
| f | Unified visibility | single OCSF store; Grafana as reference consumer |
| g | SIEM and data lake integration | `aufla/output/adapters.py` |
| h | AI/ML-ready analytics | partitioned NDJSON/Parquet export |
| i | Reduced parser effort | model-authored mappings under human approval |
| j | Air-gapped | no network at runtime or install |
| k | Containerisable | pure Python, no daemons |

## Layout

```
aufla/
  ids.py           UUIDv7, SHA-256, idempotency keys
  models.py        RawEvent — frozen, bytes-only, self-verifying
  storage/         append-only raw store (SQLite dev, ClickHouse layout)
  ocsf/            field types, class catalogue, three-layer validation
  mapping/         YAML schema, format router, hot-reloading registry
  normalize/       parsers, transforms, the normaliser
  ledger/          Merkle trees, Ed25519 signing, the chain
  forensics/       Section 63 certificate preparation
  output/          SIEM adapters and data-lake export
  pipeline.py      capture -> seal -> normalise
  cli.py           the ulpf command line
sources/           mapping files
tests/             295 tests
docs/BUILD_LOG.md  what was built, verified, and fixed at each step
```

## Testing

```bash
python -m pytest -q
```

295 tests. The suite covers the guarantees rather than the lines: undecodable
bytes surviving a storage round trip, redelivery collapsing while genuine
repeats are kept, ports outside 1–65535 being rejected, endpoints detected as
swapped, Merkle roots changing under reordering, and every class of tampering
being caught by `verify`.

## Known limitations

Stated deliberately; see `docs/BUILD_LOG.md` for detail.

- **Semantically wrong mappings remain possible.** Grammar constraints bound
  field *names*, not meaning. Type and range validation, directionality
  heuristics and human approval narrow this; they do not close it.
- **Raw storage roughly doubles cost.** That is the price of structural
  losslessness. Tiered retention keeps Merkle roots forever at a few KB a day
  even after events are archived off.
- **The online signing key is a residual risk.** The daily offline checkpoint
  bounds forgery to one day.
- **SQLite is the current backend.** The schema mirrors the planned ClickHouse
  layout, so the swap is a backend change rather than a migration.
