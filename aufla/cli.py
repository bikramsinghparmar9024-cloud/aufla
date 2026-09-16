"""``ulpf`` command line.

``ulpf verify`` is the one that matters. It recomputes the whole chain from the
raw store and reports the first divergent batch, so tamper-evidence can be
demonstrated live rather than asserted on a slide.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from . import __version__
from .forensics import build_certificate
from .ledger import Ledger
from .ledger.signing import load_or_create_keypair
from .mapping import MappingRegistry, detect_format
from .models import Transport
from .normalize import Normalizer
from .output import export_records, get_adapter
from .pipeline import Pipeline
from .storage import SQLiteRawStore

DEFAULT_DATA = Path("data")
DEFAULT_SOURCES = Path("sources")


def _open(data_dir: Path, sources_dir: Path):
    store = SQLiteRawStore(data_dir / "raw.db")
    ledger = Ledger(
        data_dir / "ledger.db",
        batch_key=load_or_create_keypair(data_dir / "keys" / "batch.pem", "batch"),
        checkpoint_key=load_or_create_keypair(
            data_dir / "keys" / "checkpoint.pem", "checkpoint"
        ),
    )
    registry = MappingRegistry(sources_dir)
    report = registry.refresh()
    for path, error in report.failed:
        print(f"warning: {path}: {error}", file=sys.stderr)
    return store, ledger, registry


# --- commands ------------------------------------------------------------


def cmd_ingest(args) -> int:
    store, ledger, registry = _open(args.data, args.sources)
    pipeline = Pipeline(store, ledger, registry)

    payloads = [
        line.rstrip(b"\r\n")
        for line in Path(args.file).read_bytes().splitlines()
        if line.strip()
    ]
    result = pipeline.ingest(
        payloads, args.source, transport=Transport(args.transport)
    )

    print(f"ingested {args.file} as source {args.source!r}")
    print(f"  {result}")
    if result.accepted:
        print(f"  coverage: {result.coverage:.0%} fully normalised")

    for record in result.records:
        if record.is_quarantined:
            for warning in record.warnings[:1]:
                print(f"  quarantined: {warning}")
            break

    store.close()
    ledger.close()
    return 0


def cmd_verify(args) -> int:
    store, ledger, _ = _open(args.data, args.sources)
    result = ledger.verify(store=None if args.ledger_only else store)
    print(result)
    store.close()
    ledger.close()
    return 0 if result.ok else 1


def cmd_sources(args) -> int:
    registry = MappingRegistry(args.sources)
    report = registry.refresh()

    for mapping in registry:
        approval = mapping.approved_by or "UNAPPROVED"
        print(
            f"{mapping.source:<24} {mapping.format:<6} v{mapping.version}  "
            f"classes={','.join(str(c) for c in mapping.ocsf_classes):<12} "
            f"rules={len(mapping.rules)}  approved_by={approval}"
        )
        print(f"{'':<24} hash={mapping.content_hash()[:32]}...")

    for path, error in report.failed:
        print(f"FAILED {path}: {error}", file=sys.stderr)
    return 1 if report.failed else 0


def cmd_detect(args) -> int:
    payload = (
        Path(args.file).read_bytes() if args.file else args.line.encode()
    )
    for line in payload.splitlines()[: args.limit]:
        if not line.strip():
            continue
        d = detect_format(line)
        model = "model required" if d.needs_model else "deterministic"
        print(
            f"{d.format.value:<12} {d.strategy.value:<16} "
            f"conf={d.confidence:.2f}  {model}"
        )
    return 0


def cmd_export(args) -> int:
    store, ledger, registry = _open(args.data, args.sources)
    normalizer = Normalizer(registry)
    records = [
        normalizer.normalize(e)
        for e in store.iter_events(source_id=args.source, limit=args.limit)
    ]

    if args.format in {"cef", "leef", "ocsf-json"}:
        adapter = get_adapter(args.format)
        for line in adapter.render_many(records):
            print(line)
    else:
        written = export_records(records, args.out)
        for partition, count in written.items():
            print(f"{partition}: {count} records")

    store.close()
    ledger.close()
    return 0


def cmd_certificate(args) -> int:
    store, ledger, registry = _open(args.data, args.sources)
    certificate = build_certificate(
        ledger,
        store=store,
        sources=registry.sources,
        custodian=args.custodian,
    )
    text = certificate.render()
    if args.out:
        Path(args.out).write_text(text, encoding="utf-8")
        print(f"certificate written to {args.out}")
    else:
        print(text)
    store.close()
    ledger.close()
    return 0


def cmd_checkpoint(args) -> int:
    store, ledger, _ = _open(args.data, args.sources)
    try:
        checkpoint = ledger.create_checkpoint(args.day)
    except ValueError as exc:
        print(f"error: {exc}", file=sys.stderr)
        store.close()
        ledger.close()
        return 1
    print(
        f"checkpoint {checkpoint.checkpoint_id} for {checkpoint.day}: "
        f"batches {checkpoint.first_batch}-{checkpoint.last_batch}, "
        f"head {checkpoint.chain_head[:16]}..."
    )
    store.close()
    ledger.close()
    return 0


def cmd_serve(args) -> int:
    from .web import serve

    store, ledger, registry = _open(args.data, args.sources)
    try:
        serve(store, ledger, registry, host=args.host, port=args.port)
    finally:
        store.close()
        ledger.close()
    return 0


def cmd_stats(args) -> int:
    store, ledger, registry = _open(args.data, args.sources)
    print(f"raw events   : {store.count()}")
    print(f"sealed events: {ledger.event_count}")
    print(f"batches      : {ledger.batch_count}")
    print(f"chain head   : {ledger.head}")
    print(f"checkpoints  : {len(ledger.checkpoints())}")
    print(f"mappings     : {len(registry)} ({', '.join(registry.sources)})")
    store.close()
    ledger.close()
    return 0


# --- argument parsing ----------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ulpf",
        description="AUFLA - Universal Log Pre-processing Framework",
    )
    parser.add_argument("--version", action="version", version=f"ulpf {__version__}")
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--sources", type=Path, default=DEFAULT_SOURCES)

    sub = parser.add_subparsers(dest="command", required=True)

    p = sub.add_parser("ingest", help="ingest a file of log lines")
    p.add_argument("file")
    p.add_argument("--source", required=True)
    p.add_argument(
        "--transport", default="file", choices=[t.value for t in Transport]
    )
    p.set_defaults(func=cmd_ingest)

    p = sub.add_parser("verify", help="recompute the chain and report divergence")
    p.add_argument(
        "--ledger-only",
        action="store_true",
        help="check internal consistency without re-reading the raw store",
    )
    p.set_defaults(func=cmd_verify)

    p = sub.add_parser("sources", help="list loaded mappings")
    p.set_defaults(func=cmd_sources)

    p = sub.add_parser("detect", help="classify lines and show the routing decision")
    p.add_argument("--file")
    p.add_argument("--line", default="")
    p.add_argument("--limit", type=int, default=20)
    p.set_defaults(func=cmd_detect)

    p = sub.add_parser("export", help="render normalised records downstream")
    p.add_argument(
        "--format", default="ocsf-json", choices=["ocsf-json", "cef", "leef", "ndjson"]
    )
    p.add_argument("--source")
    p.add_argument("--limit", type=int, default=100)
    p.add_argument("--out", default="export")
    p.set_defaults(func=cmd_export)

    p = sub.add_parser("certificate", help="prepare a Section 63 BSA certificate")
    p.add_argument("--custodian")
    p.add_argument("--out")
    p.set_defaults(func=cmd_certificate)

    p = sub.add_parser("checkpoint", help="sign a daily offline checkpoint")
    p.add_argument("--day", required=True)
    p.set_defaults(func=cmd_checkpoint)

    p = sub.add_parser("serve", help="run the read-only Forensic Explorer UI")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8000)
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("stats", help="show store and ledger counters")
    p.set_defaults(func=cmd_stats)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    args.data.mkdir(parents=True, exist_ok=True)
    return int(args.func(args))


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
