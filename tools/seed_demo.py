"""Generate a realistic demo dataset.

Twelve events make a poor dashboard. This produces a few thousand events across
the bundled sources, spread over a window of time, with the shape a real
perimeter actually has: mostly routine traffic, a minority of blocks, a handful
of IDS alerts, and a few events in a format nobody has onboarded yet so the
quarantine path is visible rather than theoretical.

Usage::

    python tools/seed_demo.py --events 3000 --hours 6
"""

from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from aufla.ledger import Ledger                      # noqa: E402
from aufla.ledger.signing import load_or_create_keypair  # noqa: E402
from aufla.mapping import MappingRegistry            # noqa: E402
from aufla.models import RawEvent, Transport         # noqa: E402
from aufla.normalize import Normalizer               # noqa: E402
from aufla.storage import SQLiteRawStore             # noqa: E402

INTERNAL = [f"10.0.{s}.{h}" for s in (0, 1, 2) for h in range(5, 60)]
EXTERNAL = [
    "203.0.113.9", "198.51.100.23", "8.8.8.8", "1.1.1.1", "93.184.216.34",
    "104.18.32.7", "140.82.121.4", "152.199.19.161",
]
HOSTILE = ["198.18.0.9", "198.18.7.41", "45.83.64.12"]
SIGNATURES = [
    ("ET SCAN Potential SSH Scan", 2001219, "Attempted Recon", 2),
    ("ET POLICY Outbound DNS Non-Standard Port", 2018400, "Potentially Bad Traffic", 3),
    ("ET MALWARE Suspicious User-Agent", 2013031, "A Network Trojan was Detected", 1),
    ("ET SCAN Nmap Scripting Engine", 2009358, "Web Application Attack", 1),
    ("ET INFO Observed DNS Query to .top TLD", 2027865, "Misc activity", 3),
]
URLS = [
    "http://intranet.test/reports/q3", "http://updates.test/patch.bin",
    "http://docs.test/handbook.pdf", "http://blocked.test/tracker.js",
    "http://cdn.test/assets/app.js",
]
# A vendor nobody has written a mapping for yet.
UNKNOWN = (
    "<190>%b ACME-FW v4.2 :: sess={sid} act={act} "
    "from {src}/{sp} to {dst}/{dp} proto=tcp cls=web dur={dur}ms"
)


def pfsense(ts_ms: int, rng: random.Random) -> bytes:
    block = rng.random() < 0.22
    src = rng.choice(HOSTILE if block else INTERNAL)
    dst = rng.choice(INTERNAL if block else EXTERNAL)
    sport, dport = rng.randint(1024, 65535), rng.choice([22, 80, 443, 445, 3389, 53])
    tag = time.strftime("%b %d %H:%M:%S", time.gmtime(ts_ms / 1000))
    return (
        f"<134>{tag} fw01 filterlog[1234]: "
        f"5,,,100000{rng.randint(1000,9999)},em0,match,{'block' if block else 'pass'},"
        f"in,4,0x0,,64,0,0,DF,6,tcp,60,{src},{dst},{sport},{dport},"
        f"{rng.randint(0, 9000)}"
    ).encode()


def suricata(ts_ms: int, rng: random.Random) -> bytes:
    import json

    alert = rng.random() < 0.35
    iso = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(ts_ms / 1000)) + ".000000+0000"
    src, dst = rng.choice(HOSTILE), rng.choice(INTERNAL)
    if alert:
        sig, sid, cat, sev = rng.choice(SIGNATURES)
        body = {
            "timestamp": iso, "event_type": "alert", "src_ip": src, "dest_ip": dst,
            "src_port": rng.randint(1024, 65535), "dest_port": rng.choice([22, 80, 443]),
            "alert": {"signature": sig, "signature_id": sid, "category": cat,
                      "severity": sev},
        }
    else:
        body = {
            "timestamp": iso, "event_type": "flow",
            "src_ip": rng.choice(INTERNAL), "dest_ip": rng.choice(EXTERNAL),
            "src_port": rng.randint(1024, 65535), "dest_port": 443,
            "flow": {"bytes_toserver": rng.randint(200, 40000),
                     "bytes_toclient": rng.randint(200, 900000),
                     "pkts_toserver": rng.randint(2, 400)},
        }
    return json.dumps(body).encode()


def squid(ts_ms: int, rng: random.Random) -> bytes:
    status = rng.choice(["TCP_MISS/200"] * 6 + ["TCP_HIT/200"] * 3 +
                        ["TCP_DENIED/403", "TCP_MISS/404", "TCP_MISS/502"])
    return (
        f"{ts_ms/1000:.3f} {rng.randint(8, 3000)} {rng.choice(INTERNAL)} {status} "
        f"{rng.randint(300, 90000)} {rng.choice(['GET']*8 + ['POST', 'HEAD'])} "
        f"{rng.choice(URLS)} - HIER_DIRECT/{rng.choice(EXTERNAL)} text/html"
    ).encode()


def unknown(ts_ms: int, rng: random.Random) -> bytes:
    tag = time.strftime("%b %d %H:%M:%S", time.gmtime(ts_ms / 1000))
    return UNKNOWN.format(
        sid=rng.randint(10000, 99999), act=rng.choice(["permit", "deny"]),
        src=rng.choice(INTERNAL), sp=rng.randint(1024, 65535),
        dst=rng.choice(EXTERNAL), dp=443, dur=rng.randint(5, 900),
    ).replace("%b", tag).encode()


GENERATORS = [
    ("pfsense_filterlog", pfsense, 0.46),
    ("suricata_eve", suricata, 0.22),
    ("squid_access", squid, 0.27),
    ("acme_fw", unknown, 0.05),          # deliberately unmapped
]


def main() -> int:
    ap = argparse.ArgumentParser(description="Seed a realistic AUFLA demo dataset")
    ap.add_argument("--events", type=int, default=3000)
    ap.add_argument("--hours", type=float, default=6.0)
    ap.add_argument("--data", type=Path, default=Path("data"))
    ap.add_argument("--sources", type=Path, default=Path("sources"))
    ap.add_argument("--seed", type=int, default=20260917)
    ap.add_argument("--batch-size", type=int, default=500)
    args = ap.parse_args()

    rng = random.Random(args.seed)
    args.data.mkdir(parents=True, exist_ok=True)

    registry = MappingRegistry(args.sources)
    report = registry.refresh()
    if report.failed:
        for path, err in report.failed:
            print(f"mapping failed: {path}: {err}", file=sys.stderr)

    store = SQLiteRawStore(args.data / "raw.db")
    ledger = Ledger(
        args.data / "ledger.db",
        batch_key=load_or_create_keypair(args.data / "keys" / "batch.pem", "batch"),
        checkpoint_key=load_or_create_keypair(
            args.data / "keys" / "checkpoint.pem", "checkpoint"
        ),
        batch_size=args.batch_size,
    )
    normalizer = Normalizer(registry)

    now_ns = time.time_ns()
    span_ns = int(args.hours * 3600 * 1e9)
    names = [g[0] for g in GENERATORS]
    weights = [g[2] for g in GENERATORS]
    makers = {g[0]: g[1] for g in GENERATORS}

    events: list[RawEvent] = []
    for i in range(args.events):
        # Spread events over the window, with a mild burst toward the end so the
        # timeline has shape rather than being uniform noise.
        frac = (i / args.events) ** 0.85
        ts_ns = now_ns - span_ns + int(frac * span_ns) + rng.randint(0, 250_000_000)
        source = rng.choices(names, weights=weights, k=1)[0]
        payload = makers[source](ts_ns // 1_000_000, rng)
        events.append(
            RawEvent.capture(
                payload, source, transport=Transport.UDP, received_at_ns=ts_ns
            )
        )

    events.sort(key=lambda e: e.received_at_ns)

    stats = store.append(events)
    mapping_set = registry.hashes()
    ledger.add(events, mapping_set=mapping_set)
    if ledger._pending:
        ledger.seal(mapping_set=mapping_set)

    outcomes = {"full": 0, "partial": 0, "quarantined": 0}
    for event in events:
        outcomes[normalizer.normalize(event).parse_status.value] += 1

    day = time.strftime("%Y-%m-%d", time.gmtime())
    try:
        ledger.create_checkpoint(day)
    except ValueError:
        pass

    print(f"seeded {stats.accepted} events over {args.hours}h")
    print(f"  sealed   : {ledger.event_count} in {ledger.batch_count} batches")
    print(f"  outcomes : {outcomes}")
    print(f"  verify   : {ledger.verify(store=store)}")

    store.close()
    ledger.close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
