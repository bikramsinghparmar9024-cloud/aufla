"""Vercel Serverless Function entrypoint for AUFLA Dashboard.

This exposes a BaseHTTPRequestHandler subclass named `handler` that Vercel's
Python runtime (@vercel/python) invokes for incoming HTTP requests.
"""

from __future__ import annotations

import io
import json
import os
import random
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

# Ensure project root is in sys.path
ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from aufla.collect import LiveCollector
from aufla.ledger import Ledger
from aufla.ledger.signing import load_or_create_keypair
from aufla.mapping import MappingRegistry
from aufla.models import RawEvent, Transport
from aufla.normalize import Normalizer
from aufla.storage import OCSFStore, SQLiteRawStore
from aufla.web.server import ForensicHandler

_LOCK = threading.Lock()
STATE: dict[str, Any] = {}


def _seed_quick_demo(data_dir: Path, sources_dir: Path, count: int = 600) -> None:
    """Populate initial demo events if databases are empty on cold start."""
    try:
        from tools.seed_demo import GENERATORS
    except ImportError:
        return

    data_dir.mkdir(parents=True, exist_ok=True)
    registry = MappingRegistry(sources_dir)
    registry.refresh()

    store = SQLiteRawStore(data_dir / "raw.db")
    keys_dir = data_dir / "keys"
    keys_dir.mkdir(parents=True, exist_ok=True)

    ledger = Ledger(
        data_dir / "ledger.db",
        batch_key=load_or_create_keypair(keys_dir / "batch.pem", "batch"),
        checkpoint_key=load_or_create_keypair(keys_dir / "checkpoint.pem", "checkpoint"),
        batch_size=200,
    )
    normalizer = Normalizer(registry)
    ocsf = OCSFStore(data_dir / "ocsf.db")

    rng = random.Random(20260917)
    now_ns = time.time_ns()
    span_ns = int(6.0 * 3600 * 1e9)

    names = [g[0] for g in GENERATORS]
    weights = [g[2] for g in GENERATORS]
    makers = {g[0]: g[1] for g in GENERATORS}

    events: list[RawEvent] = []
    for i in range(count):
        frac = (i / count) ** 0.85
        ts_ns = now_ns - span_ns + int(frac * span_ns) + rng.randint(0, 250_000_000)
        source = rng.choices(names, weights=weights, k=1)[0]
        payload = makers[source](ts_ns // 1_000_000, rng)
        events.append(
            RawEvent.capture(
                payload, source, transport=Transport.UDP, received_at_ns=ts_ns
            )
        )

    events.sort(key=lambda e: e.received_at_ns)
    store.append(events)
    mapping_set = registry.hashes()
    ledger.add(events, mapping_set=mapping_set)
    if ledger._pending:
        ledger.seal(mapping_set=mapping_set)

    records = [normalizer.normalize(event) for event in events]
    ocsf.upsert(records)

    day = time.strftime("%Y-%m-%d", time.gmtime())
    try:
        ledger.create_checkpoint(day)
    except ValueError:
        pass

    store.close()
    ledger.close()
    ocsf.close()


def _init_state() -> None:
    with _LOCK:
        if "data_dir" in STATE:
            return

        is_serverless = os.environ.get("VERCEL") == "1" or not os.access(
            ROOT_DIR / "data", os.W_OK
        )

        if is_serverless:
            data_dir = Path(tempfile.gettempdir()) / "aufla_data"
            sources_dir = Path(tempfile.gettempdir()) / "aufla_sources"
        else:
            data_dir = ROOT_DIR / "data"
            sources_dir = ROOT_DIR / "sources"

        data_dir.mkdir(parents=True, exist_ok=True)
        sources_dir.mkdir(parents=True, exist_ok=True)

        # 1. Sync sources
        source_src = ROOT_DIR / "sources"
        if source_src.exists() and sources_dir != source_src:
            for f in source_src.glob("*.yaml"):
                dest_file = sources_dir / f.name
                if not dest_file.exists():
                    shutil.copy2(f, dest_file)

        # 2. Sync seed databases if available in root data directory
        source_data = ROOT_DIR / "data"
        if source_data.exists() and data_dir != source_data:
            for item in source_data.iterdir():
                dest = data_dir / item.name
                if not dest.exists():
                    if item.is_dir():
                        shutil.copytree(item, dest, dirs_exist_ok=True)
                    elif item.suffix in [".db", ".pem"]:
                        shutil.copy2(item, dest)

        # 3. If ocsf.db does not exist or has 0 events, seed realistic demo data
        ocsf_path = data_dir / "ocsf.db"
        needs_seed = False
        if not ocsf_path.exists():
            needs_seed = True
        else:
            try:
                store = OCSFStore(ocsf_path)
                if store.count() == 0:
                    needs_seed = True
                store.close()
            except Exception:
                needs_seed = True

        if needs_seed:
            _seed_quick_demo(data_dir, sources_dir, count=600)

        registry = MappingRegistry(sources_dir)
        registry.refresh()
        collector = LiveCollector(lambda: None)

        STATE["data_dir"] = data_dir
        STATE["sources_dir"] = sources_dir
        STATE["registry"] = registry
        STATE["collector"] = collector


class handler(ForensicHandler):
    """Vercel entrypoint request handler."""

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        _init_state()
        super().__init__(
            *args,
            data_dir=STATE["data_dir"],
            sources_dir=STATE["sources_dir"],
            registry=STATE["registry"],
            collector=STATE["collector"],
            **kwargs,
        )

    def _normalize_path(self) -> None:
        """Resolve requested URL path under Vercel rewrites."""
        matched = (
            self.headers.get("x-matched-path")
            or self.headers.get("x-vercel-matched-path")
            or self.headers.get("x-forwarded-uri")
        )
        if matched:
            self.path = matched
        elif self.path.startswith("/api/index.py"):
            rem = self.path[len("/api/index.py") :]
            self.path = rem if rem else "/"

    def do_GET(self) -> None:
        self._normalize_path()
        super().do_GET()

    def do_POST(self) -> None:
        self._normalize_path()
        super().do_POST()

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Content-Length", "0")
        self.end_headers()
