"""File export for data-lake staging.

Parquet would be the production target, partitioned by date and OCSF class.
Writing it needs pyarrow, which is a large dependency and unavailable on a
genuinely air-gapped host without a wheel mirror -- so the default is NDJSON,
which every lake ingests and which needs nothing at all.

The partition layout matches what a Parquet writer would produce, so switching
formats later is a writer change, not a layout migration.
"""

from __future__ import annotations

import json
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

from ..normalize.engine import NormalizedRecord

__all__ = ["export_ndjson", "export_records", "partition_for"]


def partition_for(record: NormalizedRecord) -> str:
    """``date=YYYY-MM-DD/class=NNNN``, the conventional lake layout."""
    ts_ms = record.observed_time
    day = datetime.fromtimestamp(ts_ms / 1000, tz=timezone.utc).strftime("%Y-%m-%d")
    return f"date={day}/class={record.ocsf_class or 0}"


def export_ndjson(records: Iterable[NormalizedRecord], path: str | Path) -> int:
    """Write records as newline-delimited JSON. Returns the count written."""
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with target.open("w", encoding="utf-8", newline="\n") as fh:
        for record in records:
            fh.write(json.dumps(record.to_dict(), sort_keys=True))
            fh.write("\n")
            count += 1
    return count


def export_records(
    records: Iterable[NormalizedRecord],
    root: str | Path,
    *,
    filename: str = "part-0000.ndjson",
) -> dict[str, int]:
    """Write records into a partitioned tree, returning counts per partition."""
    grouped: dict[str, list[NormalizedRecord]] = defaultdict(list)
    for record in records:
        grouped[partition_for(record)].append(record)

    written: dict[str, int] = {}
    base = Path(root)
    for partition, group in sorted(grouped.items()):
        written[partition] = export_ndjson(group, base / partition / filename)
    return written
