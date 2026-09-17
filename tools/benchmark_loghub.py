"""Measure template-mining accuracy against the LogHub ground truth.

Uses **Grouping Accuracy (GA)**, the metric the LogHub and Drain papers report:
a message is counted correct when the set of messages sharing its predicted
template is exactly the set sharing its ground-truth template. Partial credit
is not given -- a cluster that is nearly right is wrong -- which is why GA is a
harsher number than it first looks and why comparing against published figures
is meaningful.

The datasets are the real published 2k-line samples from
https://github.com/logpai/loghub, downloaded with their labelled
``*_structured.csv`` ground truth. Nothing here is generated.

Usage::

    python tools/benchmark_loghub.py
    python tools/benchmark_loghub.py --dataset HDFS --show-templates 10
"""

from __future__ import annotations

import argparse
import csv
import sys
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aufla.discovery.drain import Drain  # noqa: E402

DATASETS = ("HDFS", "BGL", "Thunderbird")
BASE = ROOT / "samples" / "loghub"

# Each dataset prefixes its message with its own header fields; the benchmark
# parses the content column out of the ground truth rather than re-deriving it,
# so what is measured is template mining and not header stripping.
CONTENT_COLUMN = "Content"


def load(dataset: str) -> tuple[list[str], list[str]]:
    """Return (contents, ground-truth event ids) for one dataset."""
    path = BASE / dataset / f"{dataset}_2k.log_structured.csv"
    if not path.exists():
        raise FileNotFoundError(
            f"{path} not found. The LogHub samples are downloaded separately; "
            "see samples/loghub/README.md"
        )
    contents: list[str] = []
    truth: list[str] = []
    with path.open(encoding="utf-8", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            contents.append(row[CONTENT_COLUMN])
            truth.append(row["EventId"])
    return contents, truth


def grouping_accuracy(predicted: list[int], truth: list[str]) -> float:
    """Share of messages whose predicted cluster matches the true cluster.

    A message counts as correct only when the *whole* set of messages sharing
    its predicted template is identical to the set sharing its true template.
    """
    by_pred: dict[int, set[int]] = defaultdict(set)
    by_true: dict[str, set[int]] = defaultdict(set)
    for i, (p, t) in enumerate(zip(predicted, truth)):
        by_pred[p].add(i)
        by_true[t].add(i)

    correct = 0
    for members in by_pred.values():
        # Every member must agree on the true cluster, and that cluster must
        # contain nothing else.
        true_ids = {truth[i] for i in members}
        if len(true_ids) == 1 and by_true[next(iter(true_ids))] == members:
            correct += len(members)
    return correct / len(truth) if truth else 0.0


def run(dataset: str, *, show: int = 0) -> dict[str, float | int | str]:
    contents, truth = load(dataset)

    miner = Drain(depth=4, sim_threshold=0.4)
    started = time.perf_counter()
    for line in contents:
        miner.add(line)
    elapsed = time.perf_counter() - started

    ga = grouping_accuracy(miner.assignments(), truth)
    result = {
        "dataset": dataset,
        "messages": len(contents),
        "true_templates": len(set(truth)),
        "found_templates": miner.template_count,
        "grouping_accuracy": ga,
        "seconds": elapsed,
        "per_second": len(contents) / elapsed if elapsed else 0.0,
    }

    if show:
        print(f"\n  top templates for {dataset}:")
        for c in sorted(miner.clusters, key=lambda c: -c.size)[:show]:
            print(f"    {c.size:>5}  {c.text[:110]}")
    return result


def main() -> int:
    ap = argparse.ArgumentParser(description="LogHub template-mining benchmark")
    ap.add_argument("--dataset", choices=DATASETS, help="run just one dataset")
    ap.add_argument("--show-templates", type=int, default=0, metavar="N")
    args = ap.parse_args()

    targets = [args.dataset] if args.dataset else list(DATASETS)

    print("LogHub template-mining benchmark (Grouping Accuracy)")
    print("real published 2k samples with labelled ground truth\n")
    header = (
        f"{'dataset':<14}{'msgs':>7}{'true':>7}{'found':>7}"
        f"{'GA':>9}{'msgs/s':>10}"
    )
    print(header)
    print("-" * len(header))

    results = []
    for name in targets:
        try:
            r = run(name, show=args.show_templates)
        except FileNotFoundError as exc:
            print(f"{name:<14} skipped: {exc}")
            continue
        results.append(r)
        print(
            f"{r['dataset']:<14}{r['messages']:>7}{r['true_templates']:>7}"
            f"{r['found_templates']:>7}{r['grouping_accuracy']:>8.1%}"
            f"{r['per_second']:>10,.0f}"
        )

    if len(results) > 1:
        mean = sum(r["grouping_accuracy"] for r in results) / len(results)
        print("-" * len(header))
        print(f"{'mean':<14}{'':>21}{mean:>8.1%}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
