"""Drain template mining, and the accuracy it achieves on real corpora."""

from __future__ import annotations

import csv
from pathlib import Path

import pytest

from aufla.discovery.drain import WILDCARD, Drain

LOGHUB = Path(__file__).resolve().parents[1] / "samples" / "loghub"


# --- clustering behaviour -------------------------------------------------


def test_identical_messages_share_one_template():
    d = Drain()
    for _ in range(5):
        d.add("Connection established to server")
    assert d.template_count == 1
    assert d.clusters[0].size == 5


def test_messages_differing_only_in_values_collapse():
    d = Drain()
    d.add("Deleted block blk_12345 on 10.251.31.5")
    d.add("Deleted block blk_-6789 on 10.251.199.7")
    assert d.template_count == 1
    assert WILDCARD in d.clusters[0].text


def test_genuinely_different_messages_stay_apart():
    d = Drain()
    d.add("Receiving block blk_1 src: /10.0.0.1 dest: /10.0.0.2")
    d.add("PacketResponder 1 for block blk_2 terminating")
    d.add("Verification succeeded for blk_3")
    assert d.template_count == 3


def test_token_count_separates_clusters():
    # Messages of different length cannot share a template: the first tree
    # level is keyed on token count precisely so they never compare.
    d = Drain()
    d.add("a b c")
    d.add("a b c d e")
    assert d.template_count == 2


def test_template_generalises_as_examples_arrive():
    # Variation *after* the tree-key prefix merges into one template, with the
    # differing positions becoming wildcards.
    d = Drain()
    c = d.add("session closed for user alice")
    assert WILDCARD not in c.text
    d.add("session closed for user bob")

    assert d.template_count == 1
    assert d.clusters[0].text.startswith("session closed for user")
    assert d.clusters[0].text.endswith(WILDCARD)


def test_variation_inside_the_tree_prefix_splits_clusters():
    # Drain keys the tree on leading tokens, so a value in an early position
    # lands in a different branch and forms its own template. This is inherent
    # to the algorithm, not a defect: real logs put their constant prefix
    # first, and the masking step is what stops obvious values (addresses,
    # numbers, ids) from branching this way.
    d = Drain()
    d.add("alice logged in from gateway")
    d.add("bob logged in from gateway")
    assert d.template_count == 2

    # The same variation, once masked as a number, collapses to one template.
    d2 = Drain()
    d2.add("user 1001 logged in from gateway")
    d2.add("user 1002 logged in from gateway")
    assert d2.template_count == 1


def test_masking_collapses_addresses_and_numbers():
    d = Drain()
    masked = d.mask("conn from 10.0.0.5:443 id 99887766 mac 00:1a:2b:3c:4d:5e")
    assert "10.0.0.5" not in masked
    assert "99887766" not in masked
    assert "00:1a:2b:3c:4d:5e" not in masked


def test_assignments_cover_every_message_in_order():
    d = Drain()
    lines = ["alpha 1", "beta 2", "alpha 3", "gamma 4"]
    for line in lines:
        d.add(line)
    a = d.assignments()
    assert len(a) == len(lines)
    assert a[0] == a[2]          # both "alpha <*>"
    assert a[1] != a[0]


def test_depth_below_three_is_rejected():
    # Two levels are consumed by the length node and the leaf, so anything
    # shallower has nothing left to discriminate on.
    with pytest.raises(ValueError, match="at least 3"):
        Drain(depth=2)


def test_max_children_bounds_the_branching_factor():
    d = Drain(max_children=3)
    for i in range(50):
        d.add(f"prefix{i} tail value")
    root = d.root.children["3"]
    assert len(root.children) <= 4      # the cap plus the wildcard bucket


def test_mining_never_raises_on_hostile_input():
    d = Drain()
    for line in ["", "   ", "\x00\xff", "a" * 5000, "?" * 200]:
        d.add(line)


# --- accuracy against the real published corpora --------------------------


def _load(dataset: str):
    path = LOGHUB / dataset / f"{dataset}_2k.log_structured.csv"
    if not path.exists():
        pytest.skip(f"{dataset} sample not downloaded")
    contents, truth = [], []
    with path.open(encoding="utf-8", errors="replace", newline="") as fh:
        for row in csv.DictReader(fh):
            contents.append(row["Content"])
            truth.append(row["EventId"])
    return contents, truth


def _grouping_accuracy(predicted, truth) -> float:
    from collections import defaultdict

    by_pred, by_true = defaultdict(set), defaultdict(set)
    for i, (p, t) in enumerate(zip(predicted, truth)):
        by_pred[p].add(i)
        by_true[t].add(i)
    correct = 0
    for members in by_pred.values():
        ids = {truth[i] for i in members}
        if len(ids) == 1 and by_true[next(iter(ids))] == members:
            correct += len(members)
    return correct / len(truth)


# Floors, not targets. Set below the measured figures so a real regression
# fails the build while ordinary variation does not.
@pytest.mark.parametrize(
    "dataset,floor", [("HDFS", 0.95), ("BGL", 0.90), ("Thunderbird", 0.88)]
)
def test_grouping_accuracy_on_loghub(dataset, floor):
    contents, truth = _load(dataset)
    d = Drain(depth=4, sim_threshold=0.4)
    for line in contents:
        d.add(line)
    ga = _grouping_accuracy(d.assignments(), truth)
    assert ga >= floor, f"{dataset} grouping accuracy {ga:.1%} below {floor:.0%}"


def test_template_count_is_in_the_right_order_of_magnitude():
    # Finding one template per message, or one for everything, both score
    # badly on GA but for opposite reasons; this catches the degenerate cases
    # directly.
    contents, truth = _load("HDFS")
    d = Drain()
    for line in contents:
        d.add(line)
    true_count = len(set(truth))
    assert true_count / 3 <= d.template_count <= true_count * 3
