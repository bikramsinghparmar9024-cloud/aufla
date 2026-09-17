"""Drain: online log template mining with a fixed-depth tree.

Implements the algorithm from He, Zhu, Zheng and Lyu, *Drain: An Online Log
Parsing Approach with Fixed Depth Tree* (ICWS 2017) -- the paper the project
cites, now actually implemented rather than referenced.

What it is for
--------------
Structure inference reads formats that declare their own field names: JSON,
CEF, key-value. Free text declares nothing, and that is where most legacy
appliance output lives. Drain finds the *shape* of such messages by clustering
them into templates, turning

    Deleted block blk_1608999687919862906 on 10.251.31.5
    Deleted block blk_-4834595421487531  on 10.251.199.7

into one template, ``Deleted block <*> on <*>``, with the varying parts
identified. That template is what a mapping -- or a model proposing one --
then works against.

Why a tree
----------
Comparing each new message against every known template is O(n) per message
and collapses at volume. Drain groups by token count, then descends a fixed
number of levels keyed on leading tokens, so a candidate is found in a bounded
number of steps regardless of how many templates exist. That bound is what
makes it usable on a live stream rather than only on a captured file.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Iterable

__all__ = ["Drain", "LogCluster", "DEFAULT_MASKS"]

WILDCARD = "<*>"

# Applied before tokenising. These collapse the values that are obviously
# variable -- addresses, identifiers, numbers -- so they do not each look like
# a distinct template. Order matters: the more specific patterns run first.
DEFAULT_MASKS: tuple[tuple[str, str], ...] = (
    (r"\b(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}\b", WILDCARD),          # MAC
    (r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b", WILDCARD),               # IPv4(:port)
    (r"\b[0-9A-Fa-f]{8}-(?:[0-9A-Fa-f]{4}-){3}[0-9A-Fa-f]{12}\b", WILDCARD),
    (r"(?<=blk_)-?\d+", ""),                                           # HDFS block id
    (r"\b0[xX][0-9A-Fa-f]+\b", WILDCARD),                              # hex
    (r"(?<![A-Za-z])-?\d+(?:\.\d+)?(?![A-Za-z])", WILDCARD),           # bare numbers
)


@dataclass(slots=True)
class LogCluster:
    """One template and the messages assigned to it."""

    template: list[str]
    ids: list[int] = field(default_factory=list)

    @property
    def text(self) -> str:
        return " ".join(self.template)

    @property
    def size(self) -> int:
        return len(self.ids)


@dataclass(slots=True)
class _Node:
    """Internal tree node, keyed by token count then by leading tokens."""

    children: dict[str, "_Node"] = field(default_factory=dict)
    clusters: list[LogCluster] = field(default_factory=list)


class Drain:
    """Fixed-depth-tree log template miner.

    Parameters mirror the paper: ``depth`` is how many token levels the tree
    descends, ``sim_threshold`` how much of a template must match for a
    message to join it, and ``max_children`` caps the branching factor so one
    pathological field cannot explode the tree.
    """

    def __init__(
        self,
        *,
        depth: int = 4,
        sim_threshold: float = 0.4,
        max_children: int = 100,
        masks: Iterable[tuple[str, str]] = DEFAULT_MASKS,
    ) -> None:
        if depth < 3:
            # Two levels are consumed by the length node and the leaf, so a
            # depth below three leaves nothing to discriminate on.
            raise ValueError("depth must be at least 3")
        self.depth = depth - 2
        self.sim_threshold = sim_threshold
        self.max_children = max_children
        self.masks = [(re.compile(p), r) for p, r in masks]
        self.root = _Node()
        self.clusters: list[LogCluster] = []
        self._seen = 0

    # ---- preprocessing ----------------------------------------------------

    def mask(self, line: str) -> str:
        """Replace obviously-variable values before tokenising."""
        text = line
        for pattern, replacement in self.masks:
            text = pattern.sub(replacement, text)
        return text

    @staticmethod
    def tokenise(line: str) -> list[str]:
        return line.strip().split()

    # ---- tree -------------------------------------------------------------

    @staticmethod
    def _has_numbers(token: str) -> bool:
        return any(c.isdigit() for c in token)

    def _search(self, tokens: list[str]) -> LogCluster | None:
        node = self.root.children.get(str(len(tokens)))
        if node is None:
            return None

        for i, token in enumerate(tokens[: self.depth]):
            if not node.children:
                break
            nxt = node.children.get(token) or node.children.get(WILDCARD)
            if nxt is None:
                return None
            node = nxt

        return self._best_match(node.clusters, tokens)

    def _best_match(
        self, clusters: list[LogCluster], tokens: list[str]
    ) -> LogCluster | None:
        best: LogCluster | None = None
        best_sim = -1.0
        best_wildcards = 0

        for cluster in clusters:
            sim, wildcards = self._similarity(cluster.template, tokens)
            # Prefer the closer template; break ties toward the one with fewer
            # wildcards, which is the more specific of two equal matches.
            if sim > best_sim or (sim == best_sim and wildcards < best_wildcards):
                best, best_sim, best_wildcards = cluster, sim, wildcards

        return best if best_sim >= self.sim_threshold else None

    @staticmethod
    def _similarity(template: list[str], tokens: list[str]) -> tuple[float, int]:
        if len(template) != len(tokens):
            return 0.0, 0
        matched = wildcards = 0
        for t, k in zip(template, tokens):
            if t == WILDCARD:
                wildcards += 1
                continue
            if t == k:
                matched += 1
        return (matched / len(template) if template else 1.0), wildcards

    def _insert(self, cluster: LogCluster) -> None:
        tokens = cluster.template
        length_key = str(len(tokens))
        node = self.root.children.setdefault(length_key, _Node())

        for token in tokens[: self.depth]:
            # A token containing digits is treated as variable: keying the
            # tree on it would create a branch per value.
            key = WILDCARD if self._has_numbers(token) else token
            if key not in node.children:
                if len(node.children) >= self.max_children:
                    key = WILDCARD
                    node.children.setdefault(key, _Node())
                else:
                    node.children[key] = _Node()
            node = node.children[key]

        node.clusters.append(cluster)

    # ---- public API -------------------------------------------------------

    def add(self, line: str) -> LogCluster:
        """Add one message, returning the cluster it belongs to."""
        index = self._seen
        self._seen += 1

        tokens = self.tokenise(self.mask(line))
        match = self._search(tokens)

        if match is None:
            cluster = LogCluster(template=list(tokens), ids=[index])
            self.clusters.append(cluster)
            self._insert(cluster)
            return cluster

        # Merge: any position that now disagrees becomes a wildcard, which is
        # how the template generalises as more examples arrive.
        if len(match.template) == len(tokens):
            for i, (t, k) in enumerate(zip(match.template, tokens)):
                if t != k and t != WILDCARD:
                    match.template[i] = WILDCARD
        match.ids.append(index)
        return match

    def add_all(self, lines: Iterable[str]) -> list[LogCluster]:
        for line in lines:
            self.add(line)
        return self.clusters

    @property
    def template_count(self) -> int:
        return len(self.clusters)

    def assignments(self) -> list[int]:
        """Cluster index per input message, in input order."""
        out: list[int] = [0] * self._seen
        for ci, cluster in enumerate(self.clusters):
            for i in cluster.ids:
                out[i] = ci
        return out
