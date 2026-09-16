"""Merkle trees over batches of raw events.

Domain separation
-----------------
Leaves are hashed as ``0x00 || data`` and internal nodes as ``0x01 || left ||
right``. Without this, an attacker could present an internal node as if it
were a leaf -- a well-known second-preimage attack on naive Merkle
constructions. It costs one byte per hash and closes the hole entirely.

Odd node counts
---------------
An odd level promotes its last node unchanged rather than duplicating it.
Duplication is how CVE-2012-2459 happened in Bitcoin: two distinct trees could
produce the same root. Promotion has no such ambiguity.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass

__all__ = ["LEAF_PREFIX", "NODE_PREFIX", "MerkleTree", "merkle_root", "verify_proof"]

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"

# The root of an empty batch. Distinct from any real leaf hash.
EMPTY_ROOT = hashlib.sha256(b"AUFLA-EMPTY-MERKLE-ROOT").hexdigest()


def hash_leaf(data: bytes) -> str:
    return hashlib.sha256(LEAF_PREFIX + data).hexdigest()


def hash_node(left: str, right: str) -> str:
    return hashlib.sha256(
        NODE_PREFIX + bytes.fromhex(left) + bytes.fromhex(right)
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class ProofStep:
    """One sibling on the path from a leaf to the root."""

    sibling: str
    is_left: bool


class MerkleTree:
    """A Merkle tree over pre-computed leaf hashes."""

    __slots__ = ("levels",)

    def __init__(self, leaves: list[str]) -> None:
        self.levels: list[list[str]] = [list(leaves)]
        while len(self.levels[-1]) > 1:
            self.levels.append(self._next_level(self.levels[-1]))

    @staticmethod
    def _next_level(level: list[str]) -> list[str]:
        out: list[str] = []
        for i in range(0, len(level) - 1, 2):
            out.append(hash_node(level[i], level[i + 1]))
        if len(level) % 2:
            out.append(level[-1])  # promote, never duplicate
        return out

    @classmethod
    def from_data(cls, blocks: list[bytes]) -> "MerkleTree":
        return cls([hash_leaf(b) for b in blocks])

    @property
    def root(self) -> str:
        if not self.levels[0]:
            return EMPTY_ROOT
        return self.levels[-1][0]

    @property
    def leaf_count(self) -> int:
        return len(self.levels[0])

    def proof(self, index: int) -> list[ProofStep]:
        """Inclusion proof for the leaf at ``index``."""
        if not 0 <= index < self.leaf_count:
            raise IndexError(
                f"leaf index {index} out of range (0-{self.leaf_count - 1})"
            )

        steps: list[ProofStep] = []
        position = index
        for level in self.levels[:-1]:
            if position % 2 == 0:
                if position + 1 < len(level):
                    steps.append(ProofStep(level[position + 1], is_left=False))
                # else: this node was promoted; no sibling at this level
            else:
                steps.append(ProofStep(level[position - 1], is_left=True))
            position //= 2
        return steps


def merkle_root(leaves: list[str]) -> str:
    return MerkleTree(leaves).root


def verify_proof(leaf: str, steps: list[ProofStep], root: str) -> bool:
    """Recompute a root from a leaf and its proof."""
    current = leaf
    for step in steps:
        current = (
            hash_node(step.sibling, current)
            if step.is_left
            else hash_node(current, step.sibling)
        )
    return current == root
