"""Merkle construction, including the two classic ways to get it wrong."""

from __future__ import annotations

import pytest

from aufla.ledger.merkle import (
    LEAF_PREFIX,
    NODE_PREFIX,
    MerkleTree,
    hash_leaf,
    hash_node,
    merkle_root,
    verify_proof,
)


def leaves(n: int) -> list[str]:
    return [hash_leaf(f"event-{i}".encode()) for i in range(n)]


def test_leaf_and_node_prefixes_differ():
    # Domain separation. Without it an internal node could be presented as a
    # leaf -- the standard second-preimage attack on naive Merkle trees.
    assert LEAF_PREFIX != NODE_PREFIX
    data = bytes.fromhex(hash_leaf(b"a")) + bytes.fromhex(hash_leaf(b"b"))
    assert hash_leaf(data) != hash_node(hash_leaf(b"a"), hash_leaf(b"b"))


def test_single_leaf_is_its_own_root():
    ls = leaves(1)
    assert merkle_root(ls) == ls[0]


def test_empty_tree_has_a_distinct_constant_root():
    root = merkle_root([])
    assert len(root) == 64
    assert root != merkle_root(leaves(1))


@pytest.mark.parametrize("n", [1, 2, 3, 4, 5, 7, 8, 9, 16, 17, 100, 1000])
def test_root_is_deterministic_for_any_size(n):
    assert merkle_root(leaves(n)) == merkle_root(leaves(n))


def test_changing_any_leaf_changes_the_root():
    base = leaves(9)
    for i in range(len(base)):
        altered = list(base)
        altered[i] = hash_leaf(b"tampered")
        assert merkle_root(altered) != merkle_root(base)


def test_reordering_leaves_changes_the_root():
    base = leaves(8)
    swapped = list(base)
    swapped[0], swapped[1] = swapped[1], swapped[0]
    assert merkle_root(swapped) != merkle_root(base)


def test_odd_levels_promote_rather_than_duplicate():
    # Duplicating the last node is CVE-2012-2459: two distinct leaf sets can
    # then produce the same root. Promotion cannot collide this way.
    three = leaves(3)
    forged = three + [three[-1]]        # what duplication would have built
    assert merkle_root(three) != merkle_root(forged)


@pytest.mark.parametrize("n", [1, 2, 3, 5, 8, 13, 21])
def test_every_leaf_has_a_valid_inclusion_proof(n):
    ls = leaves(n)
    tree = MerkleTree(ls)
    for i in range(n):
        assert verify_proof(ls[i], tree.proof(i), tree.root)


def test_a_proof_fails_for_the_wrong_leaf():
    ls = leaves(8)
    tree = MerkleTree(ls)
    assert not verify_proof(hash_leaf(b"not in the tree"), tree.proof(3), tree.root)


def test_a_proof_fails_against_the_wrong_root():
    ls = leaves(8)
    tree = MerkleTree(ls)
    assert not verify_proof(ls[3], tree.proof(3), merkle_root(leaves(9)))


def test_out_of_range_proof_is_rejected():
    tree = MerkleTree(leaves(4))
    with pytest.raises(IndexError):
        tree.proof(4)
    with pytest.raises(IndexError):
        tree.proof(-1)


def test_from_data_builds_leaves_for_you():
    tree = MerkleTree.from_data([b"a", b"b", b"c"])
    assert tree.leaf_count == 3
    assert verify_proof(hash_leaf(b"b"), tree.proof(1), tree.root)
