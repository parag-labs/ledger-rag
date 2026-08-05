"""Crown-jewel tests: Merkle proofs and tamper detection.

These tests are the portfolio's proof of engineering rigor. They demonstrate
that a valid leaf verifies, and that any tampering (altered leaf, wrong root,
forged proof) is rejected.
"""

import pytest

from app.ledger.merkle import MerkleTree, hash_leaf, verify_inclusion
from app.ledger.signing import generate_keypair, sign_root, verify_root


def test_single_leaf_root_is_leaf_hash():
    tree = MerkleTree([b"only"])
    assert tree.root == hash_leaf(b"only")


def test_valid_inclusion_proof_verifies():
    leaves = [f"chunk-{i}".encode() for i in range(7)]  # odd count on purpose
    tree = MerkleTree(leaves)
    for i, leaf in enumerate(leaves):
        proof = tree.inclusion_proof(i)
        assert verify_inclusion(leaf, proof, tree.root) is True


def test_tampered_leaf_is_rejected():
    leaves = [f"chunk-{i}".encode() for i in range(5)]
    tree = MerkleTree(leaves)
    proof = tree.inclusion_proof(2)
    # An attacker alters the source content after indexing.
    assert verify_inclusion(b"chunk-2-TAMPERED", proof, tree.root) is False


def test_wrong_root_is_rejected():
    tree = MerkleTree([b"a", b"b", b"c", b"d"])
    other = MerkleTree([b"a", b"b", b"c", b"e"])
    proof = tree.inclusion_proof(3)
    assert verify_inclusion(b"d", proof, other.root) is False


def test_proof_length_is_logarithmic():
    tree = MerkleTree([f"c{i}".encode() for i in range(8)])
    assert len(tree.inclusion_proof(0)) == 3  # log2(8)


def test_empty_tree_raises():
    with pytest.raises(ValueError):
        MerkleTree([])


def test_signed_root_verifies_and_detects_forgery():
    priv, pub = generate_keypair()
    tree = MerkleTree([b"a", b"b"])
    sig = sign_root(priv, tree.root, prev_root=None, leaf_count=tree.leaf_count)

    assert verify_root(pub, sig, tree.root, None, tree.leaf_count) is True
    # A forged root (or altered leaf_count) must fail signature verification.
    assert verify_root(pub, sig, tree.root, None, tree.leaf_count + 1) is False
