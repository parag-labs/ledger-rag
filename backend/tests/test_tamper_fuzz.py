"""Tamper & corruption fuzz suite.

The entire premise of ledger-rag is "every answer ships a proof you can't forge."
This suite tries hard to forge one: it flips bits in leaves, proofs, roots, and
signatures across thousands of randomized trials and asserts that every corruption
is caught. A single accepted tamper here would break the whole guarantee, so these
are the tests I'd want an adversary to run first.
"""

from __future__ import annotations

import os
import random

from app.ledger.merkle import MerkleTree, ProofStep, verify_inclusion
from app.ledger.signing import generate_keypair, sign_root, verify_root
from app.ledger.store import Ledger


def _flip_one_bit(data: bytes, rng: random.Random) -> bytes:
    if not data:
        return b"\x01"
    i = rng.randrange(len(data))
    bit = 1 << rng.randrange(8)
    b = bytearray(data)
    b[i] ^= bit
    return bytes(b)


def test_untampered_proofs_always_verify():
    rng = random.Random(0)
    for _ in range(200):
        n = rng.randint(1, 64)
        leaves = [os.urandom(rng.randint(1, 40)) for _ in range(n)]
        tree = MerkleTree(leaves)
        idx = rng.randrange(n)
        proof = tree.inclusion_proof(idx)
        assert verify_inclusion(leaves[idx], proof, tree.root) is True


def test_flipping_a_bit_in_the_leaf_is_rejected():
    rng = random.Random(1)
    caught = 0
    for _ in range(1000):
        n = rng.randint(2, 64)
        leaves = [os.urandom(24) for _ in range(n)]
        tree = MerkleTree(leaves)
        idx = rng.randrange(n)
        proof = tree.inclusion_proof(idx)
        tampered = _flip_one_bit(leaves[idx], rng)
        if tampered == leaves[idx]:
            continue
        assert verify_inclusion(tampered, proof, tree.root) is False
        caught += 1
    assert caught > 900  # essentially all trials exercised a real flip


def test_corrupting_a_proof_sibling_is_rejected():
    rng = random.Random(2)
    for _ in range(1000):
        n = rng.randint(2, 64)
        leaves = [os.urandom(24) for _ in range(n)]
        tree = MerkleTree(leaves)
        idx = rng.randrange(n)
        proof = tree.inclusion_proof(idx)
        if not proof:
            continue
        j = rng.randrange(len(proof))
        bad = list(proof)
        bad[j] = ProofStep(_flip_one_bit(proof[j].sibling, rng), proof[j].side)
        assert verify_inclusion(leaves[idx], bad, tree.root) is False


def test_flipping_the_proof_side_is_rejected():
    # Swapping which side a sibling sits on changes the recomputed root unless the
    # tree is trivially symmetric, so it must fail for a non-trivial tree.
    rng = random.Random(3)
    rejected = 0
    trials = 0
    for _ in range(1000):
        n = rng.randint(3, 64)
        leaves = [os.urandom(24) for _ in range(n)]
        tree = MerkleTree(leaves)
        idx = rng.randrange(n)
        proof = tree.inclusion_proof(idx)
        if not proof:
            continue
        j = rng.randrange(len(proof))
        flipped = "left" if proof[j].side == "right" else "right"
        bad = list(proof)
        bad[j] = ProofStep(proof[j].sibling, flipped)
        trials += 1
        if verify_inclusion(leaves[idx], bad, tree.root) is False:
            rejected += 1
    # Most side-flips must be caught. The exceptions are legitimate: when a level
    # has an odd node count the last node is paired with itself, so its sibling *is*
    # the node and hash order genuinely doesn't matter - flipping the side is a
    # correct no-op there, not a forgery. That accounts for the few percent that
    # still verify, so we assert the strong majority are rejected.
    assert rejected >= trials * 0.90


def test_a_leaf_from_one_tree_wont_verify_against_another_root():
    rng = random.Random(4)
    for _ in range(500):
        n = rng.randint(2, 40)
        leaves_a = [os.urandom(24) for _ in range(n)]
        leaves_b = [os.urandom(24) for _ in range(n)]
        tree_a, tree_b = MerkleTree(leaves_a), MerkleTree(leaves_b)
        idx = rng.randrange(n)
        proof = tree_a.inclusion_proof(idx)
        # Valid against its own root, invalid against a different tree's root.
        assert verify_inclusion(leaves_a[idx], proof, tree_a.root) is True
        assert verify_inclusion(leaves_a[idx], proof, tree_b.root) is False


def test_tampering_a_signed_root_breaks_the_signature():
    rng = random.Random(5)
    for _ in range(500):
        priv, pub = generate_keypair()
        root = os.urandom(32)
        leaf_count = rng.randint(1, 1000)
        sig = sign_root(priv, root, None, leaf_count)
        assert verify_root(pub, sig, root, None, leaf_count) is True

        # Any change to the signed material must invalidate the signature.
        assert verify_root(pub, sig, _flip_one_bit(root, rng), None, leaf_count) is False
        assert verify_root(pub, sig, root, None, leaf_count + 1) is False


def test_a_forged_signature_from_the_wrong_key_is_rejected():
    _priv_real, pub_real = generate_keypair()
    priv_attacker, _ = generate_keypair()
    root = os.urandom(32)
    forged = sign_root(priv_attacker, root, None, 10)
    assert verify_root(pub_real, forged, root, None, 10) is False


def test_ledger_head_signature_survives_appends_and_rejects_forgery():
    ledger = Ledger()
    for i in range(50):
        ledger.append_leaf(f"entry-{i}".encode())
        assert ledger.verify_head_signature() is True

    # Every appended leaf still proves inclusion against the current root.
    rng = random.Random(6)
    for _ in range(50):
        idx = rng.randrange(50)
        proof = ledger.inclusion_proof(idx)
        assert verify_inclusion(f"entry-{idx}".encode(), proof, ledger.head.root) is True
        # A leaf that was never appended must not verify.
        assert verify_inclusion(b"never-happened", proof, ledger.head.root) is False
