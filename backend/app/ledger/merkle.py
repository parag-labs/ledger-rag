"""Merkle tree with SHA-256 leaves and inclusion proofs.

This is the cryptographic core of LedgerRAG. It lets us commit to an entire set
of document chunks with a single root hash, and later prove that any one chunk
belongs to that set using an O(log n) inclusion proof -- without revealing the
other chunks.

Design notes:
- Leaves are hashed with a 0x00 prefix, internal nodes with 0x01, to prevent
  second-preimage attacks (a known Merkle-tree pitfall).
- Odd nodes at a level are promoted (duplicated) to the next level.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Literal

LEAF_PREFIX = b"\x00"
NODE_PREFIX = b"\x01"


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash_leaf(data: bytes) -> bytes:
    """Hash a leaf value (a chunk's normalized bytes)."""
    return _sha256(LEAF_PREFIX + data)


def hash_nodes(left: bytes, right: bytes) -> bytes:
    """Hash two child nodes into their parent."""
    return _sha256(NODE_PREFIX + left + right)


@dataclass(frozen=True)
class ProofStep:
    """One step in a Merkle inclusion proof: a sibling hash and its side."""

    sibling: bytes
    side: Literal["left", "right"]  # which side the sibling is on


class MerkleTree:
    """An immutable Merkle tree built from a list of leaf byte-strings."""

    def __init__(self, leaves: list[bytes]):
        if not leaves:
            raise ValueError("MerkleTree requires at least one leaf")
        self._leaf_hashes: list[bytes] = [hash_leaf(x) for x in leaves]
        self._levels: list[list[bytes]] = self._build(self._leaf_hashes)

    @staticmethod
    def _build(leaf_hashes: list[bytes]) -> list[list[bytes]]:
        levels = [leaf_hashes]
        current = leaf_hashes
        while len(current) > 1:
            nxt: list[bytes] = []
            for i in range(0, len(current), 2):
                left = current[i]
                right = current[i + 1] if i + 1 < len(current) else current[i]
                nxt.append(hash_nodes(left, right))
            levels.append(nxt)
            current = nxt
        return levels

    @property
    def root(self) -> bytes:
        return self._levels[-1][0]

    @property
    def leaf_count(self) -> int:
        return len(self._leaf_hashes)

    def leaf_hash(self, index: int) -> bytes:
        return self._leaf_hashes[index]

    def inclusion_proof(self, index: int) -> list[ProofStep]:
        """Return the Merkle path proving leaf `index` is under `root`."""
        if not 0 <= index < self.leaf_count:
            raise IndexError("leaf index out of range")
        proof: list[ProofStep] = []
        idx = index
        for level in self._levels[:-1]:  # every level except the root
            is_right = idx % 2 == 1
            if is_right:
                sibling_idx = idx - 1
                side: Literal["left", "right"] = "left"
            else:
                sibling_idx = idx + 1 if idx + 1 < len(level) else idx
                side = "right"
            proof.append(ProofStep(sibling=level[sibling_idx], side=side))
            idx //= 2
        return proof


def verify_inclusion(leaf_data: bytes, proof: list[ProofStep], root: bytes) -> bool:
    """Independently verify that `leaf_data` is committed under `root`.

    This function is the whole point of LedgerRAG's verifiability: given only the
    leaf bytes, the proof, and a (signed) root, anyone can confirm membership
    without trusting the server that produced the answer.
    """
    computed = hash_leaf(leaf_data)
    for step in proof:
        if step.side == "left":
            computed = hash_nodes(step.sibling, computed)
        else:
            computed = hash_nodes(computed, step.sibling)
    return computed == root
