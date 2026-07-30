"""Append-only ledger store: chains signed Merkle roots over time.

Every ingest rebuilds the Merkle tree over all leaves and appends a new signed
entry whose signature covers (root, prev_root, leaf_count) -- so the history of
roots is tamper-evident and independently verifiable with the public key.
"""

from __future__ import annotations

from dataclasses import dataclass

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

from app.ledger.merkle import MerkleTree, ProofStep
from app.ledger.signing import generate_keypair, sign_root, verify_root


@dataclass
class LedgerEntry:
    root: bytes
    prev_root: bytes | None
    leaf_count: int
    signature: bytes


class Ledger:
    """Holds leaves, the current Merkle tree, and the chain of signed roots."""

    def __init__(self, priv: Ed25519PrivateKey | None = None):
        self._priv = priv or generate_keypair()[0]
        self._pub: Ed25519PublicKey = self._priv.public_key()
        self._leaves: list[bytes] = []
        self._tree: MerkleTree | None = None
        self._chain: list[LedgerEntry] = []

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self._pub

    def append_leaf(self, leaf: bytes) -> int:
        """Append a leaf; return its index. Re-signs the root."""
        self._leaves.append(leaf)
        index = len(self._leaves) - 1
        self._reseal()
        return index

    def _reseal(self) -> None:
        self._tree = MerkleTree(self._leaves)
        prev = self._chain[-1].root if self._chain else None
        sig = sign_root(self._priv, self._tree.root, prev, self._tree.leaf_count)
        self._chain.append(
            LedgerEntry(self._tree.root, prev, self._tree.leaf_count, sig)
        )

    @property
    def head(self) -> LedgerEntry:
        if not self._chain:
            raise RuntimeError("ledger is empty")
        return self._chain[-1]

    @property
    def history(self) -> list[LedgerEntry]:
        return list(self._chain)

    def inclusion_proof(self, leaf_index: int) -> list[ProofStep]:
        assert self._tree is not None
        return self._tree.inclusion_proof(leaf_index)

    def verify_head_signature(self) -> bool:
        h = self.head
        return verify_root(self._pub, h.signature, h.root, h.prev_root, h.leaf_count)
