"""Ed25519 signing for ledger roots.

The server signs each Merkle root so that clients can trust roots based on a
known public key -- not on the query path. A verifier only needs the public key
to confirm a root is authentic.
"""

from __future__ import annotations

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


def generate_keypair() -> tuple[Ed25519PrivateKey, Ed25519PublicKey]:
    priv = Ed25519PrivateKey.generate()
    return priv, priv.public_key()


def sign_root(priv: Ed25519PrivateKey, root: bytes, prev_root: bytes | None, leaf_count: int) -> bytes:
    """Sign the tuple (root || prev_root || leaf_count) to chain history."""
    message = _root_message(root, prev_root, leaf_count)
    return priv.sign(message)


def verify_root(
    pub: Ed25519PublicKey,
    signature: bytes,
    root: bytes,
    prev_root: bytes | None,
    leaf_count: int,
) -> bool:
    message = _root_message(root, prev_root, leaf_count)
    try:
        pub.verify(signature, message)
        return True
    except InvalidSignature:
        return False


def _root_message(root: bytes, prev_root: bytes | None, leaf_count: int) -> bytes:
    return root + (prev_root or b"") + leaf_count.to_bytes(8, "big")
