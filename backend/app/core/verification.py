"""Verification helpers shared by the /verify endpoint and the standalone CLI.

The whole value proposition: given only a QueryResponse and the public key, prove
each cited chunk is committed under the signed root -- without trusting the server.
"""

from __future__ import annotations

import hashlib

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from app.core.models import QueryResponse
from app.ledger.merkle import ProofStep, verify_inclusion
from app.ledger.signing import verify_root


def verify_response(resp: QueryResponse) -> dict[str, object]:
    sr = resp.signed_root
    pub = Ed25519PublicKey.from_public_bytes(bytes.fromhex(sr.public_key))

    root = bytes.fromhex(sr.root)
    prev = bytes.fromhex(sr.prev_root) if sr.prev_root else None
    sig_ok = verify_root(pub, bytes.fromhex(sr.signature), root, prev, sr.leaf_count)

    results = []
    all_ok = sig_ok
    for proof in resp.proofs:
        leaf_bytes = _leaf_for(resp, proof.chunk_id)
        # Integrity: does the stored hash still match the cited text?
        recomputed = hashlib.sha256(leaf_bytes).hexdigest()
        hash_ok = recomputed == proof.sha256
        path = [ProofStep(bytes.fromhex(s.sibling), s.side) for s in proof.merkle_path]
        incl_ok = verify_inclusion(leaf_bytes, path, root)
        ok = hash_ok and incl_ok
        all_ok = all_ok and ok
        results.append(
            {"chunk_id": proof.chunk_id, "hash_ok": hash_ok, "inclusion_ok": incl_ok}
        )

    return {"verified": all_ok, "signature_ok": sig_ok, "chunks": results}


def _leaf_for(resp: QueryResponse, chunk_id: str) -> bytes:
    for c in resp.citations:
        if c.chunk_id == chunk_id:
            return c.text.encode("utf-8")
    raise KeyError(f"no citation text for chunk {chunk_id}")
