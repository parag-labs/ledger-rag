"""Benchmark harness for ledger-rag's tamper-evident ledger.

Measures the three things that decide whether "every answer ships a proof" is
practical at scale:

1. Proof size vs ledger size - a Merkle inclusion proof is O(log n) sibling hashes,
   so a proof over a million entries is tiny and grows only logarithmically.
2. Proof verification throughput - how many proofs/sec you can check, since a
   verifier does this per answer.
3. Signature verify throughput - the ed25519 check on the signed root.

Run: python bench/benchmark.py
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "backend"))

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from app.ledger.merkle import MerkleTree, verify_inclusion
from app.ledger.signing import generate_keypair, sign_root, verify_root

RESULTS = Path(__file__).resolve().parent / "results"
RESULTS.mkdir(exist_ok=True)


def bench_proof_size() -> dict:
    sizes = [1, 10, 100, 1_000, 10_000, 100_000, 1_000_000]
    steps = []
    HASH_BYTES = 32
    for n in sizes:
        leaves = [f"leaf-{i}".encode() for i in range(n)]
        tree = MerkleTree(leaves)
        proof = tree.inclusion_proof(n // 2)
        steps.append(len(proof))

    proof_bytes = [s * HASH_BYTES for s in steps]

    fig, ax = plt.subplots(figsize=(6.5, 4))
    ax.semilogx(sizes, proof_bytes, "o-", color="tab:blue")
    ax.set_xlabel("ledger entries (log scale)")
    ax.set_ylabel("proof size (bytes)")
    ax.set_title("ledger-rag: proof size is O(log n)")
    ax.grid(True, alpha=0.3, which="both")
    fig.tight_layout()
    fig.savefig(RESULTS / "proof_size.png", dpi=110)
    plt.close(fig)

    return {"entries": sizes, "proof_steps": steps, "proof_bytes": proof_bytes}


def bench_verify_throughput() -> dict:
    # Build one large tree, then verify many random proofs against its root.
    n = 100_000
    leaves = [os.urandom(24) for _ in range(n)]
    tree = MerkleTree(leaves)
    root = tree.root

    indices = list(range(0, n, max(1, n // 5000)))
    proofs = [(leaves[i], tree.inclusion_proof(i)) for i in indices]

    start = time.perf_counter()
    for leaf, proof in proofs:
        assert verify_inclusion(leaf, proof, root)
    elapsed = time.perf_counter() - start
    proofs_per_sec = len(proofs) / elapsed

    # Signature verification throughput on the signed root.
    priv, pub = generate_keypair()
    sig = sign_root(priv, root, None, n)
    sig_iters = 5000
    start = time.perf_counter()
    for _ in range(sig_iters):
        verify_root(pub, sig, root, None, n)
    sig_elapsed = time.perf_counter() - start

    result = {
        "tree_entries": n,
        "proofs_verified": len(proofs),
        "proof_verifies_per_sec": int(proofs_per_sec),
        "us_per_proof_verify": round(elapsed / len(proofs) * 1e6, 2),
        "sig_verifies_per_sec": int(sig_iters / sig_elapsed),
    }

    fig, ax = plt.subplots(figsize=(6.5, 4))
    labels = ["merkle proof\nverify", "ed25519 root\nverify"]
    values = [result["proof_verifies_per_sec"], result["sig_verifies_per_sec"]]
    ax.bar(labels, values, color=["tab:blue", "tab:green"])
    for i, v in enumerate(values):
        ax.text(i, v, f"{v:,}/s", ha="center", va="bottom")
    ax.set_ylabel("verifications per second")
    ax.set_title(f"ledger-rag: verification throughput ({n:,}-entry ledger)")
    ax.grid(True, axis="y", alpha=0.3)
    fig.tight_layout()
    fig.savefig(RESULTS / "verify_throughput.png", dpi=110)
    plt.close(fig)

    return result


def main() -> None:
    summary = {
        "proof_size": bench_proof_size(),
        "verify_throughput": bench_verify_throughput(),
    }
    (RESULTS / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()
