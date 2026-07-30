"""Deterministic text chunking.

Determinism matters: the same document must always produce the same chunk bytes,
because those bytes are hashed into the Merkle ledger. We normalize newlines,
strip trailing whitespace, and encode as UTF-8 before hashing.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Chunk:
    seq: int
    text: str

    def to_bytes(self) -> bytes:
        """Canonical byte representation used for hashing (must be stable)."""
        return self.text.encode("utf-8")


def normalize(text: str) -> str:
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    return "\n".join(line.rstrip() for line in text.split("\n")).strip()


def chunk_text(text: str, chunk_size: int = 800, overlap: int = 120) -> list[Chunk]:
    """Split normalized text into overlapping, deterministic chunks."""
    text = normalize(text)
    if not text:
        return []
    if overlap >= chunk_size:
        raise ValueError("overlap must be smaller than chunk_size")

    chunks: list[Chunk] = []
    start = 0
    seq = 0
    step = chunk_size - overlap
    while start < len(text):
        piece = text[start : start + chunk_size].strip()
        if piece:
            chunks.append(Chunk(seq=seq, text=piece))
            seq += 1
        start += step
    return chunks
