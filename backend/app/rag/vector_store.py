"""In-memory vector store with cosine retrieval (zero-dependency default).

Keeps the quickstart friction-free. A pgvector adapter can implement the same
interface for production (satisfies the 'relational DB / Postgres' signal).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.core.embeddings import cosine


@dataclass
class StoredChunk:
    chunk_id: str
    doc_id: str
    seq: int
    text: str
    sha256: str
    leaf_index: int
    embedding: list[float]


@dataclass
class VectorStore:
    _items: list[StoredChunk] = field(default_factory=list)

    def add(self, chunk: StoredChunk) -> None:
        self._items.append(chunk)

    def all(self) -> list[StoredChunk]:
        return list(self._items)

    def __len__(self) -> int:
        return len(self._items)

    def search(self, query_embedding: list[float], top_k: int = 4) -> list[StoredChunk]:
        scored = sorted(
            self._items,
            key=lambda c: cosine(query_embedding, c.embedding),
            reverse=True,
        )
        return scored[:top_k]
