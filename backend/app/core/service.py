"""Core service: ingest documents and answer queries with proofs.

Ties together chunker + embeddings + vector store + ledger. A single in-process
instance backs the API (swap for persistent stores in production).
"""

from __future__ import annotations

import hashlib
import uuid

from app.core.config import settings
from app.core.embeddings import embed
from app.core.models import (
    Citation,
    Proof,
    ProofStepModel,
    QueryResponse,
    SignedRoot,
)
from app.ledger.store import Ledger
from app.rag.answer import synthesize
from app.rag.chunker import chunk_text
from app.rag.vector_store import StoredChunk, VectorStore


class LedgerRagService:
    def __init__(self) -> None:
        self.ledger = Ledger()
        self.store = VectorStore()

    def ingest(self, doc_text: str, doc_id: str | None = None) -> dict[str, object]:
        doc_id = doc_id or str(uuid.uuid4())[:8]
        chunks = chunk_text(doc_text, settings.chunk_size, settings.chunk_overlap)
        embeddings = embed([c.text for c in chunks])
        for c, emb in zip(chunks, embeddings):
            leaf = c.to_bytes()
            leaf_index = self.ledger.append_leaf(leaf)
            self.store.add(
                StoredChunk(
                    chunk_id=str(uuid.uuid4())[:8],
                    doc_id=doc_id,
                    seq=c.seq,
                    text=c.text,
                    sha256=hashlib.sha256(leaf).hexdigest(),
                    leaf_index=leaf_index,
                    embedding=emb,
                )
            )
        return {"doc_id": doc_id, "chunks": len(chunks), "root": self.ledger.head.root.hex()}

    def query(self, question: str) -> QueryResponse:
        q_emb = embed([question])[0]
        hits = self.store.search(q_emb, settings.top_k)
        answer = synthesize(question, hits)

        citations, proofs = [], []
        for h in hits:
            citations.append(Citation(chunk_id=h.chunk_id, doc_id=h.doc_id, seq=h.seq, text=h.text))
            path = self.ledger.inclusion_proof(h.leaf_index)
            proofs.append(
                Proof(
                    chunk_id=h.chunk_id,
                    leaf_index=h.leaf_index,
                    sha256=h.sha256,
                    merkle_path=[ProofStepModel(sibling=s.sibling.hex(), side=s.side) for s in path],
                )
            )

        head = self.ledger.head
        signed = SignedRoot(
            root=head.root.hex(),
            prev_root=head.prev_root.hex() if head.prev_root else None,
            leaf_count=head.leaf_count,
            signature=head.signature.hex(),
            public_key=self.ledger.public_key.public_bytes_raw().hex(),
        )
        return QueryResponse(answer=answer, citations=citations, proofs=proofs, signed_root=signed)
