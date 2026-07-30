"""Pydantic response models for the verifiable RAG API."""

from __future__ import annotations

from pydantic import BaseModel


class Citation(BaseModel):
    chunk_id: str
    doc_id: str
    seq: int
    text: str


class ProofStepModel(BaseModel):
    sibling: str  # hex
    side: str     # "left" | "right"


class Proof(BaseModel):
    chunk_id: str
    leaf_index: int
    sha256: str          # hex of the leaf's raw bytes (chunk text utf-8)
    merkle_path: list[ProofStepModel]


class SignedRoot(BaseModel):
    root: str            # hex
    prev_root: str | None
    leaf_count: int
    signature: str       # hex
    public_key: str      # hex (raw ed25519)


class QueryRequest(BaseModel):
    question: str


class QueryResponse(BaseModel):
    answer: str
    citations: list[Citation]
    proofs: list[Proof]
    signed_root: SignedRoot
