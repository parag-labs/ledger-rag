//! DTOs mirroring the Python `QueryResponse` JSON schema (snake_case on the wire).

use serde::{Deserialize, Serialize};

/// A cited source chunk carried by a [`QueryResponse`].
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Citation {
    pub chunk_id: String,
    pub doc_id: String,
    pub seq: i64,
    pub text: String,
}

/// One Merkle-path step on the wire: a hex sibling and its side.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ProofStepModel {
    pub sibling: String,
    pub side: String,
}

/// A Merkle inclusion proof for a single cited chunk.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Proof {
    pub chunk_id: String,
    pub leaf_index: i64,
    pub sha256: String,
    pub merkle_path: Vec<ProofStepModel>,
}

/// The signed Merkle-root envelope. `prev_root` is `None` when there is no
/// predecessor (JSON `null`).
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct SignedRoot {
    pub root: String,
    pub prev_root: Option<String>,
    pub leaf_count: u64,
    pub signature: String,
    pub public_key: String,
}

/// A proof-carrying answer from the RAG server.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct QueryResponse {
    pub answer: String,
    pub citations: Vec<Citation>,
    pub proofs: Vec<Proof>,
    pub signed_root: SignedRoot,
}

/// The per-chunk verification outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ChunkResult {
    pub chunk_id: String,
    pub hash_ok: bool,
    pub inclusion_ok: bool,
}

/// The overall verification outcome.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerificationResult {
    pub verified: bool,
    pub signature_ok: bool,
    pub chunks: Vec<ChunkResult>,
}
