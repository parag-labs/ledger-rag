// DTOs mirroring the Python QueryResponse JSON schema (snake_case on the wire).

/** A cited source chunk carried by a QueryResponse. */
export interface Citation {
  chunk_id: string;
  doc_id: string;
  seq: number;
  text: string;
}

/** One Merkle-path step on the wire: a hex sibling and its side. */
export interface ProofStepModel {
  sibling: string;
  side: string;
}

/** A Merkle inclusion proof for a single cited chunk. */
export interface Proof {
  chunk_id: string;
  leaf_index: number;
  sha256: string;
  merkle_path: ProofStepModel[];
}

/** The signed Merkle-root envelope. `prev_root` is null when there is no predecessor. */
export interface SignedRoot {
  root: string;
  prev_root: string | null;
  leaf_count: number;
  signature: string;
  public_key: string;
}

/** A proof-carrying answer from the RAG server. */
export interface QueryResponse {
  answer: string;
  citations: Citation[];
  proofs: Proof[];
  signed_root: SignedRoot;
}

/** The per-chunk verification outcome. */
export interface ChunkResult {
  chunk_id: string;
  hash_ok: boolean;
  inclusion_ok: boolean;
}

/** The overall verification outcome. */
export interface VerificationResult {
  verified: boolean;
  signature_ok: boolean;
  chunks: ChunkResult[];
}
