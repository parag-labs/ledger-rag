package ledgerrag

// Citation is a cited source chunk carried by a QueryResponse.
type Citation struct {
	ChunkID string `json:"chunk_id"`
	DocID   string `json:"doc_id"`
	Seq     int    `json:"seq"`
	Text    string `json:"text"`
}

// ProofStepModel is one Merkle-path step on the wire: a hex sibling and its side.
type ProofStepModel struct {
	Sibling string `json:"sibling"`
	Side    string `json:"side"`
}

// Proof is a Merkle inclusion proof for a single cited chunk.
type Proof struct {
	ChunkID    string           `json:"chunk_id"`
	LeafIndex  int              `json:"leaf_index"`
	SHA256     string           `json:"sha256"`
	MerklePath []ProofStepModel `json:"merkle_path"`
}

// SignedRoot is the signed Merkle-root envelope. PrevRoot is a pointer so a JSON
// null (no predecessor) is distinguishable from an empty string.
type SignedRoot struct {
	Root      string  `json:"root"`
	PrevRoot  *string `json:"prev_root"`
	LeafCount uint64  `json:"leaf_count"`
	Signature string  `json:"signature"`
	PublicKey string  `json:"public_key"`
}

// QueryResponse is a proof-carrying answer from the RAG server.
type QueryResponse struct {
	Answer     string     `json:"answer"`
	Citations  []Citation `json:"citations"`
	Proofs     []Proof    `json:"proofs"`
	SignedRoot SignedRoot `json:"signed_root"`
}

// ChunkResult is the per-chunk verification outcome.
type ChunkResult struct {
	ChunkID     string `json:"chunk_id"`
	HashOK      bool   `json:"hash_ok"`
	InclusionOK bool   `json:"inclusion_ok"`
}

// VerificationResult is the overall verification outcome.
type VerificationResult struct {
	Verified    bool          `json:"verified"`
	SignatureOK bool          `json:"signature_ok"`
	Chunks      []ChunkResult `json:"chunks"`
}
