package ledgerrag

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// VerifyResponse verifies a QueryResponse using only the embedded public key and
// proofs, proving each cited chunk is committed under the signed root without
// trusting the server that produced the answer.
func VerifyResponse(resp QueryResponse) (VerificationResult, error) {
	sr := resp.SignedRoot
	pub, err := hex.DecodeString(sr.PublicKey)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("bad public_key hex: %w", err)
	}
	root, err := hex.DecodeString(sr.Root)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("bad root hex: %w", err)
	}
	var prev []byte
	if sr.PrevRoot != nil && *sr.PrevRoot != "" {
		prev, err = hex.DecodeString(*sr.PrevRoot)
		if err != nil {
			return VerificationResult{}, fmt.Errorf("bad prev_root hex: %w", err)
		}
	}
	sig, err := hex.DecodeString(sr.Signature)
	if err != nil {
		return VerificationResult{}, fmt.Errorf("bad signature hex: %w", err)
	}

	sigOK := VerifyRoot(pub, sig, root, prev, sr.LeafCount)
	allOK := sigOK

	results := make([]ChunkResult, 0, len(resp.Proofs))
	for _, proof := range resp.Proofs {
		leafBytes, err := leafFor(resp, proof.ChunkID)
		if err != nil {
			return VerificationResult{}, err
		}
		// Integrity: the recorded hash is the plain SHA-256 of the chunk text
		// (NOT the 0x00-prefixed leaf hash used inside the Merkle tree).
		sum := sha256.Sum256(leafBytes)
		hashOK := hex.EncodeToString(sum[:]) == proof.SHA256
		path, err := decodePath(proof.MerklePath)
		if err != nil {
			return VerificationResult{}, err
		}
		inclOK := VerifyInclusion(leafBytes, path, root)
		allOK = allOK && hashOK && inclOK
		results = append(results, ChunkResult{ChunkID: proof.ChunkID, HashOK: hashOK, InclusionOK: inclOK})
	}
	return VerificationResult{Verified: allOK, SignatureOK: sigOK, Chunks: results}, nil
}

// decodePath converts wire proof steps (hex siblings) into raw-byte ProofSteps.
func decodePath(steps []ProofStepModel) ([]ProofStep, error) {
	path := make([]ProofStep, 0, len(steps))
	for _, s := range steps {
		sib, err := hex.DecodeString(s.Sibling)
		if err != nil {
			return nil, fmt.Errorf("bad sibling hex: %w", err)
		}
		path = append(path, ProofStep{Sibling: sib, Side: s.Side})
	}
	return path, nil
}

// leafFor returns the UTF-8 bytes of the citation text for a chunk id.
func leafFor(resp QueryResponse, chunkID string) ([]byte, error) {
	for _, c := range resp.Citations {
		if c.ChunkID == chunkID {
			return []byte(c.Text), nil
		}
	}
	return nil, fmt.Errorf("no citation text for chunk %s", chunkID)
}

// ParseQueryResponse decodes a QueryResponse from its JSON representation.
func ParseQueryResponse(data []byte) (QueryResponse, error) {
	var resp QueryResponse
	if err := json.Unmarshal(data, &resp); err != nil {
		return QueryResponse{}, err
	}
	return resp, nil
}
