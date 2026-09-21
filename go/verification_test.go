package ledgerrag

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
)

// buildSignedResponse produces a fully valid, self-signed QueryResponse over the
// given chunk texts -- exercising the whole build -> prove -> sign -> verify path.
func buildSignedResponse(t *testing.T, texts []string, prev []byte) QueryResponse {
	t.Helper()
	leaves := make([][]byte, len(texts))
	for i, s := range texts {
		leaves[i] = []byte(s)
	}
	tree, err := NewMerkleTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	sig := SignRoot(priv, tree.Root(), prev, uint64(tree.LeafCount()))

	var prevPtr *string
	if len(prev) > 0 {
		s := hex.EncodeToString(prev)
		prevPtr = &s
	}

	citations := make([]Citation, 0, len(texts))
	proofs := make([]Proof, 0, len(texts))
	for i, s := range texts {
		cid := fmt.Sprintf("c%d", i)
		citations = append(citations, Citation{ChunkID: cid, DocID: "doc", Seq: i, Text: s})
		steps, err := tree.InclusionProof(i)
		if err != nil {
			t.Fatal(err)
		}
		wire := make([]ProofStepModel, len(steps))
		for j, ps := range steps {
			wire[j] = ProofStepModel{Sibling: hex.EncodeToString(ps.Sibling), Side: ps.Side}
		}
		sum := sha256.Sum256([]byte(s))
		proofs = append(proofs, Proof{ChunkID: cid, LeafIndex: i, SHA256: hex.EncodeToString(sum[:]), MerklePath: wire})
	}
	return QueryResponse{
		Answer:    "answer",
		Citations: citations,
		Proofs:    proofs,
		SignedRoot: SignedRoot{
			Root:      hex.EncodeToString(tree.Root()),
			PrevRoot:  prevPtr,
			LeafCount: uint64(tree.LeafCount()),
			Signature: hex.EncodeToString(sig),
			PublicKey: hex.EncodeToString(pub),
		},
	}
}

func TestSampleResponseVerifies(t *testing.T) {
	data, err := os.ReadFile("../sample-response.json")
	if err != nil {
		t.Skipf("sample-response.json unavailable: %v", err)
	}
	resp, err := ParseQueryResponse(data)
	if err != nil {
		t.Fatal(err)
	}
	result, err := VerifyResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified || !result.SignatureOK {
		t.Fatalf("golden sample must verify, got %+v", result)
	}
	if len(result.Chunks) != 4 {
		t.Fatalf("expected 4 chunk results, got %d", len(result.Chunks))
	}
	for _, c := range result.Chunks {
		if !c.HashOK || !c.InclusionOK {
			t.Fatalf("chunk %s must be fully valid: %+v", c.ChunkID, c)
		}
	}
}

func TestSelfProducedResponseVerifies(t *testing.T) {
	resp := buildSignedResponse(t, []string{"alpha", "bravo", "charlie", "delta", "echo"}, nil)
	result, err := VerifyResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified {
		t.Fatalf("self-produced response must verify: %+v", result)
	}
}

func TestSelfProducedResponseWithPrevRootVerifies(t *testing.T) {
	prev := make([]byte, 32)
	for i := range prev {
		prev[i] = byte(i)
	}
	resp := buildSignedResponse(t, []string{"one", "two", "three"}, prev)
	result, err := VerifyResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Verified || !result.SignatureOK {
		t.Fatalf("response with prev_root must verify: %+v", result)
	}
}

func TestTamperedCitationTextFails(t *testing.T) {
	resp := buildSignedResponse(t, []string{"alpha", "bravo", "charlie"}, nil)
	resp.Citations[0].Text += " ...and refunds are DENIED."
	result, err := VerifyResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if result.Verified {
		t.Fatal("tampered citation text must fail verification")
	}
	if result.Chunks[0].HashOK || result.Chunks[0].InclusionOK {
		t.Fatalf("tampered chunk should fail both hash and inclusion: %+v", result.Chunks[0])
	}
}

func TestForgedSignatureViaLeafCountFails(t *testing.T) {
	resp := buildSignedResponse(t, []string{"alpha", "bravo"}, nil)
	resp.SignedRoot.LeafCount++
	result, err := VerifyResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if result.SignatureOK {
		t.Fatal("bumping leaf_count must break the signature")
	}
	if result.Verified {
		t.Fatal("verified must be false when the signature is broken")
	}
}

func TestHashOkUsesPlainSha256NotLeafHash(t *testing.T) {
	// Subtlety: proof.sha256 is the PLAIN SHA-256 of the chunk text, not the
	// 0x00-prefixed Merkle leaf hash. Substituting the leaf hash must fail hashOK.
	resp := buildSignedResponse(t, []string{"alpha", "bravo"}, nil)
	leafHashHex := hex.EncodeToString(HashLeaf([]byte("alpha")))
	resp.Proofs[0].SHA256 = leafHashHex
	result, err := VerifyResponse(resp)
	if err != nil {
		t.Fatal(err)
	}
	if result.Chunks[0].HashOK {
		t.Fatal("leaf hash must not satisfy the plain-sha256 integrity check")
	}
	if !result.Chunks[0].InclusionOK {
		t.Fatal("inclusion should still hold with the real Merkle path")
	}
	if result.Verified {
		t.Fatal("verified must be false when a hash check fails")
	}
}

func TestMissingCitationErrors(t *testing.T) {
	resp := buildSignedResponse(t, []string{"alpha", "bravo"}, nil)
	resp.Citations = resp.Citations[:1] // drop the citation for c1
	if _, err := VerifyResponse(resp); err == nil {
		t.Fatal("a proof without a matching citation must error")
	}
}
