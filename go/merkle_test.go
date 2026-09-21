package ledgerrag

import (
	"bytes"
	"testing"
)

func TestSingleLeafRootIsLeafHash(t *testing.T) {
	tree, err := NewMerkleTree([][]byte{[]byte("only")})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(tree.Root(), HashLeaf([]byte("only"))) {
		t.Fatal("single-leaf root must equal the leaf hash")
	}
}

func TestHashNodesOrderMatters(t *testing.T) {
	a := HashLeaf([]byte("a"))
	b := HashLeaf([]byte("b"))
	if bytes.Equal(HashNodes(a, b), HashNodes(b, a)) {
		t.Fatal("node hash must depend on child order")
	}
}

func TestLeafAndNodeHashesAreDomainSeparated(t *testing.T) {
	// A leaf hash must never collide with a node hash of the same bytes.
	if bytes.Equal(HashLeaf([]byte("x")), HashNodes([]byte("x"), nil)) {
		t.Fatal("leaf and node hashing must be domain-separated")
	}
}

func TestValidInclusionProofVerifiesAllIndices(t *testing.T) {
	leaves := [][]byte{}
	for i := 0; i < 7; i++ { // odd count on purpose
		leaves = append(leaves, []byte{byte('a' + i)})
	}
	tree, err := NewMerkleTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	for i, leaf := range leaves {
		proof, err := tree.InclusionProof(i)
		if err != nil {
			t.Fatal(err)
		}
		if !VerifyInclusion(leaf, proof, tree.Root()) {
			t.Fatalf("leaf %d should verify", i)
		}
	}
}

func TestTamperedLeafIsRejected(t *testing.T) {
	leaves := [][]byte{[]byte("chunk-0"), []byte("chunk-1"), []byte("chunk-2"), []byte("chunk-3"), []byte("chunk-4")}
	tree, err := NewMerkleTree(leaves)
	if err != nil {
		t.Fatal(err)
	}
	proof, err := tree.InclusionProof(2)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyInclusion([]byte("chunk-2-TAMPERED"), proof, tree.Root()) {
		t.Fatal("tampered leaf must not verify")
	}
}

func TestWrongRootIsRejected(t *testing.T) {
	tree, _ := NewMerkleTree([][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")})
	other, _ := NewMerkleTree([][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("e")})
	proof, err := tree.InclusionProof(3)
	if err != nil {
		t.Fatal(err)
	}
	if VerifyInclusion([]byte("d"), proof, other.Root()) {
		t.Fatal("proof must not verify against a different root")
	}
}

func TestProofLengthIsLogarithmic(t *testing.T) {
	leaves := [][]byte{}
	for i := 0; i < 8; i++ {
		leaves = append(leaves, []byte{byte('0' + i)})
	}
	tree, _ := NewMerkleTree(leaves)
	proof, err := tree.InclusionProof(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) != 3 { // log2(8)
		t.Fatalf("expected proof length 3, got %d", len(proof))
	}
}

func TestEmptyTreeErrors(t *testing.T) {
	if _, err := NewMerkleTree(nil); err == nil {
		t.Fatal("empty tree must error")
	}
}

func TestInclusionProofOutOfRangeErrors(t *testing.T) {
	tree, _ := NewMerkleTree([][]byte{[]byte("a"), []byte("b")})
	if _, err := tree.InclusionProof(-1); err == nil {
		t.Fatal("negative index must error")
	}
	if _, err := tree.InclusionProof(2); err == nil {
		t.Fatal("index >= leaf count must error")
	}
}

func TestOddLeafPromotionLastLeaf(t *testing.T) {
	// A 3-leaf tree pairs the last leaf with itself when promoting.
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c")}
	tree, _ := NewMerkleTree(leaves)
	proof, err := tree.InclusionProof(2)
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyInclusion([]byte("c"), proof, tree.Root()) {
		t.Fatal("promoted last leaf should still verify")
	}
}

func TestCorruptingProofSiblingIsRejected(t *testing.T) {
	leaves := [][]byte{[]byte("a"), []byte("b"), []byte("c"), []byte("d")}
	tree, _ := NewMerkleTree(leaves)
	proof, err := tree.InclusionProof(1)
	if err != nil {
		t.Fatal(err)
	}
	corrupted := make([]ProofStep, len(proof))
	copy(corrupted, proof)
	corrupted[0].Sibling = append([]byte{}, corrupted[0].Sibling...)
	corrupted[0].Sibling[0] ^= 0x01
	if VerifyInclusion([]byte("b"), corrupted, tree.Root()) {
		t.Fatal("corrupted sibling must not verify")
	}
}

func TestManualTwoLeafRoot(t *testing.T) {
	a := []byte("a")
	b := []byte("b")
	root := HashNodes(HashLeaf(a), HashLeaf(b))
	proof := []ProofStep{{Sibling: HashLeaf(b), Side: "right"}}
	if !VerifyInclusion(a, proof, root) {
		t.Fatal("hand-built proof should verify")
	}
	if VerifyInclusion([]byte("TAMPERED"), proof, root) {
		t.Fatal("wrong leaf must not verify against hand-built root")
	}
}
