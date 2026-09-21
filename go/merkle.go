// Package ledgerrag is a cross-language port of LedgerRAG's cryptographic core:
// a SHA-256 Merkle tree with inclusion proofs and Ed25519-signed roots, plus the
// independent verifier that re-checks a proof-carrying answer without trusting
// the server that produced it.
//
// The hashing and signing rules are reproduced exactly from the Python
// reference so a proof generated in Python (or C#/Java) verifies here too:
//
//   - leaf hash = SHA-256(0x00 || utf8(text))
//   - node hash = SHA-256(0x01 || left || right)
//   - root msg  = root || prev_root(optional) || leaf_count (8 bytes, big-endian)
//   - signature = Ed25519 over root msg, verified with the raw public key
package ledgerrag

import (
	"bytes"
	"crypto/sha256"
	"errors"
)

// leafPrefix and nodePrefix domain-separate leaves from internal nodes so a leaf
// hash can never be reinterpreted as an internal node (second-preimage defence).
var (
	leafPrefix = []byte{0x00}
	nodePrefix = []byte{0x01}
)

// HashLeaf hashes a leaf value (a chunk's normalized bytes) with the 0x00 prefix.
func HashLeaf(data []byte) []byte {
	h := sha256.New()
	h.Write(leafPrefix)
	h.Write(data)
	return h.Sum(nil)
}

// HashNodes hashes two child nodes into their parent with the 0x01 prefix.
func HashNodes(left, right []byte) []byte {
	h := sha256.New()
	h.Write(nodePrefix)
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// ProofStep is one step in a Merkle inclusion proof: a sibling hash and the side
// it sits on ("left" or "right").
type ProofStep struct {
	Sibling []byte
	Side    string
}

// MerkleTree is an immutable Merkle tree built from a list of leaf byte-strings.
type MerkleTree struct {
	leafHashes [][]byte
	levels     [][][]byte
}

// NewMerkleTree builds a Merkle tree over leaves. It returns an error when the
// leaf list is empty.
func NewMerkleTree(leaves [][]byte) (*MerkleTree, error) {
	if len(leaves) == 0 {
		return nil, errors.New("MerkleTree requires at least one leaf")
	}
	leafHashes := make([][]byte, len(leaves))
	for i, x := range leaves {
		leafHashes[i] = HashLeaf(x)
	}
	return &MerkleTree{leafHashes: leafHashes, levels: buildLevels(leafHashes)}, nil
}

// buildLevels folds the leaf hashes up to the root, promoting (duplicating) the
// last node when a level has an odd number of entries.
func buildLevels(leafHashes [][]byte) [][][]byte {
	levels := [][][]byte{leafHashes}
	current := leafHashes
	for len(current) > 1 {
		next := make([][]byte, 0, (len(current)+1)/2)
		for i := 0; i < len(current); i += 2 {
			left := current[i]
			var right []byte
			if i+1 < len(current) {
				right = current[i+1]
			} else {
				right = current[i]
			}
			next = append(next, HashNodes(left, right))
		}
		levels = append(levels, next)
		current = next
	}
	return levels
}

// Root returns the Merkle root hash.
func (t *MerkleTree) Root() []byte {
	return t.levels[len(t.levels)-1][0]
}

// LeafCount returns the number of leaves committed by the tree.
func (t *MerkleTree) LeafCount() int {
	return len(t.leafHashes)
}

// LeafHash returns the (0x00-prefixed) hash of the leaf at index.
func (t *MerkleTree) LeafHash(index int) []byte {
	return t.leafHashes[index]
}

// InclusionProof returns the Merkle path proving the leaf at index is under Root.
func (t *MerkleTree) InclusionProof(index int) ([]ProofStep, error) {
	if index < 0 || index >= t.LeafCount() {
		return nil, errors.New("leaf index out of range")
	}
	proof := []ProofStep{}
	idx := index
	for l := 0; l < len(t.levels)-1; l++ { // every level except the root
		level := t.levels[l]
		var siblingIdx int
		var side string
		if idx%2 == 1 {
			siblingIdx = idx - 1
			side = "left"
		} else {
			if idx+1 < len(level) {
				siblingIdx = idx + 1
			} else {
				siblingIdx = idx
			}
			side = "right"
		}
		proof = append(proof, ProofStep{Sibling: level[siblingIdx], Side: side})
		idx /= 2
	}
	return proof, nil
}

// VerifyInclusion independently confirms leafData is committed under root, given
// only the leaf bytes, the proof, and a (trusted) root.
func VerifyInclusion(leafData []byte, proof []ProofStep, root []byte) bool {
	computed := HashLeaf(leafData)
	for _, step := range proof {
		if step.Side == "left" {
			computed = HashNodes(step.Sibling, computed)
		} else {
			computed = HashNodes(computed, step.Sibling)
		}
	}
	return bytes.Equal(computed, root)
}
