package ledgerrag

import (
	"crypto/ed25519"
	"testing"
)

func TestSignedRootVerifies(t *testing.T) {
	priv, pub, err := GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	tree, _ := NewMerkleTree([][]byte{[]byte("a"), []byte("b")})
	sig := SignRoot(priv, tree.Root(), nil, uint64(tree.LeafCount()))
	if !VerifyRoot(pub, sig, tree.Root(), nil, uint64(tree.LeafCount())) {
		t.Fatal("valid signature should verify")
	}
}

func TestAlteredLeafCountFailsSignature(t *testing.T) {
	priv, pub, _ := GenerateKeypair()
	tree, _ := NewMerkleTree([][]byte{[]byte("a"), []byte("b")})
	sig := SignRoot(priv, tree.Root(), nil, uint64(tree.LeafCount()))
	if VerifyRoot(pub, sig, tree.Root(), nil, uint64(tree.LeafCount())+1) {
		t.Fatal("altering leaf_count must break the signature")
	}
}

func TestWrongKeyRejected(t *testing.T) {
	privReal, _, _ := GenerateKeypair()
	_, pubAttacker, _ := GenerateKeypair()
	root := []byte("0123456789abcdef0123456789abcdef")
	sig := SignRoot(privReal, root, nil, 10)
	if VerifyRoot(pubAttacker, sig, root, nil, 10) {
		t.Fatal("signature from a different key must be rejected")
	}
}

func TestPrevRootChangesSignature(t *testing.T) {
	priv, pub, _ := GenerateKeypair()
	root := []byte("root-bytes-32-xxxxxxxxxxxxxxxxxxx")
	prev := []byte("prev-bytes-32-xxxxxxxxxxxxxxxxxxx")
	sig := SignRoot(priv, root, prev, 5)
	if !VerifyRoot(pub, sig, root, prev, 5) {
		t.Fatal("signature with prev_root should verify with the same prev_root")
	}
	if VerifyRoot(pub, sig, root, nil, 5) {
		t.Fatal("dropping prev_root must break the signature")
	}
}

func TestVerifyRootRejectsMalformedSizes(t *testing.T) {
	priv, pub, _ := GenerateKeypair()
	root := []byte("some-root")
	sig := SignRoot(priv, root, nil, 1)
	if VerifyRoot(ed25519.PublicKey{0x00}, sig, root, nil, 1) {
		t.Fatal("short public key must be rejected without panicking")
	}
	if VerifyRoot(pub, []byte{0x00, 0x01}, root, nil, 1) {
		t.Fatal("short signature must be rejected without panicking")
	}
}
