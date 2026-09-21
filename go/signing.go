package ledgerrag

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
)

// GenerateKeypair generates a fresh Ed25519 keypair.
func GenerateKeypair() (ed25519.PrivateKey, ed25519.PublicKey, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	return priv, pub, nil
}

// SignRoot signs the tuple (root || prev_root || leaf_count) to chain history.
// A nil prevRoot is treated as absent (empty bytes).
func SignRoot(priv ed25519.PrivateKey, root, prevRoot []byte, leafCount uint64) []byte {
	return ed25519.Sign(priv, rootMessage(root, prevRoot, leafCount))
}

// VerifyRoot verifies an Ed25519 signature over (root || prev_root || leaf_count).
// A nil prevRoot is treated as absent. It returns false (rather than panicking)
// for malformed key or signature lengths.
func VerifyRoot(pub ed25519.PublicKey, signature, root, prevRoot []byte, leafCount uint64) bool {
	if len(pub) != ed25519.PublicKeySize || len(signature) != ed25519.SignatureSize {
		return false
	}
	return ed25519.Verify(pub, rootMessage(root, prevRoot, leafCount), signature)
}

// rootMessage builds the signed message: root, then the optional previous root,
// then the leaf count as 8 big-endian bytes.
func rootMessage(root, prevRoot []byte, leafCount uint64) []byte {
	msg := make([]byte, 0, len(root)+len(prevRoot)+8)
	msg = append(msg, root...)
	msg = append(msg, prevRoot...)
	var lc [8]byte
	binary.BigEndian.PutUint64(lc[:], leafCount)
	return append(msg, lc[:]...)
}
