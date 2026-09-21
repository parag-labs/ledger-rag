//! Ed25519 signing for ledger roots.
//!
//! The server signs each Merkle root so clients trust roots by a known public
//! key, not by the query path. A verifier only needs the public key.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

/// Generate a fresh Ed25519 keypair from the operating system's CSPRNG.
pub fn generate_keypair() -> (SigningKey, VerifyingKey) {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).expect("OS RNG unavailable");
    let signing_key = SigningKey::from_bytes(&seed);
    let verifying_key = signing_key.verifying_key();
    (signing_key, verifying_key)
}

/// Sign the tuple `(root || prev_root || leaf_count)` to chain history. A `None`
/// `prev_root` is treated as absent (empty bytes).
pub fn sign_root(
    signing_key: &SigningKey,
    root: &[u8],
    prev_root: Option<&[u8]>,
    leaf_count: u64,
) -> [u8; 64] {
    let message = root_message(root, prev_root, leaf_count);
    signing_key.sign(&message).to_bytes()
}

/// Verify an Ed25519 signature over `(root || prev_root || leaf_count)` using a
/// raw 32-byte public key. Returns `false` for malformed keys or signatures.
pub fn verify_root(
    public_key: &[u8],
    signature: &[u8],
    root: &[u8],
    prev_root: Option<&[u8]>,
    leaf_count: u64,
) -> bool {
    let pk_bytes: [u8; 32] = match public_key.try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let verifying_key = match VerifyingKey::from_bytes(&pk_bytes) {
        Ok(key) => key,
        Err(_) => return false,
    };
    let sig_bytes: [u8; 64] = match signature.try_into() {
        Ok(bytes) => bytes,
        Err(_) => return false,
    };
    let signature = Signature::from_bytes(&sig_bytes);
    let message = root_message(root, prev_root, leaf_count);
    verifying_key.verify(&message, &signature).is_ok()
}

/// Build the signed message: root, then the optional previous root, then the
/// leaf count as 8 big-endian bytes.
pub fn root_message(root: &[u8], prev_root: Option<&[u8]>, leaf_count: u64) -> Vec<u8> {
    let prev_len = prev_root.map_or(0, <[u8]>::len);
    let mut message = Vec::with_capacity(root.len() + prev_len + 8);
    message.extend_from_slice(root);
    if let Some(prev) = prev_root {
        message.extend_from_slice(prev);
    }
    message.extend_from_slice(&leaf_count.to_be_bytes());
    message
}
