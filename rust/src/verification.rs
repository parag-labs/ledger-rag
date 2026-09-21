//! The independent verifier: re-checks a proof-carrying answer using only the
//! embedded public key and proofs.

use sha2::{Digest, Sha256};

use crate::merkle::{verify_inclusion, ProofStep};
use crate::models::{ChunkResult, ProofStepModel, QueryResponse, VerificationResult};
use crate::signing::verify_root;

/// Verify a [`QueryResponse`], proving each cited chunk is committed under the
/// signed root without trusting the server that produced the answer.
pub fn verify_response(resp: &QueryResponse) -> Result<VerificationResult, String> {
    let sr = &resp.signed_root;
    let public_key = hex::decode(&sr.public_key).map_err(|e| format!("bad public_key hex: {e}"))?;
    let root = hex::decode(&sr.root).map_err(|e| format!("bad root hex: {e}"))?;
    let prev: Option<Vec<u8>> = match &sr.prev_root {
        Some(s) if !s.is_empty() => {
            Some(hex::decode(s).map_err(|e| format!("bad prev_root hex: {e}"))?)
        }
        _ => None,
    };
    let signature = hex::decode(&sr.signature).map_err(|e| format!("bad signature hex: {e}"))?;

    let sig_ok = verify_root(
        &public_key,
        &signature,
        &root,
        prev.as_deref(),
        sr.leaf_count,
    );
    let mut all_ok = sig_ok;

    let mut chunks = Vec::with_capacity(resp.proofs.len());
    for proof in &resp.proofs {
        let leaf_bytes = leaf_for(resp, &proof.chunk_id)?;
        // Integrity: the recorded hash is the PLAIN SHA-256 of the chunk text,
        // not the 0x00-prefixed leaf hash used inside the Merkle tree.
        let recomputed = hex::encode(Sha256::digest(&leaf_bytes));
        let hash_ok = recomputed == proof.sha256;
        let path = decode_path(&proof.merkle_path)?;
        let inclusion_ok = verify_inclusion(&leaf_bytes, &path, &root);
        all_ok = all_ok && hash_ok && inclusion_ok;
        chunks.push(ChunkResult {
            chunk_id: proof.chunk_id.clone(),
            hash_ok,
            inclusion_ok,
        });
    }
    Ok(VerificationResult {
        verified: all_ok,
        signature_ok: sig_ok,
        chunks,
    })
}

/// Convert wire proof steps (hex siblings) into raw-byte [`ProofStep`]s.
fn decode_path(steps: &[ProofStepModel]) -> Result<Vec<ProofStep>, String> {
    steps
        .iter()
        .map(|s| {
            let sibling = hex::decode(&s.sibling).map_err(|e| format!("bad sibling hex: {e}"))?;
            Ok(ProofStep {
                sibling,
                side: s.side.clone(),
            })
        })
        .collect()
}

/// Return the UTF-8 bytes of the citation text for a chunk id.
fn leaf_for(resp: &QueryResponse, chunk_id: &str) -> Result<Vec<u8>, String> {
    resp.citations
        .iter()
        .find(|c| c.chunk_id == chunk_id)
        .map(|c| c.text.as_bytes().to_vec())
        .ok_or_else(|| format!("no citation text for chunk {chunk_id}"))
}
