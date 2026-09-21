use ledger_rag::models::{Citation, Proof, ProofStepModel, QueryResponse, SignedRoot};
use ledger_rag::{generate_keypair, sign_root, verify_response, MerkleTree};
use sha2::{Digest, Sha256};

const SAMPLE: &str = include_str!("../../sample-response.json");

/// Build a fully-signed, self-consistent response over `texts`.
fn build_signed_response(texts: &[&str], prev: Option<&[u8]>) -> QueryResponse {
    let leaves: Vec<Vec<u8>> = texts.iter().map(|s| s.as_bytes().to_vec()).collect();
    let tree = MerkleTree::new(&leaves).unwrap();
    let (sk, vk) = generate_keypair();
    let root = tree.root();
    let leaf_count = tree.leaf_count() as u64;
    let sig = sign_root(&sk, &root, prev, leaf_count);

    let citations: Vec<Citation> = texts
        .iter()
        .enumerate()
        .map(|(i, s)| Citation {
            chunk_id: format!("c{i}"),
            doc_id: "doc".to_string(),
            seq: i as i64,
            text: (*s).to_string(),
        })
        .collect();

    let proofs: Vec<Proof> = texts
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let merkle_path = tree
                .inclusion_proof(i)
                .unwrap()
                .iter()
                .map(|st| ProofStepModel {
                    sibling: hex::encode(&st.sibling),
                    side: st.side.clone(),
                })
                .collect();
            Proof {
                chunk_id: format!("c{i}"),
                leaf_index: i as i64,
                sha256: hex::encode(Sha256::digest(s.as_bytes())),
                merkle_path,
            }
        })
        .collect();

    QueryResponse {
        answer: "answer".to_string(),
        citations,
        proofs,
        signed_root: SignedRoot {
            root: hex::encode(root),
            prev_root: prev.map(hex::encode),
            leaf_count,
            signature: hex::encode(sig),
            public_key: hex::encode(vk.to_bytes()),
        },
    }
}

#[test]
fn sample_response_verifies() {
    let resp: QueryResponse = serde_json::from_str(SAMPLE).unwrap();
    let result = verify_response(&resp).unwrap();
    assert!(result.verified);
    assert!(result.signature_ok);
    assert_eq!(result.chunks.len(), 4);
    for chunk in &result.chunks {
        assert!(chunk.hash_ok);
        assert!(chunk.inclusion_ok);
    }
}

#[test]
fn self_produced_response_verifies() {
    let resp = build_signed_response(&["alpha", "beta", "gamma", "delta", "epsilon"], None);
    let result = verify_response(&resp).unwrap();
    assert!(result.verified);
    assert!(result.signature_ok);
    assert_eq!(result.chunks.len(), 5);
}

#[test]
fn self_produced_response_with_prev_root_verifies() {
    let prev = [7u8; 32];
    let resp = build_signed_response(&["one", "two", "three"], Some(&prev));
    let result = verify_response(&resp).unwrap();
    assert!(result.verified);
    assert!(result.signature_ok);
}

#[test]
fn tampered_citation_text_fails() {
    let mut resp = build_signed_response(&["alpha", "beta", "gamma"], None);
    resp.citations[1].text = "beta-TAMPERED".to_string();
    let result = verify_response(&resp).unwrap();
    assert!(!result.verified);
    assert!(result.signature_ok); // root signature still checks out
    let beta = result.chunks.iter().find(|c| c.chunk_id == "c1").unwrap();
    assert!(!beta.hash_ok);
    assert!(!beta.inclusion_ok);
}

#[test]
fn forged_signature_via_leaf_count_fails() {
    let mut resp = build_signed_response(&["a", "b"], None);
    resp.signed_root.leaf_count += 1;
    let result = verify_response(&resp).unwrap();
    assert!(!result.verified);
    assert!(!result.signature_ok);
}

#[test]
fn hash_ok_uses_plain_sha256_not_leaf_hash() {
    // The integrity field is the PLAIN SHA-256 of the text, without the 0x00
    // leaf prefix. Substituting the prefixed leaf hash must break hash_ok.
    let mut resp = build_signed_response(&["alpha"], None);
    let prefixed = {
        let mut h = Sha256::new();
        h.update([0x00]);
        h.update(b"alpha");
        hex::encode(h.finalize())
    };
    resp.proofs[0].sha256 = prefixed;
    let result = verify_response(&resp).unwrap();
    assert!(!result.chunks[0].hash_ok);
    assert!(result.chunks[0].inclusion_ok); // path itself is untouched
}

#[test]
fn missing_citation_errors() {
    let mut resp = build_signed_response(&["alpha", "beta"], None);
    resp.citations.remove(0);
    assert!(verify_response(&resp).is_err());
}
