use ledger_rag::signing::{generate_keypair, sign_root, verify_root};

#[test]
fn signed_root_verifies() {
    let (sk, vk) = generate_keypair();
    let root = b"root-bytes-that-are-32-long-abcd";
    let sig = sign_root(&sk, root, None, 2);
    assert!(verify_root(&vk.to_bytes(), &sig, root, None, 2));
}

#[test]
fn altered_leaf_count_fails() {
    let (sk, vk) = generate_keypair();
    let root = b"root-bytes-that-are-32-long-abcd";
    let sig = sign_root(&sk, root, None, 2);
    assert!(!verify_root(&vk.to_bytes(), &sig, root, None, 3));
}

#[test]
fn wrong_key_rejected() {
    let (sk_real, _vk_real) = generate_keypair();
    let (_sk_attacker, vk_attacker) = generate_keypair();
    let root = b"root-bytes-that-are-32-long-abcd";
    let sig = sign_root(&sk_real, root, None, 10);
    assert!(!verify_root(&vk_attacker.to_bytes(), &sig, root, None, 10));
}

#[test]
fn prev_root_changes_signature() {
    let (sk, vk) = generate_keypair();
    let root = b"root-bytes-that-are-32-long-abcd";
    let prev = b"prev-bytes-that-are-32-long-abcd";
    let sig = sign_root(&sk, root, Some(prev), 5);
    assert!(verify_root(&vk.to_bytes(), &sig, root, Some(prev), 5));
    // Dropping prev_root changes the signed message and must fail.
    assert!(!verify_root(&vk.to_bytes(), &sig, root, None, 5));
}

#[test]
fn verify_root_rejects_malformed_sizes() {
    let (sk, vk) = generate_keypair();
    let root = b"root";
    let sig = sign_root(&sk, root, None, 1);
    // Short public key and short signature must be rejected, not panic.
    assert!(!verify_root(&[0u8; 4], &sig, root, None, 1));
    assert!(!verify_root(&vk.to_bytes(), &[0u8, 1u8], root, None, 1));
}
