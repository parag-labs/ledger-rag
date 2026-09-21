use ledger_rag::merkle::{hash_leaf, hash_nodes, verify_inclusion, MerkleTree, ProofStep};

fn leaves(items: &[&str]) -> Vec<Vec<u8>> {
    items.iter().map(|s| s.as_bytes().to_vec()).collect()
}

#[test]
fn single_leaf_root_is_leaf_hash() {
    let tree = MerkleTree::new(&leaves(&["only"])).unwrap();
    assert_eq!(tree.root(), hash_leaf(b"only"));
}

#[test]
fn hash_nodes_order_matters() {
    let a = hash_leaf(b"a");
    let b = hash_leaf(b"b");
    assert_ne!(hash_nodes(&a, &b), hash_nodes(&b, &a));
}

#[test]
fn leaf_and_node_hashes_are_domain_separated() {
    assert_ne!(hash_leaf(b"x").to_vec(), hash_nodes(b"x", b"").to_vec());
}

#[test]
fn valid_inclusion_proof_verifies_all_indices() {
    let items = leaves(&["a", "b", "c", "d", "e", "f", "g"]); // odd count
    let tree = MerkleTree::new(&items).unwrap();
    for (i, leaf) in items.iter().enumerate() {
        let proof = tree.inclusion_proof(i).unwrap();
        assert!(verify_inclusion(leaf, &proof, &tree.root()));
    }
}

#[test]
fn tampered_leaf_is_rejected() {
    let items = leaves(&["chunk-0", "chunk-1", "chunk-2", "chunk-3", "chunk-4"]);
    let tree = MerkleTree::new(&items).unwrap();
    let proof = tree.inclusion_proof(2).unwrap();
    assert!(!verify_inclusion(b"chunk-2-TAMPERED", &proof, &tree.root()));
}

#[test]
fn wrong_root_is_rejected() {
    let tree = MerkleTree::new(&leaves(&["a", "b", "c", "d"])).unwrap();
    let other = MerkleTree::new(&leaves(&["a", "b", "c", "e"])).unwrap();
    let proof = tree.inclusion_proof(3).unwrap();
    assert!(!verify_inclusion(b"d", &proof, &other.root()));
}

#[test]
fn proof_length_is_logarithmic() {
    let items = leaves(&["0", "1", "2", "3", "4", "5", "6", "7"]);
    let tree = MerkleTree::new(&items).unwrap();
    assert_eq!(tree.inclusion_proof(0).unwrap().len(), 3); // log2(8)
}

#[test]
fn empty_tree_errors() {
    assert!(MerkleTree::new(&[]).is_err());
}

#[test]
fn inclusion_proof_out_of_range_errors() {
    let tree = MerkleTree::new(&leaves(&["a", "b"])).unwrap();
    assert!(tree.inclusion_proof(2).is_err());
}

#[test]
fn odd_leaf_promotion_last_leaf() {
    let items = leaves(&["a", "b", "c"]);
    let tree = MerkleTree::new(&items).unwrap();
    let proof = tree.inclusion_proof(2).unwrap();
    assert!(verify_inclusion(b"c", &proof, &tree.root()));
}

#[test]
fn corrupting_proof_sibling_is_rejected() {
    let items = leaves(&["a", "b", "c", "d"]);
    let tree = MerkleTree::new(&items).unwrap();
    let mut proof = tree.inclusion_proof(1).unwrap();
    proof[0].sibling[0] ^= 0x01;
    assert!(!verify_inclusion(b"b", &proof, &tree.root()));
}

#[test]
fn manual_two_leaf_root() {
    let root = hash_nodes(&hash_leaf(b"a"), &hash_leaf(b"b"));
    let proof = vec![ProofStep {
        sibling: hash_leaf(b"b").to_vec(),
        side: "right".to_string(),
    }];
    assert!(verify_inclusion(b"a", &proof, &root));
    assert!(!verify_inclusion(b"TAMPERED", &proof, &root));
}
