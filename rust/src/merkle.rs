//! SHA-256 Merkle tree with domain-separated leaves and inclusion proofs.

use sha2::{Digest, Sha256};

/// Domain-separation prefix for leaf hashes.
const LEAF_PREFIX: u8 = 0x00;
/// Domain-separation prefix for internal-node hashes.
const NODE_PREFIX: u8 = 0x01;

/// Hash a leaf value (a chunk's normalized bytes) with the `0x00` prefix.
pub fn hash_leaf(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([LEAF_PREFIX]);
    hasher.update(data);
    hasher.finalize().into()
}

/// Hash two child nodes into their parent with the `0x01` prefix.
pub fn hash_nodes(left: &[u8], right: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update([NODE_PREFIX]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// One step in a Merkle inclusion proof: a sibling hash and the side it sits on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofStep {
    /// The sibling hash (raw bytes).
    pub sibling: Vec<u8>,
    /// Which side the sibling is on: `"left"` or `"right"`.
    pub side: String,
}

/// An immutable Merkle tree built from a list of leaf byte-strings.
pub struct MerkleTree {
    leaf_hashes: Vec<[u8; 32]>,
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Build a Merkle tree over `leaves`, returning an error if the list is empty.
    pub fn new(leaves: &[Vec<u8>]) -> Result<Self, &'static str> {
        if leaves.is_empty() {
            return Err("MerkleTree requires at least one leaf");
        }
        let leaf_hashes: Vec<[u8; 32]> = leaves.iter().map(|x| hash_leaf(x)).collect();
        let levels = build_levels(&leaf_hashes);
        Ok(Self {
            leaf_hashes,
            levels,
        })
    }

    /// Return the Merkle root hash.
    pub fn root(&self) -> [u8; 32] {
        self.levels
            .last()
            .and_then(|top| top.first())
            .copied()
            .expect("a non-empty tree always has a root")
    }

    /// Return the number of leaves committed by the tree.
    pub fn leaf_count(&self) -> usize {
        self.leaf_hashes.len()
    }

    /// Return the (`0x00`-prefixed) hash of the leaf at `index`.
    pub fn leaf_hash(&self, index: usize) -> [u8; 32] {
        self.leaf_hashes[index]
    }

    /// Return the Merkle path proving the leaf at `index` is under [`root`](Self::root).
    pub fn inclusion_proof(&self, index: usize) -> Result<Vec<ProofStep>, &'static str> {
        if index >= self.leaf_count() {
            return Err("leaf index out of range");
        }
        let mut proof = Vec::new();
        let mut idx = index;
        let last = self.levels.len() - 1;
        for level in &self.levels[..last] {
            let (sibling_idx, side) = if idx % 2 == 1 {
                (idx - 1, "left")
            } else if idx + 1 < level.len() {
                (idx + 1, "right")
            } else {
                (idx, "right")
            };
            proof.push(ProofStep {
                sibling: level[sibling_idx].to_vec(),
                side: side.to_string(),
            });
            idx /= 2;
        }
        Ok(proof)
    }
}

/// Fold the leaf hashes up to the root, promoting the last node on odd levels.
fn build_levels(leaf_hashes: &[[u8; 32]]) -> Vec<Vec<[u8; 32]>> {
    let mut levels = vec![leaf_hashes.to_vec()];
    let mut current = leaf_hashes.to_vec();
    while current.len() > 1 {
        let mut next = Vec::with_capacity(current.len().div_ceil(2));
        let mut i = 0;
        while i < current.len() {
            let left = current[i];
            let right = if i + 1 < current.len() {
                current[i + 1]
            } else {
                current[i]
            };
            next.push(hash_nodes(&left, &right));
            i += 2;
        }
        current = next.clone();
        levels.push(next);
    }
    levels
}

/// Independently confirm `leaf_data` is committed under `root`, given only the
/// leaf bytes, the proof, and a (trusted) root.
pub fn verify_inclusion(leaf_data: &[u8], proof: &[ProofStep], root: &[u8]) -> bool {
    let mut computed = hash_leaf(leaf_data).to_vec();
    for step in proof {
        computed = if step.side == "left" {
            hash_nodes(&step.sibling, &computed).to_vec()
        } else {
            hash_nodes(&computed, &step.sibling).to_vec()
        };
    }
    computed.as_slice() == root
}
