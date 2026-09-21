//! Cross-language port of LedgerRAG's cryptographic core.
//!
//! LedgerRAG commits document chunks into a SHA-256 Merkle tree, signs each root
//! with Ed25519, and ships an inclusion proof with every answer. This crate
//! reproduces the exact hashing and signing rules of the Python reference so a
//! proof produced in Python (or C#/Java) re-verifies here:
//!
//! - leaf hash = `SHA-256(0x00 || utf8(text))`
//! - node hash = `SHA-256(0x01 || left || right)`
//! - root msg  = `root || prev_root(optional) || leaf_count` (8 bytes, big-endian)
//! - signature = Ed25519 over the root message, verified with the raw public key

pub mod merkle;
pub mod models;
pub mod signing;
pub mod verification;

pub use merkle::{hash_leaf, hash_nodes, verify_inclusion, MerkleTree, ProofStep};
pub use models::{
    ChunkResult, Citation, Proof, ProofStepModel, QueryResponse, SignedRoot, VerificationResult,
};
pub use signing::{generate_keypair, root_message, sign_root, verify_root};
pub use verification::verify_response;
