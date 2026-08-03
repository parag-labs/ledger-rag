package com.ledgerrag.verifier;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonProperty;

/** DTOs mirroring the Python QueryResponse JSON schema (snake_case on the wire). */
public final class Models {

    public record QueryResponse(
            String answer,
            List<Citation> citations,
            List<Proof> proofs,
            @JsonProperty("signed_root") SignedRoot signedRoot) {
    }

    public record Citation(
            @JsonProperty("chunk_id") String chunkId,
            @JsonProperty("doc_id") String docId,
            int seq,
            String text) {
    }

    public record Proof(
            @JsonProperty("chunk_id") String chunkId,
            @JsonProperty("leaf_index") int leafIndex,
            String sha256,
            @JsonProperty("merkle_path") List<ProofStep> merklePath) {
    }

    public record ProofStep(String sibling, String side) {
    }

    public record SignedRoot(
            String root,
            @JsonProperty("prev_root") String prevRoot,
            @JsonProperty("leaf_count") long leafCount,
            String signature,
            @JsonProperty("public_key") String publicKey) {
    }

    public record ChunkResult(String chunkId, boolean hashOk, boolean inclusionOk) {
    }

    public record VerificationResult(boolean verified, boolean signatureOk, List<ChunkResult> chunks) {
    }

    private Models() {
    }
}
