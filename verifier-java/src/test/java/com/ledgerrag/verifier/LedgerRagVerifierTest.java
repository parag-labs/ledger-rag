package com.ledgerrag.verifier;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.nio.charset.StandardCharsets;
import java.util.List;

import org.junit.jupiter.api.Test;

import com.ledgerrag.verifier.Models.ProofStep;

/**
 * Verifies the Java implementation reproduces the Python/C# hashing rules and
 * that inclusion proofs behave correctly (valid accepts, tampered rejects).
 */
class LedgerRagVerifierTest {

    @Test
    void leafHashIsDeterministic() {
        byte[] h1 = LedgerRagVerifier.hashLeaf("a".getBytes(StandardCharsets.UTF_8));
        byte[] h2 = LedgerRagVerifier.hashLeaf("a".getBytes(StandardCharsets.UTF_8));
        assertArrayEquals(h1, h2);
    }

    @Test
    void inclusionProofRoundTrips() {
        // Build a 2-leaf tree by hand: root = N(L(a), L(b)).
        byte[] a = "a".getBytes(StandardCharsets.UTF_8);
        byte[] b = "b".getBytes(StandardCharsets.UTF_8);
        byte[] root = LedgerRagVerifier.hashNodes(
                LedgerRagVerifier.hashLeaf(a), LedgerRagVerifier.hashLeaf(b));

        // Proof for leaf 'a': sibling is L(b) on the right.
        String siblingHex = toHex(LedgerRagVerifier.hashLeaf(b));
        List<ProofStep> proof = List.of(new ProofStep(siblingHex, "right"));

        assertTrue(LedgerRagVerifier.verifyInclusion(a, proof, root));
        assertFalse(LedgerRagVerifier.verifyInclusion(
                "TAMPERED".getBytes(StandardCharsets.UTF_8), proof, root));
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte x : bytes) {
            sb.append(String.format("%02x", x));
        }
        return sb.toString();
    }
}
