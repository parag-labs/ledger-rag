package com.ledgerrag.verifier;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.List;

import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.crypto.signers.Ed25519Signer;

import com.ledgerrag.verifier.Models.ChunkResult;
import com.ledgerrag.verifier.Models.Proof;
import com.ledgerrag.verifier.Models.ProofStep;
import com.ledgerrag.verifier.Models.QueryResponse;
import com.ledgerrag.verifier.Models.SignedRoot;
import com.ledgerrag.verifier.Models.VerificationResult;

/**
 * Independent, cross-language verifier for LedgerRAG answers.
 *
 * <p>Reproduces exactly the Python server's hashing/signing rules so a proof
 * generated in Python can be re-verified in Java -- proving the verifiability is
 * standards-based, not language-specific:
 * <ul>
 *   <li>leaf hash = SHA-256(0x00 || utf8(text))</li>
 *   <li>node hash = SHA-256(0x01 || left || right)</li>
 *   <li>root msg  = root || prev_root(optional) || leaf_count (8 bytes, big-endian)</li>
 *   <li>signature = Ed25519 over root msg, verified with the raw public key</li>
 * </ul>
 */
public final class LedgerRagVerifier {

    private LedgerRagVerifier() {
    }

    public static VerificationResult verify(QueryResponse resp) {
        SignedRoot sr = resp.signedRoot();
        byte[] root = hexDecode(sr.root());
        byte[] prev = (sr.prevRoot() == null || sr.prevRoot().isEmpty())
                ? new byte[0] : hexDecode(sr.prevRoot());

        byte[] msg = concat(root, prev, toBigEndian8(sr.leafCount()));
        boolean sigOk = verifyEd25519(hexDecode(sr.publicKey()), msg, hexDecode(sr.signature()));

        boolean allOk = sigOk;
        var chunkResults = new java.util.ArrayList<ChunkResult>();
        for (Proof proof : resp.proofs()) {
            String text = resp.citations().stream()
                    .filter(c -> c.chunkId().equals(proof.chunkId()))
                    .findFirst().orElseThrow().text();
            byte[] leafBytes = text.getBytes(StandardCharsets.UTF_8);

            String recomputed = toHex(sha256(leafBytes));
            boolean hashOk = recomputed.equals(proof.sha256());
            boolean inclusionOk = verifyInclusion(leafBytes, proof.merklePath(), root);
            boolean ok = hashOk && inclusionOk;
            allOk = allOk && ok;
            chunkResults.add(new ChunkResult(proof.chunkId(), hashOk, inclusionOk));
        }
        return new VerificationResult(allOk, sigOk, chunkResults);
    }

    static boolean verifyInclusion(byte[] leafData, List<ProofStep> path, byte[] root) {
        byte[] computed = hashLeaf(leafData);
        for (ProofStep step : path) {
            byte[] sibling = hexDecode(step.sibling());
            computed = "left".equals(step.side())
                    ? hashNodes(sibling, computed)
                    : hashNodes(computed, sibling);
        }
        return java.util.Arrays.equals(computed, root);
    }

    static byte[] hashLeaf(byte[] data) {
        return sha256(concat(new byte[] {0x00}, data));
    }

    static byte[] hashNodes(byte[] left, byte[] right) {
        return sha256(concat(new byte[] {0x01}, left, right));
    }

    private static boolean verifyEd25519(byte[] publicKey, byte[] message, byte[] signature) {
        Ed25519Signer verifier = new Ed25519Signer();
        verifier.init(false, new Ed25519PublicKeyParameters(publicKey, 0));
        verifier.update(message, 0, message.length);
        return verifier.verifySignature(signature);
    }

    private static byte[] sha256(byte[] data) {
        try {
            return MessageDigest.getInstance("SHA-256").digest(data);
        } catch (Exception e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static byte[] toBigEndian8(long value) {
        byte[] b = new byte[8];
        for (int i = 7; i >= 0; i--) {
            b[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        return b;
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }

    private static byte[] hexDecode(String hex) {
        int len = hex.length();
        byte[] out = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(hex.substring(i, i + 2), 16);
        }
        return out;
    }

    private static String toHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
