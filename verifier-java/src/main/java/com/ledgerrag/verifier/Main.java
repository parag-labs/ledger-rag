package com.ledgerrag.verifier;

import java.io.File;

import com.fasterxml.jackson.databind.ObjectMapper;

import com.ledgerrag.verifier.Models.ChunkResult;
import com.ledgerrag.verifier.Models.QueryResponse;
import com.ledgerrag.verifier.Models.VerificationResult;

/** CLI entrypoint: {@code java -jar ledgerrag-verifier.jar response.json}. */
public final class Main {

    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            System.out.println("usage: java -jar ledgerrag-verifier.jar <response.json>");
            System.exit(2);
        }

        ObjectMapper mapper = new ObjectMapper();
        QueryResponse resp = mapper.readValue(new File(args[0]), QueryResponse.class);

        VerificationResult result = LedgerRagVerifier.verify(resp);
        System.out.println(result.verified() ? "\u2705 VERIFIED (Java)" : "\u274c TAMPERED / INVALID (Java)");
        System.out.println("  signature_ok = " + result.signatureOk());
        for (ChunkResult c : result.chunks()) {
            System.out.printf("  chunk %s: hash_ok=%s inclusion_ok=%s%n",
                    c.chunkId(), c.hashOk(), c.inclusionOk());
        }
        System.exit(result.verified() ? 0 : 1);
    }

    private Main() {
    }
}
