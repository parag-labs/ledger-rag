// The independent verifier: re-checks a proof-carrying answer using only the
// embedded public key and proofs.

import { createHash } from "node:crypto";

import { verifyInclusion, type ProofStep } from "./merkle.ts";
import type {
  ChunkResult,
  ProofStepModel,
  QueryResponse,
  VerificationResult,
} from "./models.ts";
import { verifyRoot } from "./signing.ts";

/**
 * Verify a QueryResponse, proving each cited chunk is committed under the
 * signed root without trusting the server that produced the answer. Throws if a
 * proof references a chunk id with no matching citation.
 */
export function verifyResponse(resp: QueryResponse): VerificationResult {
  const sr = resp.signed_root;
  const publicKey = Buffer.from(sr.public_key, "hex");
  const root = Buffer.from(sr.root, "hex");
  const prev = sr.prev_root ? Buffer.from(sr.prev_root, "hex") : null;
  const signature = Buffer.from(sr.signature, "hex");

  const signatureOk = verifyRoot(publicKey, signature, root, prev, sr.leaf_count);
  let allOk = signatureOk;

  const chunks: ChunkResult[] = [];
  for (const proof of resp.proofs) {
    const leafBytes = leafFor(resp, proof.chunk_id);
    // Integrity: the recorded hash is the PLAIN SHA-256 of the chunk text, not
    // the 0x00-prefixed leaf hash used inside the Merkle tree.
    const recomputed = createHash("sha256").update(leafBytes).digest("hex");
    const hashOk = recomputed === proof.sha256;
    const path = decodePath(proof.merkle_path);
    const inclusionOk = verifyInclusion(leafBytes, path, root);
    allOk = allOk && hashOk && inclusionOk;
    chunks.push({ chunk_id: proof.chunk_id, hash_ok: hashOk, inclusion_ok: inclusionOk });
  }
  return { verified: allOk, signature_ok: signatureOk, chunks };
}

/** Convert wire proof steps (hex siblings) into raw-byte proof steps. */
function decodePath(steps: ProofStepModel[]): ProofStep[] {
  return steps.map((step) => ({
    sibling: Buffer.from(step.sibling, "hex"),
    side: step.side === "left" ? "left" : "right",
  }));
}

/** Return the UTF-8 bytes of the citation text for a chunk id. */
function leafFor(resp: QueryResponse, chunkId: string): Buffer {
  const citation = resp.citations.find((c) => c.chunk_id === chunkId);
  if (!citation) {
    throw new Error(`no citation text for chunk ${chunkId}`);
  }
  return Buffer.from(citation.text, "utf8");
}
