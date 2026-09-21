import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import { describe, expect, it } from "vitest";

import { MerkleTree } from "./merkle.ts";
import type { Citation, Proof, QueryResponse } from "./models.ts";
import { generateKeypair, signRoot } from "./signing.ts";
import { verifyResponse } from "./verification.ts";

const SAMPLE_PATH = fileURLToPath(new URL("../../sample-response.json", import.meta.url));

function loadSample(): QueryResponse {
  return JSON.parse(readFileSync(SAMPLE_PATH, "utf8")) as QueryResponse;
}

/** Build a fully-signed, self-consistent response over `texts`. */
function buildSignedResponse(texts: string[], prev: Buffer | null): QueryResponse {
  const leaves = texts.map((t) => Buffer.from(t, "utf8"));
  const tree = new MerkleTree(leaves);
  const { privateKey, publicKey } = generateKeypair();
  const root = tree.root();
  const leafCount = tree.leafCount();
  const signature = signRoot(privateKey, root, prev, leafCount);

  const citations: Citation[] = texts.map((t, i) => ({
    chunk_id: `c${i}`,
    doc_id: "doc",
    seq: i,
    text: t,
  }));
  const proofs: Proof[] = texts.map((t, i) => ({
    chunk_id: `c${i}`,
    leaf_index: i,
    sha256: createHash("sha256").update(Buffer.from(t, "utf8")).digest("hex"),
    merkle_path: tree.inclusionProof(i).map((s) => ({
      sibling: s.sibling.toString("hex"),
      side: s.side,
    })),
  }));

  return {
    answer: "answer",
    citations,
    proofs,
    signed_root: {
      root: root.toString("hex"),
      prev_root: prev ? prev.toString("hex") : null,
      leaf_count: leafCount,
      signature: signature.toString("hex"),
      public_key: publicKey.toString("hex"),
    },
  };
}

describe("verification", () => {
  it("verifies the Python-produced golden sample", () => {
    const result = verifyResponse(loadSample());
    expect(result.verified).toBe(true);
    expect(result.signature_ok).toBe(true);
    expect(result.chunks).toHaveLength(4);
    for (const chunk of result.chunks) {
      expect(chunk.hash_ok).toBe(true);
      expect(chunk.inclusion_ok).toBe(true);
    }
  });

  it("verifies a self-produced response", () => {
    const resp = buildSignedResponse(["alpha", "beta", "gamma", "delta", "epsilon"], null);
    const result = verifyResponse(resp);
    expect(result.verified).toBe(true);
    expect(result.signature_ok).toBe(true);
    expect(result.chunks).toHaveLength(5);
  });

  it("verifies a self-produced response carrying a prev_root", () => {
    const resp = buildSignedResponse(["one", "two", "three"], Buffer.alloc(32, 7));
    const result = verifyResponse(resp);
    expect(result.verified).toBe(true);
    expect(result.signature_ok).toBe(true);
  });

  it("fails when a citation's text is tampered", () => {
    const resp = buildSignedResponse(["alpha", "beta", "gamma"], null);
    resp.citations[1].text = "beta-TAMPERED";
    const result = verifyResponse(resp);
    expect(result.verified).toBe(false);
    expect(result.signature_ok).toBe(true);
    const beta = result.chunks.find((c) => c.chunk_id === "c1");
    expect(beta?.hash_ok).toBe(false);
    expect(beta?.inclusion_ok).toBe(false);
  });

  it("fails when the leaf count is forged", () => {
    const resp = buildSignedResponse(["a", "b"], null);
    resp.signed_root.leaf_count += 1;
    const result = verifyResponse(resp);
    expect(result.verified).toBe(false);
    expect(result.signature_ok).toBe(false);
  });

  it("hash_ok uses the plain SHA-256 of the text, not the leaf hash", () => {
    const resp = buildSignedResponse(["alpha"], null);
    const prefixed = createHash("sha256")
      .update(Buffer.from([0x00]))
      .update(Buffer.from("alpha", "utf8"))
      .digest("hex");
    resp.proofs[0].sha256 = prefixed;
    const result = verifyResponse(resp);
    expect(result.chunks[0].hash_ok).toBe(false);
    expect(result.chunks[0].inclusion_ok).toBe(true);
  });

  it("throws when a proof references a missing citation", () => {
    const resp = buildSignedResponse(["alpha", "beta"], null);
    resp.citations.shift();
    expect(() => verifyResponse(resp)).toThrow();
  });
});
