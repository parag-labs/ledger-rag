import { describe, expect, it } from "vitest";

import { hashLeaf, hashNodes, MerkleTree, verifyInclusion, type ProofStep } from "./merkle.ts";

function leaves(items: string[]): Buffer[] {
  return items.map((s) => Buffer.from(s, "utf8"));
}

describe("merkle", () => {
  it("root of a single leaf equals its leaf hash", () => {
    const tree = new MerkleTree(leaves(["only"]));
    expect(tree.root().equals(hashLeaf(Buffer.from("only")))).toBe(true);
  });

  it("hashNodes is order sensitive", () => {
    const a = hashLeaf(Buffer.from("a"));
    const b = hashLeaf(Buffer.from("b"));
    expect(hashNodes(a, b).equals(hashNodes(b, a))).toBe(false);
  });

  it("leaf and node hashes are domain separated", () => {
    expect(hashLeaf(Buffer.from("x")).equals(hashNodes(Buffer.from("x"), Buffer.alloc(0)))).toBe(
      false,
    );
  });

  it("valid inclusion proofs verify for every index (odd leaf count)", () => {
    const items = leaves(["a", "b", "c", "d", "e", "f", "g"]);
    const tree = new MerkleTree(items);
    items.forEach((leaf, i) => {
      expect(verifyInclusion(leaf, tree.inclusionProof(i), tree.root())).toBe(true);
    });
  });

  it("a tampered leaf is rejected", () => {
    const tree = new MerkleTree(leaves(["chunk-0", "chunk-1", "chunk-2", "chunk-3", "chunk-4"]));
    const proof = tree.inclusionProof(2);
    expect(verifyInclusion(Buffer.from("chunk-2-TAMPERED"), proof, tree.root())).toBe(false);
  });

  it("a proof does not verify against a different root", () => {
    const tree = new MerkleTree(leaves(["a", "b", "c", "d"]));
    const other = new MerkleTree(leaves(["a", "b", "c", "e"]));
    const proof = tree.inclusionProof(3);
    expect(verifyInclusion(Buffer.from("d"), proof, other.root())).toBe(false);
  });

  it("proof length is logarithmic in the leaf count", () => {
    const tree = new MerkleTree(leaves(["0", "1", "2", "3", "4", "5", "6", "7"]));
    expect(tree.inclusionProof(0).length).toBe(3);
  });

  it("an empty tree throws", () => {
    expect(() => new MerkleTree([])).toThrow();
  });

  it("an out-of-range inclusion proof throws", () => {
    const tree = new MerkleTree(leaves(["a", "b"]));
    expect(() => tree.inclusionProof(2)).toThrow();
  });

  it("the promoted last leaf of an odd level still verifies", () => {
    const tree = new MerkleTree(leaves(["a", "b", "c"]));
    expect(verifyInclusion(Buffer.from("c"), tree.inclusionProof(2), tree.root())).toBe(true);
  });

  it("corrupting a proof sibling is rejected", () => {
    const tree = new MerkleTree(leaves(["a", "b", "c", "d"]));
    const proof = tree.inclusionProof(1);
    proof[0].sibling[0] ^= 0x01;
    expect(verifyInclusion(Buffer.from("b"), proof, tree.root())).toBe(false);
  });

  it("verifies against a hand-built two-leaf root", () => {
    const root = hashNodes(hashLeaf(Buffer.from("a")), hashLeaf(Buffer.from("b")));
    const proof: ProofStep[] = [{ sibling: hashLeaf(Buffer.from("b")), side: "right" }];
    expect(verifyInclusion(Buffer.from("a"), proof, root)).toBe(true);
    expect(verifyInclusion(Buffer.from("TAMPERED"), proof, root)).toBe(false);
  });
});
