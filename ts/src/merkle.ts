// SHA-256 Merkle tree with domain-separated leaves and inclusion proofs.

import { createHash } from "node:crypto";

const LEAF_PREFIX = 0x00;
const NODE_PREFIX = 0x01;

/** Hash a leaf value (a chunk's normalized bytes) with the 0x00 prefix. */
export function hashLeaf(data: Buffer): Buffer {
  return createHash("sha256").update(Buffer.from([LEAF_PREFIX])).update(data).digest();
}

/** Hash two child nodes into their parent with the 0x01 prefix. */
export function hashNodes(left: Buffer, right: Buffer): Buffer {
  return createHash("sha256")
    .update(Buffer.from([NODE_PREFIX]))
    .update(left)
    .update(right)
    .digest();
}

/** One step in a Merkle inclusion proof: a sibling hash and the side it sits on. */
export interface ProofStep {
  sibling: Buffer;
  side: "left" | "right";
}

/** An immutable Merkle tree built from a list of leaf byte-strings. */
export class MerkleTree {
  private readonly leafHashes: Buffer[];
  private readonly levels: Buffer[][];

  constructor(leaves: Buffer[]) {
    if (leaves.length === 0) {
      throw new Error("MerkleTree requires at least one leaf");
    }
    this.leafHashes = leaves.map((leaf) => hashLeaf(leaf));
    this.levels = buildLevels(this.leafHashes);
  }

  /** Return the Merkle root hash. */
  root(): Buffer {
    const top = this.levels[this.levels.length - 1];
    return top[0];
  }

  /** Return the number of leaves committed by the tree. */
  leafCount(): number {
    return this.leafHashes.length;
  }

  /** Return the (0x00-prefixed) hash of the leaf at `index`. */
  leafHash(index: number): Buffer {
    return this.leafHashes[index];
  }

  /** Return the Merkle path proving the leaf at `index` is under the root. */
  inclusionProof(index: number): ProofStep[] {
    if (index < 0 || index >= this.leafCount()) {
      throw new Error("leaf index out of range");
    }
    const proof: ProofStep[] = [];
    let idx = index;
    for (let level = 0; level < this.levels.length - 1; level++) {
      const nodes = this.levels[level];
      let siblingIdx: number;
      let side: "left" | "right";
      if (idx % 2 === 1) {
        siblingIdx = idx - 1;
        side = "left";
      } else if (idx + 1 < nodes.length) {
        siblingIdx = idx + 1;
        side = "right";
      } else {
        siblingIdx = idx;
        side = "right";
      }
      proof.push({ sibling: nodes[siblingIdx], side });
      idx = Math.floor(idx / 2);
    }
    return proof;
  }
}

/** Fold the leaf hashes up to the root, promoting the last node on odd levels. */
function buildLevels(leafHashes: Buffer[]): Buffer[][] {
  const levels: Buffer[][] = [leafHashes];
  let current = leafHashes;
  while (current.length > 1) {
    const next: Buffer[] = [];
    for (let i = 0; i < current.length; i += 2) {
      const left = current[i];
      const right = i + 1 < current.length ? current[i + 1] : current[i];
      next.push(hashNodes(left, right));
    }
    levels.push(next);
    current = next;
  }
  return levels;
}

/**
 * Independently confirm `leafData` is committed under `root`, given only the
 * leaf bytes, the proof, and a (trusted) root.
 */
export function verifyInclusion(leafData: Buffer, proof: ProofStep[], root: Buffer): boolean {
  let computed = hashLeaf(leafData);
  for (const step of proof) {
    computed =
      step.side === "left" ? hashNodes(step.sibling, computed) : hashNodes(computed, step.sibling);
  }
  return computed.equals(root);
}
