// Ed25519 signing for ledger roots, using Node's built-in crypto.

import { createPublicKey, generateKeyPairSync, sign, verify, type KeyObject } from "node:crypto";

/** A generated Ed25519 keypair: a private key object plus the raw 32-byte public key. */
export interface Keypair {
  privateKey: KeyObject;
  publicKey: Buffer;
}

// DER prefix for an Ed25519 SubjectPublicKeyInfo wrapping a raw 32-byte key.
const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

/** Generate a fresh Ed25519 keypair, returning the public key as raw bytes. */
export function generateKeypair(): Keypair {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const spki = publicKey.export({ format: "der", type: "spki" });
  const raw = spki.subarray(spki.length - 32);
  return { privateKey, publicKey: Buffer.from(raw) };
}

/** Rebuild a public-key object from a raw 32-byte Ed25519 key. */
function publicKeyFromRaw(raw: Buffer): KeyObject {
  const der = Buffer.concat([SPKI_ED25519_PREFIX, raw]);
  return createPublicKey({ key: der, format: "der", type: "spki" });
}

/**
 * Build the signed message: root, then the optional previous root, then the
 * leaf count as 8 big-endian bytes. An empty/absent previous root is skipped.
 */
export function rootMessage(root: Buffer, prevRoot: Buffer | null, leafCount: number | bigint): Buffer {
  const countBuf = Buffer.alloc(8);
  countBuf.writeBigUInt64BE(BigInt(leafCount));
  const parts: Buffer[] = [root];
  if (prevRoot && prevRoot.length > 0) {
    parts.push(prevRoot);
  }
  parts.push(countBuf);
  return Buffer.concat(parts);
}

/** Sign `(root || prev_root || leaf_count)` with an Ed25519 private key. */
export function signRoot(
  privateKey: KeyObject,
  root: Buffer,
  prevRoot: Buffer | null,
  leafCount: number | bigint,
): Buffer {
  return sign(null, rootMessage(root, prevRoot, leafCount), privateKey);
}

/**
 * Verify an Ed25519 signature over `(root || prev_root || leaf_count)` using a
 * raw 32-byte public key. Returns false for malformed keys or signatures.
 */
export function verifyRoot(
  publicKey: Buffer,
  signature: Buffer,
  root: Buffer,
  prevRoot: Buffer | null,
  leafCount: number | bigint,
): boolean {
  if (publicKey.length !== 32 || signature.length !== 64) {
    return false;
  }
  let keyObj: KeyObject;
  try {
    keyObj = publicKeyFromRaw(publicKey);
  } catch {
    return false;
  }
  return verify(null, rootMessage(root, prevRoot, leafCount), keyObj, signature);
}
