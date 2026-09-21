import { describe, expect, it } from "vitest";

import { generateKeypair, signRoot, verifyRoot } from "./signing.ts";

const ROOT = Buffer.from("root-bytes-that-are-32-long-abcd");

describe("signing", () => {
  it("a freshly signed root verifies", () => {
    const { privateKey, publicKey } = generateKeypair();
    const sig = signRoot(privateKey, ROOT, null, 2);
    expect(verifyRoot(publicKey, sig, ROOT, null, 2)).toBe(true);
  });

  it("an altered leaf count fails verification", () => {
    const { privateKey, publicKey } = generateKeypair();
    const sig = signRoot(privateKey, ROOT, null, 2);
    expect(verifyRoot(publicKey, sig, ROOT, null, 3)).toBe(false);
  });

  it("a signature does not verify under a different key", () => {
    const real = generateKeypair();
    const attacker = generateKeypair();
    const sig = signRoot(real.privateKey, ROOT, null, 10);
    expect(verifyRoot(attacker.publicKey, sig, ROOT, null, 10)).toBe(false);
  });

  it("prev_root is part of the signed message", () => {
    const { privateKey, publicKey } = generateKeypair();
    const prev = Buffer.from("prev-bytes-that-are-32-long-abcd");
    const sig = signRoot(privateKey, ROOT, prev, 5);
    expect(verifyRoot(publicKey, sig, ROOT, prev, 5)).toBe(true);
    // Dropping prev_root changes the message and must fail.
    expect(verifyRoot(publicKey, sig, ROOT, null, 5)).toBe(false);
  });

  it("malformed key or signature sizes are rejected, not thrown", () => {
    const { privateKey, publicKey } = generateKeypair();
    const sig = signRoot(privateKey, ROOT, null, 1);
    expect(verifyRoot(Buffer.alloc(4), sig, ROOT, null, 1)).toBe(false);
    expect(verifyRoot(publicKey, Buffer.alloc(2), ROOT, null, 1)).toBe(false);
  });
});
