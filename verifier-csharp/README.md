# LedgerRAG Verifier - C# (.NET 10)

An **independent, cross-language verifier** for LedgerRAG answers.

## Why this exists

LedgerRAG's core promise is: *verify an answer without trusting the server.* This C# verifier proves that promise is **real and standards-based** - it re-verifies the exact same Merkle proof + Ed25519 signature produced by the Python server, using a completely different language and crypto stack (.NET + BouncyCastle).

If Python produces a proof and **C# independently confirms it**, the verifiability isn't a Python-specific trick - it's genuine cryptographic interoperability.

## What it checks

For a `response.json` produced by the Python server:
1. **Signature** - Ed25519 over `root || prev_root || leaf_count(8B big-endian)`, using the embedded raw public key.
2. **Integrity** - recompute each cited chunk's SHA-256; must match the recorded hash.
3. **Inclusion** - walk the Merkle path (`leaf = SHA256(0x00‖text)`, `node = SHA256(0x01‖L‖R)`) and confirm it derives the signed root.

## Run

```bash
dotnet run -c Release -- ../sample-response.json
```

**Valid proof:**
```
✅ VERIFIED (C#)
  signature_ok = True
  chunk 146b468c: hash_ok=True inclusion_ok=True
  ...
# exit code 0
```

**Tampered proof** (a citation's text was altered after signing):
```
❌ TAMPERED / INVALID (C#)
  chunk 146b468c: hash_ok=False inclusion_ok=False
# exit code 1
```

## Stack

.NET 10 · `System.Security.Cryptography` (SHA-256) · BouncyCastle (Ed25519) · `System.Text.Json`

## Note

Ed25519 is not built into `System.Security.Cryptography`, so this uses BouncyCastle - the standard .NET choice for EdDSA.
