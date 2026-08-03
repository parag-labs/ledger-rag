# LedgerRAG Verifier - Java (Maven)

An **independent, cross-language verifier** for LedgerRAG answers - the enterprise/JVM counterpart to the Python and C# verifiers.

## Why this exists

LedgerRAG's promise is *verify without trusting the server*. This Java verifier re-verifies the exact Merkle proof + Ed25519 signature produced by the Python server, using a third, independent stack (JVM + Jackson + BouncyCastle). Three languages agreeing on the same proof = the verifiability is genuinely standards-based.

Enterprise/regulated shops (LedgerRAG's target market) run on the JVM - this SDK lets them verify answers natively.

## What it checks

Same rules as the Python and C# verifiers:
- `leaf = SHA-256(0x00 ‖ utf8(text))`
- `node = SHA-256(0x01 ‖ left ‖ right)`
- `root msg = root ‖ prev_root(optional) ‖ leaf_count (8 bytes, big-endian)`
- `signature = Ed25519(root msg)` verified with the raw public key

## Build & run

```bash
mvn -q package
java -jar target/ledgerrag-verifier-0.1.0.jar ../sample-response.json
```

**Valid:** `✅ VERIFIED (Java)` (exit 0) · **Tampered:** `❌ TAMPERED / INVALID (Java)` (exit 1)

```bash
mvn test        # JUnit 5 unit tests
```

## Stack

Java 17 · Jackson (JSON) · BouncyCastle (Ed25519) · JUnit 5 · Maven

> Note: this module requires a JDK + Maven to build. The Python and C# verifiers in sibling folders are pre-verified; this shares their exact byte-level rules.
