<h1 align="center">LedgerRAG</h1>
<p align="center"><b>Verifiable RAG you can prove.</b><br/>
Retrieval-augmented generation where every answer ships with a cryptographic proof linking it to signed, tamper-evident sources.</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/C%23-.NET%2010-512BD4?logo=csharp&logoColor=white" />
  <img src="https://img.shields.io/badge/Java-21-ED8B00?logo=openjdk&logoColor=white" />
  <img src="https://img.shields.io/badge/FastAPI-009688?logo=fastapi&logoColor=white" />
  <img src="https://img.shields.io/badge/crypto-Ed25519%20%2B%20SHA--256%20Merkle-orange" />
  <img src="https://img.shields.io/badge/tests-11%20passing-brightgreen" />
  <img src="https://img.shields.io/badge/license-MIT-green" />
</p>

---

## Why this exists

Standard RAG gives you **citations you have to trust**. LedgerRAG gives you **citations you can verify** - and detects source tampering automatically.

Enterprises in regulated domains (finance, healthcare, legal, government) can't adopt RAG at scale because they can't prove:

- **Provenance** - which exact source produced this answer?
- **Integrity** - has that source been altered since it was indexed?
- **Non-repudiation** - can a third party verify the answer *without trusting the server*?

LedgerRAG solves all three by committing every ingested chunk into an append-only **Merkle-tree ledger** and returning a **Merkle inclusion proof + Ed25519 signature** with every answer.

## How it works

```
INGEST:  document → chunk → SHA-256 hash → append to Merkle ledger → embed → sign root
QUERY:   question → retrieve chunks → LLM answer → attach inclusion proofs + signed root
VERIFY:  independent CLI recomputes the Merkle path and checks the signature -
         proving the answer is grounded in untampered sources, without trusting the server
```

If a source is tampered with after indexing, its chunk hash no longer verifies against the signed root - LedgerRAG detects the drift and refuses to serve altered content.

## Quickstart (<5 min)

```bash
# Backend
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install -r backend/requirements.txt
uvicorn app.main:app --reload --app-dir backend        # http://localhost:8000/docs

# Ingest a doc, ask a question, verify the proof
curl -F "file=@docs/sample.txt" http://localhost:8000/ingest
curl -X POST http://localhost:8000/query -H "Content-Type: application/json" \
     -d '{"question": "What is the refund policy?"}'

# Independent verification (trusts only the public key, not the server)
python -m app.cli.verify response.json
```

Or run everything with Docker:

```bash
docker compose up
```

## Architecture

```
backend/app/
  api/     FastAPI routes: /ingest, /query, /verify, /ledger
  core/    config, models, embeddings + LLM clients
  ledger/  Merkle tree, Ed25519 signing, append-only store   ← crypto core
  rag/     chunker, vector store, retriever, answer synthesis
frontend/  React proof-panel UI (verified ✅ / tampered ❌)
```

## Cross-language verification (polyglot proof)

LedgerRAG's promise - *verify an answer without trusting the server* - is proven by **three independent verifiers in three languages**, each re-verifying the exact same Python-produced proof:

| Verifier | Stack | Location |
|----------|-------|----------|
| Python | `cryptography` | `backend/app/cli/verify.py` |
| **C#** | .NET 10 + BouncyCastle | [`verifier-csharp/`](./verifier-csharp) |
| **Java** | JDK 21 + BouncyCastle | [`verifier-java/`](./verifier-java) |

```bash
# All three agree on the same proof produced by the Python server:
python -m app.cli.verify ../sample-response.json          # ✅ VERIFIED
dotnet run -c Release -- ../sample-response.json           # ✅ VERIFIED (C#)
java -jar target/ledgerrag-verifier-0.1.0.jar ../sample-response.json  # ✅ VERIFIED (Java)
```

Three languages, three crypto stacks, one proof - that's what makes the verifiability **standards-based, not a trick**. Tamper with any cited source and all three reject it.

## Feature checklist

- [x] Merkle-tree ledger with inclusion proofs
- [x] Ed25519-signed, append-only, chained roots
- [ ] RAG pipeline with citations
- [ ] Proofs attached to every answer
- [ ] Independent verifier CLI
- [ ] Live tamper-detection demo
- [ ] React proof-panel UI

## Tech stack

Python · FastAPI · `cryptography` (Ed25519 + SHA-256 Merkle) · pgvector / Chroma · OpenAI (with local fallback) · React + Vite · Docker · GitHub Actions

## Design notes and numbers

- **[DESIGN.md](DESIGN.md)** - the threat model (tamper-*evident*, not tamper-proof against
  the key holder), why domain-separated SHA-256 and chained ed25519 roots, and the
  non-goals. Includes [threat-model](docs/diagrams/threat-model.png) and
  [query-sequence](docs/diagrams/verifiable-query-sequence.png) diagrams.
- **[BENCHMARKS.md](BENCHMARKS.md)** - proof size is O(log n) (a million-entry ledger
  yields a 640-byte, 20-hash proof) and verification throughput, with graphs.
  Reproduce with `python bench/benchmark.py`.
- **Tamper fuzz** (`backend/tests/test_tamper_fuzz.py`) - thousands of randomized
  bit-flips against leaves, proofs, roots, and signatures; every corruption is caught.

## Roadmap

Part of [parag-labs](https://github.com/parag-labs) - small, focused tools for building AI systems you can trust.

## License

MIT
