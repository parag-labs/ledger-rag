# LedgerRAG - Detailed Build Plan (`plan.md`)

> **Verifiable RAG you can prove.** A retrieval-augmented generation system where every answer ships with a cryptographic proof linking it to signed, tamper-evident sources.
>
> **Status:** Flagship portfolio project · **Owner:** Parag Sawant · **Est. effort:** 3-4 weekends

---

## 1. Problem & thesis

**Problem.** Enterprises in regulated domains (finance, healthcare, legal, gov) cannot adopt RAG at scale because they cannot *prove*:
1. **Provenance** - which exact source produced this answer?
2. **Integrity** - has that source been altered since it was indexed?
3. **Non-repudiation** - can a third party verify the answer *without trusting the server*?

**Thesis.** By committing every ingested chunk into an append-only **Merkle-tree ledger** and returning a **Merkle inclusion proof + signature** with every answer, we make RAG answers independently verifiable and tamper-evident - turning "the model said so" into "here is cryptographic proof of the source."

**Why it's unique.** Standard RAG returns citations you have to trust. LedgerRAG returns citations you can *verify* - and detects source tampering automatically. This is the Azure Approval Service (zero-trust + signed ledger) reimagined as an open AI product.

---

## 2. Core concepts (crypto primer)

| Concept | Role in LedgerRAG |
|---------|-------------------|
| **SHA-256 hash** | Fingerprint of each chunk's exact bytes. Any change ⇒ different hash. |
| **Merkle tree** | Binary tree of hashes; the single **root** commits to *all* chunks. Cheap to prove one leaf belongs. |
| **Inclusion proof (Merkle path)** | O(log n) sibling hashes proving "chunk X is leaf N under root R." |
| **Ed25519 signature** | Server signs each ledger root, so clients trust roots without trusting queries. |
| **Append-only ledger** | Roots are chained (like a mini-blockchain); history can't be silently rewritten. |

**Tamper detection flow:** re-hash a source doc → recompute its chunk hashes → if any differ from what's in the ledger, the leaf no longer verifies against the signed root ⇒ flag + refuse to serve.

---

## 3. Architecture

```
┌──────────────────────────────────────────────────────────────────────────┐
│                              INGESTION PATH                                │
│                                                                            │
│  Document ─▶ Chunker ─▶ [ for each chunk ]                                 │
│                            ├─ SHA-256 hash ──▶ Merkle Ledger (append leaf) │
│                            └─ Embed ─────────▶ Vector Store (pgvector)     │
│                                                                            │
│  After batch: compute Merkle root ─▶ Ed25519 sign ─▶ append to Ledger chain│
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│                                QUERY PATH                                  │
│                                                                            │
│  Question ─▶ Embed ─▶ Vector search (top-k chunks)                         │
│                          │                                                 │
│                          ├─▶ LLM answer (grounded on chunks)               │
│                          └─▶ For each cited chunk:                         │
│                                 build Merkle inclusion proof               │
│                                                                            │
│  Response = { answer, citations[], proofs[], signed_root }                 │
└──────────────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────────────┐
│                          INDEPENDENT VERIFIER (CLI)                        │
│                                                                            │
│  Given { chunk, proof, signed_root }:                                      │
│    1. verify Ed25519 signature on root  (trust the key, not the server)   │
│    2. recompute leaf hash from chunk bytes                                 │
│    3. walk Merkle path ─▶ derive root ─▶ compare to signed_root            │
│    ✅ match ⇒ answer is provably grounded in untampered source            │
└──────────────────────────────────────────────────────────────────────────┘
```

### Component map
```
backend/
  app/
    api/          FastAPI routes: /ingest, /query, /verify, /ledger
    core/         config, models (pydantic), embeddings + LLM clients
    ledger/       Merkle tree, Ed25519 signing, append-only store
    rag/          chunker, vector store, retriever, answer synthesis
  tests/          unit tests (ledger proofs are the crown-jewel tests)
frontend/         React/Vite "verifiable answer" UI with proof panel
docs/             architecture diagram, demo GIFs
```

---

## 4. Tech decisions (and why)

| Decision | Choice | Rationale |
|----------|--------|-----------|
| Language | **Python 3.11 + FastAPI** | Fast to build, great AI ecosystem, matches JD (Python). |
| Crypto | **`cryptography` lib** (Ed25519, SHA-256) | Battle-tested; no hand-rolled crypto. |
| Merkle tree | **Custom, ~120 LOC** | Small, auditable, and the tests showcase engineering rigor. |
| Vector store | **pgvector** (prod) / **Chroma** (local default) | pgvector satisfies the "relational DB (Postgres)" JD signal; Chroma keeps quickstart zero-config. |
| Embeddings | **OpenAI `text-embedding-3-small`** w/ local fallback (`sentence-transformers`) | Works offline for demos; swappable via config. |
| LLM | **OpenAI** w/ local fallback (Ollama) | Same swappability; no hard vendor lock. |
| Frontend | **React + Vite + Tailwind** | Fast, clean, deployable to Vercel. |
| Packaging | **Docker + docker-compose** | One-command local run; sets up DeployKit later. |
| CI | **GitHub Actions** (lint + test + eval) | Portfolio credibility; hooks into EvalForge later. |

**Guardrails / principles:**
- Never trust the query path - the **verifier must work standalone**.
- Deterministic hashing (normalize chunk bytes: UTF-8, fixed newline, trimmed).
- Keys: dev key in repo is a throwaway; real key via env/secret store.

---

## 5. Data model

```python
# Chunk
{
  "id": "uuid",
  "doc_id": "uuid",
  "seq": 3,                       # position in doc
  "text": "normalized chunk text",
  "sha256": "hex...",             # leaf hash
  "leaf_index": 42,               # position in Merkle tree
  "embedding": [float, ...]       # in vector store
}

# LedgerEntry (append-only chain)
{
  "root": "hex merkle root",
  "prev_root": "hex or null",     # chains history
  "leaf_count": 128,
  "signature": "ed25519 hex",     # sign(root || prev_root || leaf_count)
  "signed_at": "iso8601",
  "pubkey_id": "key fingerprint"
}

# QueryResponse
{
  "answer": "text",
  "citations": [{ "chunk_id", "doc_id", "seq", "text" }],
  "proofs": [{ "chunk_id", "leaf_index", "sha256", "merkle_path": [...] }],
  "signed_root": { ...LedgerEntry }
}
```

---

## 6. API surface

| Method | Route | Purpose |
|--------|-------|---------|
| `POST` | `/ingest` | Upload doc(s) → chunk, hash, embed, append to ledger, re-sign root |
| `POST` | `/query` | Ask a question → answer + citations + proofs + signed root |
| `POST` | `/verify` | Server-side verify (mirrors the CLI) for convenience |
| `GET`  | `/ledger` | Current signed root, leaf count, chain head |
| `GET`  | `/ledger/history` | Chain of roots (audit trail) |
| `POST` | `/tamper-demo` | (Demo only) mutate a stored source → show detection |

Independent verification also ships as a **standalone CLI**: `ledgerrag-verify proof.json`.

---

## 7. Milestones & task breakdown

### Milestone 1 - Ledger core (crypto foundation) · *Weekend 1, day 1*
- [ ] `ledger/merkle.py`: build tree, compute root, generate inclusion proof, verify proof.
- [ ] `ledger/signing.py`: Ed25519 keygen, sign root, verify signature.
- [ ] `ledger/store.py`: append-only ledger entries with prev-root chaining.
- [ ] **Tests** (crown jewels): proof verifies for valid leaf; fails for tampered leaf; fails for wrong root; signature verify.
- **Exit criteria:** `pytest tests/test_merkle.py` green; can prove/verify a leaf end-to-end.

### Milestone 2 - RAG pipeline · *Weekend 1, day 2*
- [ ] `rag/chunker.py`: deterministic chunking + byte normalization.
- [ ] `rag/vector_store.py`: Chroma (default) + pgvector adapter.
- [ ] `rag/retriever.py`: embed query, top-k search.
- [ ] `rag/answer.py`: LLM synthesis grounded strictly on retrieved chunks.
- **Exit criteria:** ask a question, get a cited answer (no proofs yet).

### Milestone 3 - Wire ledger into RAG · *Weekend 2, day 1*
- [ ] `/ingest`: chunk → hash → append leaf → embed → re-sign root.
- [ ] `/query`: attach inclusion proofs + signed root to each citation.
- [ ] `core/models.py`: pydantic response schema.
- **Exit criteria:** `/query` returns a full verifiable response object.

### Milestone 4 - Independent verifier · *Weekend 2, day 2*
- [ ] `ledgerrag-verify` CLI: takes a response/proof JSON, verifies with only the public key.
- [ ] `/verify` endpoint mirroring the CLI.
- [ ] **Tamper test:** mutate a source, re-ingest/re-hash, show proof now fails.
- **Exit criteria:** CLI verifies a real answer offline; tamper is detected.

### Milestone 5 - Frontend proof panel + demo · *Weekend 3*
- [ ] React chat UI: question box, answer, expandable **Proof Panel** (green ✅ verified / red ❌ tampered).
- [ ] `/tamper-demo` button that flips a byte and re-verifies live.
- [ ] Record **demo GIF** for README.
- **Exit criteria:** clickable demo showing verified vs. tampered answer.

### Milestone 6 - Polish & ship · *Weekend 4 (optional but recommended)*
- [ ] README (problem, architecture image, GIF, quickstart, "why it matters").
- [ ] Docker compose one-command run.
- [ ] GitHub Actions CI (lint + tests).
- [ ] Deploy live demo (Vercel frontend + Render/Fly backend).
- [ ] Short blog post + LinkedIn post.
- **Exit criteria:** a stranger can `git clone`, run in <5 min, and understand it in <2 min.

---

## 8. Testing strategy

- **Unit (must-have):** Merkle proof correctness, signature verify, tamper rejection, deterministic hashing.
- **Integration:** ingest → query → verify round-trip.
- **Adversarial demo tests:** altered source, reordered chunks, forged root (should all fail verification).
- **Eval (via EvalForge later):** answer groundedness / citation accuracy as a CI gate.

> The Merkle/tamper tests are the portfolio's *proof of engineering rigor* - make them clean and readable; reviewers will look here.

---

## 9. Stretch goals (post-MVP, great talking points)

- **Transparency log**: publish signed roots to an external append-only log (Sigstore/Rekor-style).
- **Selective disclosure**: prove an answer used a source *without revealing other sources*.
- **Multi-tenant isolation**: per-tenant ledgers + keys (ties to your tenant-isolation resume line).
- **Revocation**: mark a source as retracted; answers citing it are flagged.
- **On-chain anchoring**: periodically anchor the root hash to a public chain for extra non-repudiation.

---

## 10. Definition of Done (flagship)

- ✅ Verifiable answers with working Merkle proofs + signed roots
- ✅ Standalone verifier proves an answer *without trusting the server*
- ✅ Live tamper-detection demo (GIF in README)
- ✅ <5-min quickstart, tests + CI green, live demo link
- ✅ One blog post + one LinkedIn post published
- ✅ Pinned on GitHub profile as flagship

---

## 11. How to start *today*

```bash
cd LedgerRAG
python -m venv .venv && .venv\Scripts\activate      # Windows
pip install -r backend/requirements.txt
# 1) Implement ledger/merkle.py (Milestone 1) - start with the tests in tests/test_merkle.py
pytest backend/tests -q
# 2) Run the API skeleton
uvicorn app.main:app --reload --app-dir backend
```

The repo is already scaffolded (folder structure, README, starter code, CI). Start at **Milestone 1** - the Merkle ledger - because everything else builds on it.
