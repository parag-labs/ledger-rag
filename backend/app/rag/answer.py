"""Answer synthesis grounded strictly on retrieved chunks.

Local provider returns an extractive answer (no external calls) so the demo
works offline; OpenAI provider gives fluent synthesis. Either way, the answer is
constrained to the retrieved, ledger-committed context.
"""

from __future__ import annotations

from app.core.config import settings
from app.rag.vector_store import StoredChunk


def synthesize(question: str, chunks: list[StoredChunk]) -> str:
    if not chunks:
        return "No relevant sources found; refusing to answer."
    if settings.llm_provider == "openai":
        return _synthesize_openai(question, chunks)
    return _synthesize_local(question, chunks)


def _synthesize_local(question: str, chunks: list[StoredChunk]) -> str:
    top = chunks[0]
    return (
        f"Based on source [{top.doc_id}#{top.seq}]: {top.text[:400]}"
        f"\n\n(Answer grounded on {len(chunks)} ledger-verified source(s).)"
    )


def _synthesize_openai(question: str, chunks: list[StoredChunk]) -> str:
    from openai import OpenAI

    client = OpenAI(api_key=settings.openai_api_key)
    context = "\n\n".join(f"[{c.doc_id}#{c.seq}] {c.text}" for c in chunks)
    prompt = (
        "Answer the question using ONLY the context. Cite sources as [doc#seq]. "
        "If the context is insufficient, say so.\n\n"
        f"Context:\n{context}\n\nQuestion: {question}"
    )
    resp = client.chat.completions.create(
        model="gpt-4o-mini",
        messages=[{"role": "user", "content": prompt}],
        temperature=0,
    )
    return resp.choices[0].message.content or ""
