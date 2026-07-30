"""FastAPI application entrypoint (skeleton).

Milestone 1 ships the ledger core + tests. The routes below are stubs to be
filled in Milestones 2-4 (RAG pipeline, proofs, verification). See plan.md.
"""

from fastapi import FastAPI

from app.api import ledger as ledger_routes
from app.api import rag as rag_routes

app = FastAPI(
    title="LedgerRAG",
    version="0.1.0",
    description="Verifiable RAG with a tamper-evident cryptographic ledger.",
)

app.include_router(rag_routes.router)
app.include_router(ledger_routes.router)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}
