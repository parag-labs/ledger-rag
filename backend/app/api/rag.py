"""API routes: /ingest, /query, /verify."""

from __future__ import annotations

from fastapi import APIRouter, UploadFile

from app.core.models import QueryRequest, QueryResponse
from app.core.service import LedgerRagService
from app.core.verification import verify_response

router = APIRouter(tags=["rag"])

# Single in-process service instance (demo scope).
service = LedgerRagService()


@router.post("/ingest")
async def ingest(file: UploadFile) -> dict[str, object]:
    text = (await file.read()).decode("utf-8", errors="ignore")
    return service.ingest(text, doc_id=file.filename)


@router.post("/query", response_model=QueryResponse)
def query(req: QueryRequest) -> QueryResponse:
    return service.query(req.question)


@router.post("/verify")
def verify(resp: QueryResponse) -> dict[str, object]:
    """Server-side mirror of the standalone CLI verifier."""
    return verify_response(resp)
