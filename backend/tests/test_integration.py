"""Integration tests: end-to-end ingest -> query -> verify, plus tamper detection."""

import copy

from app.core.service import LedgerRagService
from app.core.verification import verify_response

DOC = (
    "Refund Policy. Customers may request a full refund within 30 days of purchase. "
    "Subscriptions can be cancelled anytime and take effect at the end of the cycle. "
    "Security. All data is encrypted in transit and at rest with least-privilege access."
)


def _service_with_doc() -> LedgerRagService:
    svc = LedgerRagService()
    svc.ingest(DOC, doc_id="policy")
    return svc


def test_ingest_then_query_returns_proofs():
    svc = _service_with_doc()
    resp = svc.query("What is the refund window?")
    assert resp.answer
    assert resp.citations and resp.proofs
    assert resp.signed_root.leaf_count == len(svc.store)


def test_valid_response_verifies():
    svc = _service_with_doc()
    resp = svc.query("How is data protected?")
    result = verify_response(resp)
    assert result["verified"] is True
    assert result["signature_ok"] is True


def test_tampered_citation_text_fails_verification():
    svc = _service_with_doc()
    resp = svc.query("What is the refund window?")
    tampered = copy.deepcopy(resp)
    # Attacker rewrites the answer's cited source text after the fact.
    tampered.citations[0].text = tampered.citations[0].text + " ...and refunds are DENIED."
    result = verify_response(tampered)
    assert result["verified"] is False


def test_forged_signature_fails():
    svc = _service_with_doc()
    resp = svc.query("cancellation policy?")
    tampered = copy.deepcopy(resp)
    # Flip the leaf_count so the signed message no longer matches.
    tampered.signed_root.leaf_count += 1
    result = verify_response(tampered)
    assert result["signature_ok"] is False
    assert result["verified"] is False
