"""Ledger inspection routes (skeleton for Milestone 3)."""

from fastapi import APIRouter

router = APIRouter(prefix="/ledger", tags=["ledger"])


@router.get("")
def current_root() -> dict[str, object]:
    """Return the current signed Merkle root and leaf count.

    TODO(Milestone 3): wire to the append-only ledger store.
    """
    return {"root": None, "leaf_count": 0, "note": "not yet wired -- see plan.md"}
