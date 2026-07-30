"""Standalone verifier CLI.

    python -m app.cli.verify response.json

Verifies a saved QueryResponse using ONLY the embedded public key and proofs --
demonstrating that answers are trustworthy without trusting the server.
"""

from __future__ import annotations

import json
import sys

from app.core.models import QueryResponse
from app.core.verification import verify_response


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python -m app.cli.verify <response.json>")
        return 2
    with open(argv[1], encoding="utf-8") as f:
        resp = QueryResponse.model_validate(json.load(f))

    result = verify_response(resp)
    ok = result["verified"]
    mark = "\u2705 VERIFIED" if ok else "\u274c TAMPERED / INVALID"
    print(mark)
    print(json.dumps(result, indent=2))
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
