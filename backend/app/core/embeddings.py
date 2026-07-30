"""Embeddings with a dependency-free local fallback.

The default 'local' provider is a deterministic hashing embedder so the whole
project runs and tests pass with zero external services or API keys. Swap to
OpenAI via config for real semantic quality.
"""

from __future__ import annotations

import hashlib
import math

from app.core.config import settings

_DIM = 256


def embed(texts: list[str]) -> list[list[float]]:
    if settings.embedding_provider == "openai":
        return _embed_openai(texts)
    return [_embed_local(t) for t in texts]


def _embed_local(text: str) -> list[float]:
    """Deterministic bag-of-tokens hashing embedding (offline, no deps)."""
    vec = [0.0] * _DIM
    for token in text.lower().split():
        h = int(hashlib.sha256(token.encode("utf-8")).hexdigest(), 16)
        vec[h % _DIM] += 1.0
    norm = math.sqrt(sum(v * v for v in vec)) or 1.0
    return [v / norm for v in vec]


def _embed_openai(texts: list[str]) -> list[list[float]]:
    from openai import OpenAI

    client = OpenAI(api_key=settings.openai_api_key)
    resp = client.embeddings.create(model="text-embedding-3-small", input=texts)
    return [d.embedding for d in resp.data]


def cosine(a: list[float], b: list[float]) -> float:
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a)) or 1.0
    nb = math.sqrt(sum(y * y for y in b)) or 1.0
    return dot / (na * nb)
