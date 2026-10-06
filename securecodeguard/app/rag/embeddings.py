"""
SecureCodeGuard – Embedding Service

Wraps a BGE/E5-family Sentence Transformers model for generating
embeddings. The model name is configurable via .env.
"""

from __future__ import annotations

import logging
from typing import List, Optional

from app.config import get_settings

logger = logging.getLogger(__name__)

# Lazy-loaded singleton
_model = None


def _fallback_embed(text: str, dim: int = 384) -> List[float]:
    """Lightweight deterministic feature hash vectorizer fallback."""
    import hashlib
    import math
    vec = [0.0] * dim
    words = text.lower().split()
    if not words:
        return vec
    for word in words:
        h = int(hashlib.md5(word.encode('utf-8')).hexdigest(), 16)
        idx = h % dim
        vec[idx] += 1.0
    norm = math.sqrt(sum(x * x for x in vec))
    if norm > 0:
        vec = [x / norm for x in vec]
    return vec


def _get_model():
    """Load the embedding model lazily."""
    global _model
    if _model is None:
        settings = get_settings()
        try:
            from sentence_transformers import SentenceTransformer
            logger.info(
                "Loading embedding model: %s on %s",
                settings.embedding_model, settings.embedding_device,
            )
            _model = SentenceTransformer(
                settings.embedding_model,
                device=settings.embedding_device,
            )
            logger.info("Embedding model loaded successfully.")
        except Exception as e:
            logger.warning("sentence_transformers unavailable or failed (%s); using fallback hash embeddings.", e)
            _model = "FALLBACK"
    return _model


def embed_texts(texts: List[str]) -> List[List[float]]:
    """Embed a list of texts and return vectors."""
    model = _get_model()
    if model == "FALLBACK":
        return [_fallback_embed(t) for t in texts]
    embeddings = model.encode(
        texts,
        normalize_embeddings=True,
        show_progress_bar=False,
    )
    return embeddings.tolist()


def embed_query(query: str) -> List[float]:
    """Embed a single query string."""
    return embed_texts([query])[0]
