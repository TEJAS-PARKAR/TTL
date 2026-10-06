"""
SecureCodeGuard – ChromaDB Vector Store

Manages ChromaDB collections for code, guidelines, logs,
static-analysis findings, and historical findings.
Supports metadata filtering by doc_type.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import chromadb
    from chromadb.config import Settings as ChromaSettings
    _HAVE_CHROMA = True
except ImportError:
    chromadb = None  # type: ignore
    _HAVE_CHROMA = False

from app.config import get_settings
from app.rag.embeddings import embed_texts, embed_query

logger = logging.getLogger(__name__)

# Fallback in-memory storage
_in_memory_store: Dict[str, Dict[str, Any]] = {}


class _InMemoryCollection:
    def __init__(self, name: str):
        self.name = name
        if name not in _in_memory_store:
            _in_memory_store[name] = {"ids": [], "docs": [], "embeds": [], "metas": []}
        self.data = _in_memory_store[name]

    def add(self, ids, documents, embeddings, metadatas):
        self.data["ids"].extend(ids)
        self.data["docs"].extend(documents)
        self.data["embeds"].extend(embeddings)
        self.data["metas"].extend(metadatas)

    def count(self):
        return len(self.data["ids"])

    def query(self, query_embeddings, n_results=5, where=None, include=None):
        if not self.data["ids"]:
            return {"ids": [[]], "documents": [[]], "metadatas": [[]], "distances": [[]]}
        
        q_emb = query_embeddings[0]
        scored = []
        for i, (did, doc, emb, meta) in enumerate(zip(self.data["ids"], self.data["docs"], self.data["embeds"], self.data["metas"])):
            if where:
                match = True
                for k, v in where.items():
                    if meta.get(k) != v:
                        match = False
                        break
                if not match:
                    continue
            # Cosine distance
            dot = sum(a * b for a, b in zip(q_emb, emb))
            dist = max(0.0, 1.0 - dot)
            scored.append((dist, did, doc, meta))
        
        scored.sort(key=lambda x: x[0])
        top = scored[:n_results]
        
        return {
            "ids": [[x[1] for x in top]],
            "documents": [[x[2] for x in top]],
            "metadatas": [[x[3] for x in top]],
            "distances": [[x[0] for x in top]],
        }


# Singleton client
_client: Optional[Any] = None


def get_chroma_client() -> Any:
    """Get or create the ChromaDB persistent client."""
    global _client
    if not _HAVE_CHROMA:
        return None
    if _client is None:
        settings = get_settings()
        persist_dir = str(settings.resolve_path(settings.chroma_persist_dir))
        Path(persist_dir).mkdir(parents=True, exist_ok=True)
        logger.info("Initializing ChromaDB at %s", persist_dir)
        try:
            _client = chromadb.PersistentClient(path=persist_dir)
        except Exception:
            _client = chromadb.Client()
    return _client


def _get_or_create_collection(name: str):
    """Get or create a ChromaDB or fallback collection."""
    if not _HAVE_CHROMA:
        return _InMemoryCollection(name)
    client = get_chroma_client()
    if client is None:
        return _InMemoryCollection(name)
    try:
        return client.get_or_create_collection(
            name=name,
            metadata={"hnsw:space": "cosine"},
        )
    except Exception as e:
        logger.warning("Falling back to in-memory collection due to: %s", e)
        return _InMemoryCollection(name)


def add_documents(
    collection_name: str,
    ids: List[str],
    texts: List[str],
    metadatas: List[Dict[str, Any]],
) -> int:
    """
    Add documents to a ChromaDB collection with pre-computed embeddings.

    Returns the number of documents added.
    """
    if not texts:
        return 0

    collection = _get_or_create_collection(collection_name)
    embeddings = embed_texts(texts)

    # ChromaDB has batch size limits; chunk if needed
    batch_size = 100
    added = 0
    for i in range(0, len(texts), batch_size):
        batch_ids = ids[i:i + batch_size]
        batch_texts = texts[i:i + batch_size]
        batch_embeds = embeddings[i:i + batch_size]
        batch_meta = metadatas[i:i + batch_size]

        # Ensure metadata values are str/int/float (ChromaDB constraint)
        clean_meta = []
        for m in batch_meta:
            clean = {}
            for k, v in m.items():
                if isinstance(v, (str, int, float, bool)):
                    clean[k] = v
                else:
                    clean[k] = str(v)
            clean_meta.append(clean)

        collection.add(
            ids=batch_ids,
            documents=batch_texts,
            embeddings=batch_embeds,
            metadatas=clean_meta,
        )
        added += len(batch_ids)

    logger.info("Added %d documents to collection '%s'", added, collection_name)
    return added


def query_collection(
    collection_name: str,
    query_text: str,
    top_k: Optional[int] = None,
    where_filter: Optional[Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """
    Query a ChromaDB collection by semantic similarity.

    Parameters
    ----------
    collection_name : str
        Name of the collection to query.
    query_text : str
        The query string.
    top_k : int, optional
        Number of results to return (defaults to config RAG_TOP_K).
    where_filter : dict, optional
        ChromaDB metadata filter, e.g. {"doc_type": "code"}.

    Returns
    -------
    List of dicts with keys: id, text, metadata, distance.
    """
    settings = get_settings()
    k = top_k or settings.rag_top_k
    collection = _get_or_create_collection(collection_name)

    query_embedding = embed_query(query_text)

    kwargs: Dict[str, Any] = {
        "query_embeddings": [query_embedding],
        "n_results": k,
        "include": ["documents", "metadatas", "distances"],
    }
    if where_filter:
        kwargs["where"] = where_filter

    try:
        results = collection.query(**kwargs)
    except Exception as e:
        logger.error("ChromaDB query failed: %s", e)
        return []

    # Unpack ChromaDB results format
    documents = results.get("documents", [[]])[0]
    metadatas = results.get("metadatas", [[]])[0]
    distances = results.get("distances", [[]])[0]
    ids = results.get("ids", [[]])[0]

    output = []
    for i in range(len(documents)):
        output.append({
            "id": ids[i],
            "text": documents[i],
            "metadata": metadatas[i] if i < len(metadatas) else {},
            "distance": distances[i] if i < len(distances) else 1.0,
        })

    return output


def query_multiple_collections(
    query_text: str,
    doc_types: Optional[List[str]] = None,
    top_k: Optional[int] = None,
) -> Dict[str, List[Dict[str, Any]]]:
    """
    Query across multiple document type collections.

    Parameters
    ----------
    query_text : str
    doc_types : list of str, optional
        Which doc types to query. None = all.
    top_k : int, optional

    Returns
    -------
    Dict mapping doc_type → list of results.
    """
    settings = get_settings()
    all_types = {
        "code": settings.chroma_collection_code,
        "guidelines": settings.chroma_collection_guidelines,
        "logs": settings.chroma_collection_logs,
        "static_analysis": settings.chroma_collection_static,
        "historical": settings.chroma_collection_historical,
    }

    if doc_types:
        types_to_query = {k: v for k, v in all_types.items() if k in doc_types}
    else:
        types_to_query = all_types

    results = {}
    for dtype, coll_name in types_to_query.items():
        try:
            results[dtype] = query_collection(
                collection_name=coll_name,
                query_text=query_text,
                top_k=top_k,
            )
        except Exception as e:
            logger.warning("Failed to query collection %s: %s", coll_name, e)
            results[dtype] = []

    return results


def get_collection_count(collection_name: str) -> int:
    """Return the number of documents in a collection."""
    try:
        collection = _get_or_create_collection(collection_name)
        return collection.count()
    except Exception:
        return 0


def clear_collection(collection_name: str) -> None:
    """Delete all documents in a collection."""
    client = get_chroma_client()
    try:
        client.delete_collection(collection_name)
        logger.info("Cleared collection: %s", collection_name)
    except Exception as e:
        logger.warning("Could not clear collection %s: %s", collection_name, e)
