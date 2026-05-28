import hashlib
import json
import threading
import time
import uuid

import chromadb
import redis
from sentence_transformers import SentenceTransformer

from app.core.config import (
    CACHE_SIMILARITY_THRESHOLD,
    CACHE_TTL_SECONDS,
    CHROMA_COLLECTION_NAME,
    EMBEDDING_MODEL_NAME,
    REDIS_URL,
)
from app.core.logger import logger

_redis_client = None
_chroma_client = None
_collection = None
_embedding_model = None
_lock = threading.Lock()


def normalize_prompt(prompt: str) -> str:
    return " ".join(prompt.strip().split()).lower()


def build_exact_cache_key(prompt: str) -> str:
    normalized_prompt = normalize_prompt(prompt)
    prompt_hash = hashlib.sha256(normalized_prompt.encode("utf-8")).hexdigest()
    return f"semantic_cache:exact:{prompt_hash}"


def get_redis_client():
    global _redis_client
    if _redis_client is not None:
        return _redis_client

    with _lock:
        if _redis_client is not None:
            return _redis_client

        try:
            _redis_client = redis.Redis.from_url(REDIS_URL, decode_responses=True)
            _redis_client.ping()
            logger.info("Redis cache initialized")
        except Exception as exc:
            logger.warning(f"Redis cache unavailable: {exc}")
            _redis_client = None

    return _redis_client


def get_chroma_collection():
    global _chroma_client, _collection
    if _collection is not None:
        return _collection

    with _lock:
        if _collection is not None:
            return _collection

        _chroma_client = chromadb.Client()
        _collection = _chroma_client.get_or_create_collection(
            name=CHROMA_COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )
        logger.info("Chroma semantic cache initialized")

    return _collection


def get_embedding_model():
    global _embedding_model
    if _embedding_model is not None:
        return _embedding_model

    with _lock:
        if _embedding_model is not None:
            return _embedding_model

        _embedding_model = SentenceTransformer(EMBEDDING_MODEL_NAME)
        logger.info(f"Embedding model loaded: {EMBEDDING_MODEL_NAME}")

    return _embedding_model


def generate_embedding(text: str):
    model = get_embedding_model()
    embedding = model.encode(text, normalize_embeddings=True)
    return embedding.tolist()


def get_exact_cache(prompt: str):
    redis_client = get_redis_client()
    if redis_client is None:
        return None

    cached_value = redis_client.get(build_exact_cache_key(prompt))
    if cached_value is None:
        return None

    try:
        return json.loads(cached_value)
    except json.JSONDecodeError:
        logger.warning("Invalid JSON in Redis exact cache entry")
        return None


def search_semantic_cache(prompt: str):
    collection = get_chroma_collection()
    query_embedding = generate_embedding(prompt)

    results = collection.query(
        query_embeddings=[query_embedding],
        n_results=1,
        include=["documents", "metadatas", "distances"],
    )

    if not results.get("ids") or not results["ids"][0]:
        return None

    distance = float(results["distances"][0][0])
    if distance > CACHE_SIMILARITY_THRESHOLD:
        return None

    metadata = results.get("metadatas", [[{}]])[0][0] or {}
    documents = results.get("documents", [[""]])[0][0]

    return {
        "response": documents,
        "distance": distance,
        "source_prompt": metadata.get("prompt"),
        "cached_entry": metadata,
    }


def cache_response(
    *,
    prompt: str,
    response: str,
    request_id: str,
    model_name: str,
    prompt_tokens: int,
    completion_tokens: int,
    total_tokens: int,
    estimated_cost: float,
    cache_type: str,
    source_prompt: str | None = None,
    similarity_distance: float | None = None,
    security_metadata: dict | None = None,
):
    payload = {
        "prompt": prompt,
        "response": response,
        "request_id": request_id,
        "model": model_name,
        "prompt_tokens": prompt_tokens,
        "completion_tokens": completion_tokens,
        "total_tokens": total_tokens,
        "estimated_cost": estimated_cost,
        "cache_type": cache_type,
        "source_prompt": source_prompt,
        "similarity_distance": similarity_distance,
        "cached_at": time.time(),
        "security_metadata": security_metadata,
    }

    redis_client = get_redis_client()
    if redis_client is not None:
        try:
            redis_client.setex(
                build_exact_cache_key(prompt),
                CACHE_TTL_SECONDS,
                json.dumps(payload),
            )
        except Exception as exc:
            logger.warning(f"Failed to write Redis cache: {exc}")

    try:
        collection = get_chroma_collection()
        collection.add(
            documents=[response],
            embeddings=[generate_embedding(prompt)],
            metadatas=[payload],
            ids=[str(uuid.uuid4())],
        )
    except Exception as exc:
        logger.warning(f"Failed to write semantic cache: {exc}")
