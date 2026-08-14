from dotenv import load_dotenv
import os

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
REDIS_URL = os.getenv("REDIS_URL", "redis://localhost:6379/0")
CHROMA_COLLECTION_NAME = os.getenv("CHROMA_COLLECTION_NAME", "semantic_cache")
CACHE_SIMILARITY_THRESHOLD = float(os.getenv("CACHE_SIMILARITY_THRESHOLD", "0.15"))
CACHE_TTL_SECONDS = int(os.getenv("CACHE_TTL_SECONDS", "3600"))
EMBEDDING_MODEL_NAME = os.getenv("EMBEDDING_MODEL_NAME", "BAAI/bge-small-en-v1.5")
ENABLE_PII_MASKING = os.getenv("ENABLE_PII_MASKING", "true").lower() == "true"
BLOCK_PROMPT_INJECTION = os.getenv("BLOCK_PROMPT_INJECTION", "true").lower() == "true"
BLOCK_HIGH_RISK_PROMPTS = os.getenv("BLOCK_HIGH_RISK_PROMPTS", "true").lower() == "true"
MAX_RISK_SCORE = float(os.getenv("MAX_RISK_SCORE", "0.8"))
ALLOW_EMAILS = os.getenv("ALLOW_EMAILS", "false").lower() == "true"
ALLOW_PHONE_NUMBERS = os.getenv("ALLOW_PHONE_NUMBERS", "false").lower() == "true"
API_KEYS = [key.strip() for key in os.getenv("API_KEYS", "").split(",") if key.strip()]
REQUIRE_API_KEY = os.getenv("REQUIRE_API_KEY", "true").lower() == "true"
MAX_PROMPT_CHARS = int(os.getenv("MAX_PROMPT_CHARS", "4000"))
MAX_RESPONSE_CHARS = int(os.getenv("MAX_RESPONSE_CHARS", "12000"))
REQUEST_TIMEOUT_SECONDS = float(os.getenv("REQUEST_TIMEOUT_SECONDS", "20"))
REDIS_TIMEOUT_SECONDS = float(os.getenv("REDIS_TIMEOUT_SECONDS", "0.5"))
CHROMA_TIMEOUT_SECONDS = float(os.getenv("CHROMA_TIMEOUT_SECONDS", "1.5"))
GROQ_TIMEOUT_SECONDS = float(os.getenv("GROQ_TIMEOUT_SECONDS", "15"))
GROQ_RETRY_ATTEMPTS = int(os.getenv("GROQ_RETRY_ATTEMPTS", "2"))
GROQ_RETRY_BASE_DELAY_SECONDS = float(os.getenv("GROQ_RETRY_BASE_DELAY_SECONDS", "0.25"))
GROQ_CIRCUIT_BREAKER_FAILURE_THRESHOLD = int(os.getenv("GROQ_CIRCUIT_BREAKER_FAILURE_THRESHOLD", "3"))
GROQ_CIRCUIT_BREAKER_RESET_SECONDS = float(os.getenv("GROQ_CIRCUIT_BREAKER_RESET_SECONDS", "30"))
SECONDARY_MODEL_NAME = os.getenv("SECONDARY_MODEL_NAME", "llama-3.1-8b-instant")


def validate_settings():
    errors = []

    if not GROQ_API_KEY:
        errors.append("GROQ_API_KEY is required")

    if not 0.0 <= CACHE_SIMILARITY_THRESHOLD <= 1.0:
        errors.append("CACHE_SIMILARITY_THRESHOLD must be between 0.0 and 1.0")

    if CACHE_TTL_SECONDS <= 0:
        errors.append("CACHE_TTL_SECONDS must be a positive integer")

    if not 0.0 <= MAX_RISK_SCORE <= 1.0:
        errors.append("MAX_RISK_SCORE must be between 0.0 and 1.0")

    if MAX_PROMPT_CHARS <= 0:
        errors.append("MAX_PROMPT_CHARS must be a positive integer")

    if MAX_RESPONSE_CHARS <= 0:
        errors.append("MAX_RESPONSE_CHARS must be a positive integer")

    if REQUEST_TIMEOUT_SECONDS <= 0:
        errors.append("REQUEST_TIMEOUT_SECONDS must be positive")
    if REDIS_TIMEOUT_SECONDS <= 0:
        errors.append("REDIS_TIMEOUT_SECONDS must be positive")
    if CHROMA_TIMEOUT_SECONDS <= 0:
        errors.append("CHROMA_TIMEOUT_SECONDS must be positive")
    if GROQ_TIMEOUT_SECONDS <= 0:
        errors.append("GROQ_TIMEOUT_SECONDS must be positive")
    if GROQ_RETRY_ATTEMPTS < 0:
        errors.append("GROQ_RETRY_ATTEMPTS must be zero or positive")
    if GROQ_RETRY_BASE_DELAY_SECONDS <= 0:
        errors.append("GROQ_RETRY_BASE_DELAY_SECONDS must be positive")
    if GROQ_CIRCUIT_BREAKER_FAILURE_THRESHOLD <= 0:
        errors.append("GROQ_CIRCUIT_BREAKER_FAILURE_THRESHOLD must be positive")
    if GROQ_CIRCUIT_BREAKER_RESET_SECONDS <= 0:
        errors.append("GROQ_CIRCUIT_BREAKER_RESET_SECONDS must be positive")

    if REQUIRE_API_KEY and not API_KEYS:
        errors.append("API_KEYS must contain at least one key when REQUIRE_API_KEY=true")

    if errors:
        raise ValueError("Invalid configuration: " + "; ".join(errors))
