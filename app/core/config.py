from dotenv import load_dotenv
import os

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
GEMINI_API_KEY = os.getenv("GEMINI_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
OPEN_ROUTER_API_KEY = os.getenv("OPEN_ROUTER_API_KEY") or os.getenv("OPENROUTER_API_KEY")
# Only allow OpenRouter's free models (":free"), so proxy traffic never spends credits.
OPENROUTER_FREE_ONLY = os.getenv("OPENROUTER_FREE_ONLY", "true").lower() == "true"
DEFAULT_PROVIDER = os.getenv("DEFAULT_PROVIDER", "groq").lower()
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
def _parse_api_keys(raw: str) -> dict:
    """API_KEYS entries are either "key" or "appname:key" (appname = letters, digits,
    "_" or "-"). The app name labels metrics and logs so you can see which application
    is spending tokens or being blocked; unnamed keys get "key-<hash prefix>" so the
    secret itself never appears in metrics or logs."""
    import hashlib
    import re

    apps = {}
    for entry in raw.split(","):
        entry = entry.strip()
        if not entry:
            continue
        match = re.fullmatch(r"([A-Za-z0-9_-]{1,40}):(.+)", entry)
        if match:
            apps[match.group(2).strip()] = match.group(1)
        else:
            apps[entry] = "key-" + hashlib.sha256(entry.encode("utf-8")).hexdigest()[:8]
    return apps


API_KEY_APPS = _parse_api_keys(os.getenv("API_KEYS", ""))
API_KEYS = list(API_KEY_APPS)


def _parse_app_policies(raw: str) -> dict:
    """APP_POLICIES is JSON keyed by app name (the name in API_KEYS "appname:key"):
        {"support-bot": {"rpm": 30, "tpm": 4000,
                         "allowed_models": ["groq/*", "openrouter/*:free"],
                         "max_risk_score": 0.9}}
    Every field is optional; apps without a policy use the global settings."""
    import json

    if not raw.strip():
        return {}
    try:
        policies = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError(f"APP_POLICIES is not valid JSON: {exc}") from exc
    if not isinstance(policies, dict) or not all(isinstance(v, dict) for v in policies.values()):
        raise ValueError('APP_POLICIES must be a JSON object like {"app-name": {"rpm": 30}}')
    return policies


APP_POLICIES = _parse_app_policies(os.getenv("APP_POLICIES", ""))


def get_app_policy(app_name: str) -> dict:
    return APP_POLICIES.get(app_name, {})
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
SECONDARY_MODEL_NAME = os.getenv("SECONDARY_MODEL_NAME", "openai/gpt-oss-20b")
PROMPT_INJECTION_MODEL_NAME = os.getenv(
    "PROMPT_INJECTION_MODEL_NAME",
    "protectai/deberta-v3-base-prompt-injection-v2",
)
# Second-opinion injection model (Llama Prompt Guard 2 on Groq), consulted only when
# the local classifier is the sole signal; cuts false positives on harmless prompts.
INJECTION_VERIFIER_ENABLED = os.getenv("INJECTION_VERIFIER_ENABLED", "true").lower() == "true"
INJECTION_VERIFIER_MODEL = os.getenv("INJECTION_VERIFIER_MODEL", "meta-llama/llama-prompt-guard-2-86m")
INJECTION_VERIFIER_THRESHOLD = float(os.getenv("INJECTION_VERIFIER_THRESHOLD", "0.5"))
INJECTION_VERIFIER_TIMEOUT_SECONDS = float(os.getenv("INJECTION_VERIFIER_TIMEOUT_SECONDS", "3"))
SYSTEM_PROMPT_CANARY = os.getenv("SYSTEM_PROMPT_CANARY", "AI_GUARDRAIL_SYSTEM_CANARY_7f3b9a")
MAX_BEHAVIOR_RISK_SCORE = float(os.getenv("MAX_BEHAVIOR_RISK_SCORE", "0.35"))
BEHAVIOR_RISK_WINDOW_SECONDS = int(os.getenv("BEHAVIOR_RISK_WINDOW_SECONDS", "300"))
BEHAVIOR_RISK_RATE_THRESHOLD = int(os.getenv("BEHAVIOR_RISK_RATE_THRESHOLD", "4"))
RPM_LIMIT_PER_MINUTE = int(os.getenv("RPM_LIMIT_PER_MINUTE", "120"))
TPM_LIMIT_PER_MINUTE = int(os.getenv("TPM_LIMIT_PER_MINUTE", "12000"))
# Models advertised by GET /v1/models (comma-separated, "<provider>/<model>").
AVAILABLE_MODELS = [
    m.strip()
    for m in os.getenv(
        "AVAILABLE_MODELS",
        "groq/openai/gpt-oss-120b,groq/openai/gpt-oss-20b,groq/qwen/qwen3.8-27b,"
        "openrouter/openrouter/free,openrouter/nvidia/nemotron-3.5-super-vl:free,openrouter/google/gemma-4-31b-it:free,"
        "openai/gpt-4o-mini,gemini/gemini-2.5-flash,anthropic/claude-opus-5-5",
    ).split(",")
    if m.strip()
]
# Output hardening options.
# HTML-escape responses (for clients that render them as raw HTML). Off by default:
# JSON clients and the bundled console render text safely, and escaping corrupts code.
ESCAPE_HTML_RESPONSES = os.getenv("ESCAPE_HTML_RESPONSES", "false").lower() == "true"
# Return the model's chain-of-thought ("reasoning" fields). Off by default: it can
# echo system-prompt content and is not PII-redacted by providers.
EXPOSE_REASONING = os.getenv("EXPOSE_REASONING", "false").lower() == "true"
# Characters of streamed output held back so PII/canary redaction can see a whole
# sentence before it is sent.
STREAM_REDACTION_HOLDBACK_CHARS = int(os.getenv("STREAM_REDACTION_HOLDBACK_CHARS", "64"))
# Seconds clients should wait after a degraded (503) response.
DEGRADED_RETRY_AFTER_SECONDS = int(os.getenv("DEGRADED_RETRY_AFTER_SECONDS", "30"))
# Directory for a persistent semantic cache; empty keeps it in memory.
CHROMA_PERSIST_DIR = os.getenv("CHROMA_PERSIST_DIR", "")
# With masking on, the most PII alone may add to the risk score. Kept below
# MAX_RISK_SCORE minus the max behaviour risk (0.35) so masked PII is never blocked alone.
MASKED_PII_RISK_CAP = float(os.getenv("MASKED_PII_RISK_CAP", "0.4"))
# Presidio entity types treated as PII. Context-dependent types (PERSON, LOCATION,
# DATE_TIME, NRP, URL) are off by default: the small spaCy model flags ordinary words
# ("France", "tomorrow") and masking them breaks normal prompts. Add them here to enable.
PII_ENTITIES = frozenset(
    e.strip().upper()
    for e in os.getenv(
        "PII_ENTITIES",
        "EMAIL_ADDRESS,PHONE_NUMBER,CREDIT_CARD,US_SSN,IP_ADDRESS,IBAN_CODE,US_BANK_NUMBER,"
        "US_PASSPORT,US_DRIVER_LICENSE,US_ITIN,CRYPTO,MEDICAL_LICENSE,IN_AADHAAR,IN_PAN",
    ).split(",")
    if e.strip()
)


def validate_settings():
    errors = []

    if DEFAULT_PROVIDER not in {"groq", "openai", "gemini", "anthropic", "openrouter"}:
        errors.append("DEFAULT_PROVIDER must be one of: groq, openai, gemini, anthropic, openrouter")

    if DEFAULT_PROVIDER == "groq" and not GROQ_API_KEY:
        errors.append("GROQ_API_KEY is required when DEFAULT_PROVIDER=groq")
    elif DEFAULT_PROVIDER == "openai" and not OPENAI_API_KEY:
        errors.append("OPENAI_API_KEY is required when DEFAULT_PROVIDER=openai")
    elif DEFAULT_PROVIDER == "gemini" and not GEMINI_API_KEY:
        errors.append("GEMINI_API_KEY is required when DEFAULT_PROVIDER=gemini")
    elif DEFAULT_PROVIDER == "anthropic" and not ANTHROPIC_API_KEY:
        errors.append("ANTHROPIC_API_KEY is required when DEFAULT_PROVIDER=anthropic")
    elif DEFAULT_PROVIDER == "openrouter" and not OPEN_ROUTER_API_KEY:
        errors.append("OPEN_ROUTER_API_KEY is required when DEFAULT_PROVIDER=openrouter")

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
    if MAX_BEHAVIOR_RISK_SCORE < 0.0 or MAX_BEHAVIOR_RISK_SCORE > 1.0:
        errors.append("MAX_BEHAVIOR_RISK_SCORE must be between 0.0 and 1.0")
    if BEHAVIOR_RISK_WINDOW_SECONDS <= 0:
        errors.append("BEHAVIOR_RISK_WINDOW_SECONDS must be positive")
    if BEHAVIOR_RISK_RATE_THRESHOLD <= 0:
        errors.append("BEHAVIOR_RISK_RATE_THRESHOLD must be positive")
    if RPM_LIMIT_PER_MINUTE <= 0:
        errors.append("RPM_LIMIT_PER_MINUTE must be positive")
    if TPM_LIMIT_PER_MINUTE <= 0:
        errors.append("TPM_LIMIT_PER_MINUTE must be positive")

    if not 0.0 <= MASKED_PII_RISK_CAP <= 1.0:
        errors.append("MASKED_PII_RISK_CAP must be between 0.0 and 1.0")

    if REQUIRE_API_KEY and not API_KEYS:
        errors.append("API_KEYS must contain at least one key when REQUIRE_API_KEY=true")

    if errors:
        raise ValueError("Invalid configuration: " + "; ".join(errors))
