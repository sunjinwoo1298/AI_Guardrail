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