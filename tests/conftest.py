import os
import sys
from pathlib import Path
import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

os.environ.setdefault("GROQ_API_KEY", "test-key")
os.environ.setdefault("API_KEYS", "test-api-key")
os.environ.setdefault("SECONDARY_MODEL_NAME", "fallback-model")
# Tests must not call the remote injection verifier; tests that need it monkeypatch it.
os.environ.setdefault("INJECTION_VERIFIER_ENABLED", "false")


@pytest.fixture(autouse=True)
def _reset_service_state():
    import app.services.llm_orchestrator as groq_service
    from app.core.resilience import CircuitBreaker

    groq_service._breakers.clear()
    groq_service._breakers["groq/llama-3.1-8b-instant"] = CircuitBreaker(3, 30)
    groq_service._breakers[os.environ["SECONDARY_MODEL_NAME"]] = CircuitBreaker(3, 30)
    yield
