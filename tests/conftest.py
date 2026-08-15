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


@pytest.fixture(autouse=True)
def _reset_service_state():
    import app.services.resilient_groq_service as groq_service
    from app.core.resilience import CircuitBreaker

    groq_service.client = None
    groq_service.SECONDARY_MODEL = os.environ["SECONDARY_MODEL_NAME"]
    groq_service.BREAKERS[groq_service.MODEL_NAME] = CircuitBreaker(3, 30)
    groq_service.BREAKERS[groq_service.SECONDARY_MODEL] = CircuitBreaker(3, 30)
    yield
