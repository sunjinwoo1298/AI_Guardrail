from fastapi.testclient import TestClient

from app.main import app


def test_generate_requires_api_key():
    client = TestClient(app)
    response = client.post("/generate", json={"prompt": "hello"})

    assert response.status_code == 401


def test_generate_accepts_valid_api_key(monkeypatch):
    import app.services.resilient_groq_service as groq_service

    async def fake_none(query):
        return None

    monkeypatch.setattr(groq_service, "get_exact_cache", fake_none)
    monkeypatch.setattr(groq_service, "search_semantic_cache", fake_none)

    class FakeUsage:
        prompt_tokens = 1
        completion_tokens = 1
        total_tokens = 2

    class FakeMessage:
        content = "ok"

    class FakeChoice:
        message = FakeMessage()

    class FakeCompletion:
        usage = FakeUsage()
        choices = [FakeChoice()]

    class FakeClient:
        class chat:
            class completions:
                @staticmethod
                async def create(**kwargs):
                    return FakeCompletion()

    monkeypatch.setattr(groq_service, "get_groq_client", lambda: FakeClient())
    monkeypatch.setattr(groq_service, "record_model_observation", lambda **kwargs: None)
    async def fake_cache_response(**kwargs):
        return None

    monkeypatch.setattr(groq_service, "cache_response", fake_cache_response)

    client = TestClient(app)
    response = client.post(
        "/generate",
        headers={"x-api-key": "test-api-key"},
        json={"prompt": "hello"},
    )

    assert response.status_code == 200
    assert response.json()["response"] == "ok"


def test_generate_rate_limit_rejects_abusive_key(monkeypatch):
    import app.middleware.auth_middleware as auth_middleware

    async def fake_check_and_consume(*args, **kwargs):
        class Result:
            allowed = False
            reason = "rpm_exceeded"
            rpm_used = 121
            rpm_limit = 120
            tpm_used = 1000
            tpm_limit = 12000

        return Result()

    monkeypatch.setattr(auth_middleware, "check_and_consume", lambda *args, **kwargs: type("Result", (), {
        "allowed": False,
        "reason": "rpm_exceeded",
        "rpm_used": 121,
        "rpm_limit": 120,
        "tpm_used": 1000,
        "tpm_limit": 12000,
    })())

    client = TestClient(app)
    response = client.post(
        "/generate",
        headers={"x-api-key": "test-api-key"},
        json={"prompt": "hello"},
    )

    assert response.status_code == 429
    body = response.json()
    assert body["error"] == "Rate limit exceeded"
    assert body["reason"] == "rpm_exceeded"
