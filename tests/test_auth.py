from fastapi.testclient import TestClient

from app.main import app


def test_generate_requires_api_key():
    client = TestClient(app)
    response = client.post("/generate", json={"prompt": "hello"})

    assert response.status_code == 401


def test_generate_accepts_valid_api_key(monkeypatch):
    import app.services.llm_orchestrator as groq_service

    async def fake_none(*args, **kwargs):
        return None

    monkeypatch.setattr(groq_service, "get_exact_cache", fake_none)
    monkeypatch.setattr(groq_service, "search_semantic_cache", fake_none)

    async def fake_create_completion(messages, model, stream=False, **_kwargs):
        return {
            "choices": [{"message": {"role": "assistant", "content": "ok"}}],
            "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}
        }

    monkeypatch.setattr(groq_service, "_create_completion", fake_create_completion)
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
