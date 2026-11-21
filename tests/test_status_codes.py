from fastapi.testclient import TestClient

from app.main import app

HEADERS = {"x-api-key": "test-api-key"}


def _allow_everything(monkeypatch):
    import app.middleware.auth_middleware as auth_middleware
    import app.middleware.security_middleware as security_middleware

    monkeypatch.setattr(auth_middleware, "check_and_consume", lambda *a, **k: type("R", (), {"allowed": True})())
    monkeypatch.setattr(security_middleware, "calculate_risk_score", lambda text: (0.0, [], []))


def _degraded_meta():
    return {"status": "degraded", "reason": "model_unavailable", "response": "Service temporarily degraded."}


def test_degraded_generate_returns_503_with_retry_after(monkeypatch):
    import app.api.routes as routes

    _allow_everything(monkeypatch)

    async def fake_generate(*args, **kwargs):
        return {"error": "service degraded"}, _degraded_meta()

    monkeypatch.setattr(routes, "generate_response", fake_generate)
    response = TestClient(app).post("/generate", headers=HEADERS, json={"prompt": "hello"})

    assert response.status_code == 503
    assert response.headers["Retry-After"].isdigit()
    assert response.json()["status"] == "degraded"


def test_degraded_chat_completion_returns_openai_style_503(monkeypatch):
    import app.api.routes as routes

    _allow_everything(monkeypatch)

    async def fake_generate(*args, **kwargs):
        return {"error": "service degraded"}, _degraded_meta()

    monkeypatch.setattr(routes, "generate_response", fake_generate)
    response = TestClient(app).post(
        "/v1/chat/completions",
        headers=HEADERS,
        json={"model": "groq/openai/gpt-oss-20b", "messages": [{"role": "user", "content": "hi"}]},
    )

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "model_unavailable"


def test_degraded_stream_returns_503_before_streaming(monkeypatch):
    import app.api.routes as routes

    _allow_everything(monkeypatch)

    async def fake_stream(*args, **kwargs):
        yield "metadata", _degraded_meta()

    monkeypatch.setattr(routes, "stream_response", fake_stream)
    response = TestClient(app).post("/stream", headers=HEADERS, json={"prompt": "hello"})

    assert response.status_code == 503
    assert "Retry-After" in response.headers


def test_oversize_prompt_returns_413(monkeypatch):
    from app.core.config import MAX_PROMPT_CHARS

    _allow_everything(monkeypatch)
    response = TestClient(app).post("/generate", headers=HEADERS, json={"prompt": "a" * (MAX_PROMPT_CHARS + 1)})

    assert response.status_code == 413
    assert "Prompt too long" in response.json()["error"]


def test_rate_limited_response_has_retry_after(monkeypatch):
    import app.middleware.auth_middleware as auth_middleware

    monkeypatch.setattr(auth_middleware, "check_and_consume", lambda *a, **k: type("R", (), {
        "allowed": False, "reason": "tpm_exceeded", "rpm_used": 1, "rpm_limit": 120,
        "tpm_used": 12000, "tpm_limit": 12000,
    })())
    response = TestClient(app).post("/generate", headers=HEADERS, json={"prompt": "hello"})

    assert response.status_code == 429
    assert 1 <= int(response.headers["Retry-After"]) <= 61
