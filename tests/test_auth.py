from fastapi.testclient import TestClient

from app.main import app


def test_generate_requires_api_key():
    client = TestClient(app)
    response = client.post("/generate", json={"prompt": "hello"})

    assert response.status_code == 401


def test_generate_accepts_valid_api_key(monkeypatch):
    import app.services.groq_service as groq_service

    monkeypatch.setattr(groq_service, "get_exact_cache", lambda query: None)
    monkeypatch.setattr(groq_service, "search_semantic_cache", lambda query: None)

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
    monkeypatch.setattr(groq_service, "cache_response", lambda **kwargs: None)

    client = TestClient(app)
    response = client.post(
        "/generate",
        headers={"x-api-key": "test-api-key"},
        json={"prompt": "hello"},
    )

    assert response.status_code == 200
    assert response.json()["response"] == "ok"
