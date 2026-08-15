import os

from locust import HttpUser, SequentialTaskSet, task, between


API_KEY = os.getenv("LOAD_TEST_API_KEY", "test-api-key")


class GuardrailFlow(SequentialTaskSet):
    @task
    def generate(self):
        self.client.post(
            "/generate",
            headers={"x-api-key": API_KEY},
            json={"prompt": "Explain transformer architecture in simple terms"},
            name="/generate",
        )

    @task
    def stream(self):
        self.client.post(
            "/stream",
            headers={"x-api-key": API_KEY},
            json={"prompt": "Explain transformers briefly"},
            name="/stream",
        )


class GuardrailUser(HttpUser):
    tasks = [GuardrailFlow]
    wait_time = between(1, 3)
