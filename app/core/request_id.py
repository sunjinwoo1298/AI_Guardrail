import uuid
from app.core.context import request_id_context


def generate_request_id():
    request_id = str(uuid.uuid4())
    request_id_context.set(request_id)
    return request_id


def get_request_id(default: str | None = None) -> str | None:
    current = request_id_context.get()
    return current or default
