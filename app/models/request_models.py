from pydantic import BaseModel, ConfigDict, validator
from typing import Optional, List, Dict, Any

from app.core.config import MAX_PROMPT_CHARS

class PromptRequest(BaseModel):
    prompt: str

    @validator("prompt")
    def validate_prompt(cls, value):
        normalized = value.strip()
        if not normalized:
            raise ValueError("prompt must not be empty")
        if len(normalized) > MAX_PROMPT_CHARS:
            raise ValueError(f"prompt must not exceed {MAX_PROMPT_CHARS} characters")
        return normalized


class ChatCompletionRequest(BaseModel):
    # Keep every other OpenAI parameter (tools, tool_choice, response_format, top_p,
    # seed, user, ...) so it can be forwarded; they used to be silently dropped.
    model_config = ConfigDict(extra="allow")

    model: str
    messages: List[Dict[str, Any]]
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    stream: Optional[bool] = False

    @validator("messages")
    def validate_messages(cls, value):
        if not value:
            raise ValueError("messages must not be empty")
        return value

    @validator("model")
    def validate_model(cls, value):
        if not value.strip():
            raise ValueError("model must not be empty")
        return value.strip()


    
