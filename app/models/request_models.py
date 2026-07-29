from pydantic import BaseModel, validator

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

    
