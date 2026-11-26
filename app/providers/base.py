from __future__ import annotations

from typing import AsyncGenerator, Optional

from fastapi import HTTPException


def resolve_api_key(provider: str, platform_key: Optional[str]) -> Optional[str]:
    """The key to call ``provider`` with for the current request.

    A control-plane tenant's own key (BYOK, project key over organization key) wins.
    Without one, the platform's key from the environment is used, unless the tenant's
    policy sets ``allow_platform_provider_keys: false``; then the request is refused,
    so the platform never pays for, or sees traffic on, an account the tenant should own.
    """
    from app.core.context import tenant_context

    tenant = tenant_context.get()
    if tenant is None:
        return platform_key
    own = tenant.provider_key(provider)
    if own:
        return own
    if not tenant.policy.allow_platform_provider_keys:
        raise HTTPException(status_code=400, detail={
            "message": f"No '{provider}' API key is configured for this project, and the platform key is not allowed",
            "type": "invalid_request_error",
            "code": "provider_key_missing",
        })
    return platform_key


class BaseLLMAdapter:
    # Provider name as used in model strings ("groq/...") and in BYOK credentials.
    provider_name: str = ""
    _platform_key: Optional[str] = None

    @property
    def api_key(self) -> Optional[str]:
        return resolve_api_key(self.provider_name, self._platform_key)

    @api_key.setter
    def api_key(self, value: Optional[str]) -> None:
        self._platform_key = value

    async def generate(
        self,
        messages: list[dict],
        model: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs
    ) -> dict:
        """
        Accepts OpenAI-compatible messages and model parameter, returns standard OpenAI response dict.
        """
        raise NotImplementedError()

    async def stream(
        self,
        messages: list[dict],
        model: str,
        temperature: float | None = None,
        max_tokens: int | None = None,
        **kwargs
    ) -> AsyncGenerator[dict, None]:
        """
        Accepts OpenAI-compatible messages and model parameter, yields standard OpenAI stream chunk dicts.
        """
        raise NotImplementedError()
        yield  # to satisfy compiler/linter that this is a generator
