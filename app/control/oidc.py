"""Verify admin users' OpenID Connect tokens (SSO).

The admin console or CLI signs the user in at the company's identity provider (Okta,
Entra ID, Google Workspace, Auth0, Keycloak, ...) and sends the resulting JWT as
``Authorization: Bearer <jwt>``. The signature is checked against the issuer's published
keys (JWKS, cached), plus issuer, audience, expiry and, by default, ``email_verified``.
"""
from __future__ import annotations

import threading
import time
from typing import Optional

from app.core import config
from app.core.logger import logger


class OidcError(Exception):
    pass


_jwks_client = None
_jwks_lock = threading.Lock()
_discovery = {"url": None, "fetched_at": 0.0}


def enabled() -> bool:
    return bool(config.OIDC_ISSUER and config.OIDC_AUDIENCE)


def looks_like_jwt(token: str) -> bool:
    return token.count(".") == 2 and token.startswith("eyJ")


def _jwks_url() -> str:
    if config.OIDC_JWKS_URL:
        return config.OIDC_JWKS_URL
    if _discovery["url"] and time.monotonic() - _discovery["fetched_at"] < 3600:
        return _discovery["url"]
    import httpx

    response = httpx.get(f"{config.OIDC_ISSUER}/.well-known/openid-configuration", timeout=5)
    response.raise_for_status()
    url = response.json()["jwks_uri"]
    _discovery.update(url=url, fetched_at=time.monotonic())
    return url


def _client():
    global _jwks_client
    with _jwks_lock:
        if _jwks_client is None:
            from jwt import PyJWKClient

            # Keys are cached and refetched when an unknown key id appears (key rotation).
            _jwks_client = PyJWKClient(_jwks_url(), cache_keys=True, lifespan=3600)
        return _jwks_client


def reset() -> None:
    global _jwks_client
    with _jwks_lock:
        _jwks_client = None
    _discovery.update(url=None, fetched_at=0.0)


def verify(token: str, signing_key: Optional[object] = None) -> str:
    """The verified, lower-cased e-mail of the token's subject, or OidcError."""
    import jwt

    try:
        key = signing_key if signing_key is not None else _client().get_signing_key_from_jwt(token).key
        claims = jwt.decode(
            token, key, algorithms=config.OIDC_ALGORITHMS, audience=config.OIDC_AUDIENCE,
            issuer=config.OIDC_ISSUER, options={"require": ["exp", "iat", "iss", "aud"]}, leeway=30,
        )
    except jwt.PyJWTError as exc:
        raise OidcError(f"invalid token: {exc}") from exc
    except Exception as exc:  # JWKS fetch / discovery failures
        logger.warning(f"OIDC key retrieval failed: {exc!r}")
        raise OidcError("identity provider keys unavailable") from exc
    email = claims.get(config.OIDC_EMAIL_CLAIM)
    if not isinstance(email, str) or "@" not in email:
        raise OidcError(f"token has no '{config.OIDC_EMAIL_CLAIM}' claim")
    if config.OIDC_REQUIRE_EMAIL_VERIFIED and claims.get("email_verified") is not True:
        raise OidcError("e-mail address is not verified by the identity provider")
    return email.strip().lower()
