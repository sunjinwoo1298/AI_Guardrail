"""Encryption of tenants' provider keys (bring your own key) and hashing of API keys."""
from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import List, Optional

from app.core import config


class EncryptionUnavailable(RuntimeError):
    """PROVIDER_KEY_ENCRYPTION_KEYS is not configured, so secrets cannot be stored."""


def validate_keys(keys: List[str]) -> Optional[str]:
    try:
        from cryptography.fernet import Fernet

        for key in keys:
            Fernet(key.encode("utf-8"))
    except ImportError:
        return "PROVIDER_KEY_ENCRYPTION_KEYS needs the 'cryptography' package"
    except Exception:
        return "PROVIDER_KEY_ENCRYPTION_KEYS must be comma-separated Fernet keys (32 url-safe base64 bytes)"
    return None


def _fernet():
    if not config.PROVIDER_KEY_ENCRYPTION_KEYS:
        raise EncryptionUnavailable("PROVIDER_KEY_ENCRYPTION_KEYS is not configured")
    from cryptography.fernet import Fernet, MultiFernet

    # MultiFernet encrypts with the first key and decrypts with any, so a new key can be
    # put in front and old ciphertexts re-encrypted later (rotate_ciphertext).
    return MultiFernet([Fernet(k.encode("utf-8")) for k in config.PROVIDER_KEY_ENCRYPTION_KEYS])


def encrypt_secret(plaintext: str) -> str:
    return _fernet().encrypt(plaintext.encode("utf-8")).decode("ascii")


def decrypt_secret(ciphertext: str) -> str:
    return _fernet().decrypt(ciphertext.encode("ascii")).decode("utf-8")


def rotate_ciphertext(ciphertext: str) -> str:
    return _fernet().rotate(ciphertext.encode("ascii")).decode("ascii")


def secret_hint(secret: str) -> str:
    """Last four characters, the only part of a stored secret ever shown again."""
    return "…" + secret[-4:] if len(secret) >= 8 else "…"


# --- API keys ---------------------------------------------------------------------------

def generate_api_key() -> str:
    """``gpk_<43 url-safe chars>`` (256 bits of randomness)."""
    return f"{config.API_KEY_PREFIX}_{secrets.token_urlsafe(32)}"


def hash_api_key(key: str) -> str:
    """HMAC-SHA256 with a server-side secret. Plain SHA-256 of a high-entropy key would also
    resist brute force, but the HMAC means a leaked database alone can't even confirm a
    guessed key."""
    return hmac.new(config.KEY_HASH_SECRET.encode("utf-8"), key.encode("utf-8"), hashlib.sha256).hexdigest()


def key_display_prefix(key: str) -> str:
    """Shown in the admin API and logs to identify a key: "gpk_AbCd1234"."""
    return key[: len(config.API_KEY_PREFIX) + 9]


def looks_like_issued_key(key: str) -> bool:
    return key.startswith(f"{config.API_KEY_PREFIX}_") and len(key) >= len(config.API_KEY_PREFIX) + 20
