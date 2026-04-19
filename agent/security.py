import hmac
import hashlib
import json
import time
import base64
import os
from typing import Dict, Any, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# =========================================================
# CONFIG
# =========================================================

DEFAULT_TIMESTAMP_TOLERANCE = 300  # 5 minutes
AES_NONCE_SIZE = 12  # required for AES-GCM


# =========================================================
# JSON HELPERS
# =========================================================

def _serialize_body(body: Dict[str, Any]) -> str:
    return json.dumps(body or {}, sort_keys=True, separators=(",", ":"))


def _build_message(timestamp: str, body: Dict[str, Any]) -> bytes:
    return f"{timestamp}:{_serialize_body(body)}".encode("utf-8")


# =========================================================
# HMAC SIGNING (AUTH + INTEGRITY)
# =========================================================

def sign_request(secret: str, timestamp: str, body: Dict[str, Any]) -> str:
    message = _build_message(timestamp, body)

    return hmac.new(
        secret.encode("utf-8"),
        message,
        hashlib.sha256
    ).hexdigest()


def verify_request(
    secret: str,
    timestamp: str,
    body: Dict[str, Any],
    signature: str,
    tolerance_seconds: int = DEFAULT_TIMESTAMP_TOLERANCE
) -> bool:

    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False

    now = int(time.time())

    # replay protection
    if abs(now - ts) > tolerance_seconds:
        return False

    expected = sign_request(secret, timestamp, body)

    return hmac.compare_digest(expected, signature)


# =========================================================
# ENCRYPTION (CONFIDENTIALITY)
# =========================================================

def encrypt_payload(key: bytes, data: Dict[str, Any]) -> str:
    """
    Encrypt JSON payload using AES-GCM.
    Returns base64 string (nonce + ciphertext).
    """

    aesgcm = AESGCM(key)

    nonce = os.urandom(AES_NONCE_SIZE)
    plaintext = _serialize_body(data).encode("utf-8")

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)

    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def decrypt_payload(key: bytes, token: str) -> Dict[str, Any]:
    """
    Decrypt AES-GCM payload from base64 string.
    Returns original JSON dict.
    """

    raw = base64.b64decode(token)

    nonce = raw[:AES_NONCE_SIZE]
    ciphertext = raw[AES_NONCE_SIZE:]

    aesgcm = AESGCM(key)

    plaintext = aesgcm.decrypt(nonce, ciphertext, None)

    return json.loads(plaintext.decode("utf-8"))


# =========================================================
# CONVENIENCE HELPERS (DJANGO USAGE)
# =========================================================

def extract_headers(request) -> Dict[str, Optional[str]]:
    return {
        "secret": request.headers.get("X-AGENT-SECRET"),
        "timestamp": request.headers.get("X-AGENT-TIMESTAMP"),
        "signature": request.headers.get("X-AGENT-SIGNATURE"),
        "encrypted": request.headers.get("X-AGENT-BODY"),
    }


def validate_request(secret: str, timestamp: str, body: Dict[str, Any], signature: str) -> bool:
    return verify_request(secret, timestamp, body, signature)


def decrypt_request_body(secret: bytes, encrypted_body: str) -> Dict[str, Any]:
    return decrypt_payload(secret, encrypted_body)