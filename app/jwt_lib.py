"""
A minimal, from-scratch JSON Web Token (JWT) implementation.

This module implements JWT encoding/decoding by hand -- it does NOT use
PyJWT or any other JWT library. It supports the HS256 (HMAC-SHA256)
signing algorithm only, which is all this project needs.

JWT structure (per RFC 7519 / RFC 7515):

    base64url(header) + "." + base64url(payload) + "." + base64url(signature)

where:
    header    = {"alg": "HS256", "typ": "JWT"}  (JSON, utf-8)
    payload   = arbitrary JSON claims (utf-8)
    signature = HMAC-SHA256(secret, header_b64 + "." + payload_b64)
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time
from typing import Any, Dict, Optional


class JWTError(Exception):
    """Base class for all JWT-related errors."""


class InvalidSignatureError(JWTError):
    """Raised when the signature does not match the expected HMAC."""


class ExpiredTokenError(JWTError):
    """Raised when the token's ``exp`` claim is in the past."""


class MalformedTokenError(JWTError):
    """Raised when the token is not a well-formed ``h.p.s`` string."""


def _b64url_encode(data: bytes) -> str:
    """Base64url-encode bytes with no padding, per RFC 7515 Appendix C."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    """Decode a base64url string, restoring any stripped padding."""
    padding = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + padding)


def _sign(signing_input: str, secret: str) -> bytes:
    """Compute the raw HMAC-SHA256 signature bytes for ``signing_input``."""
    return hmac.new(
        secret.encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256
    ).digest()


def encode(payload: Dict[str, Any], secret: str, expires_in: Optional[int] = None) -> str:
    """
    Encode ``payload`` into a signed HS256 JWT string.

    :param payload: JSON-serializable claims dict (e.g. {"sub": user_id}).
    :param secret: HMAC signing secret.
    :param expires_in: if given, seconds from now after which the token
        expires; sets the standard ``exp`` claim (and ``iat``).
    :return: the encoded "header.payload.signature" JWT string.
    """
    header = {"alg": "HS256", "typ": "JWT"}
    claims = dict(payload)
    now = int(time.time())
    claims.setdefault("iat", now)
    if expires_in is not None:
        claims["exp"] = now + expires_in

    header_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(claims, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_b64}.{payload_b64}"
    signature_b64 = _b64url_encode(_sign(signing_input, secret))

    return f"{signing_input}.{signature_b64}"


def decode(token: str, secret: str, verify_exp: bool = True) -> Dict[str, Any]:
    """
    Decode and verify a JWT string, returning its claims dict.

    Verifies the HMAC-SHA256 signature using constant-time comparison and
    (by default) rejects expired tokens.

    :raises MalformedTokenError: token is not "header.payload.signature".
    :raises InvalidSignatureError: signature doesn't match.
    :raises ExpiredTokenError: ``exp`` claim is in the past.
    """
    try:
        header_b64, payload_b64, signature_b64 = token.split(".")
    except ValueError as exc:
        raise MalformedTokenError("Token must have exactly 3 dot-separated parts") from exc

    signing_input = f"{header_b64}.{payload_b64}"
    try:
        expected_sig = _sign(signing_input, secret)
        actual_sig = _b64url_decode(signature_b64)
    except Exception as exc:  # noqa: BLE001 - any decode failure is malformed
        raise MalformedTokenError(f"Could not decode token: {exc}") from exc

    if not hmac.compare_digest(expected_sig, actual_sig):
        raise InvalidSignatureError("Signature verification failed")

    try:
        payload_json = _b64url_decode(payload_b64)
        claims = json.loads(payload_json)
    except Exception as exc:  # noqa: BLE001
        raise MalformedTokenError(f"Could not decode payload: {exc}") from exc

    if verify_exp and "exp" in claims:
        if int(time.time()) >= int(claims["exp"]):
            raise ExpiredTokenError("Token has expired")

    return claims
