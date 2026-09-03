"""Core JWT validation logic for superuser authentication."""

import httpx
from fastapi import Header, HTTPException, status
from jose import ExpiredSignatureError, JWTError, jwt

from jarvis_auth_client.models import SuperuserUser

# Key material is bound to the algorithm FAMILY, never to one shared variable.
# jarvis-auth publishes its RSA public key at /auth/public-key for anyone to
# read. If a single "the key" variable fed jwt.decode, an attacker could sign a
# token HS256 using that published public key as the HMAC secret and be verified
# as a superuser. Binding the key to the family means such a token is checked
# against the HMAC secret instead, and fails.
SYMMETRIC_ALGORITHMS = frozenset({"HS256"})
ASYMMETRIC_ALGORITHMS = frozenset({"RS256"})
SUPPORTED_ALGORITHMS = SYMMETRIC_ALGORITHMS | ASYMMETRIC_ALGORITHMS

_secret_key: str | None = None
_algorithm: str = "HS256"
_auth_base_url: str | None = None
_public_key_cache: str | None = None


def init(
    secret_key: str,
    algorithm: str = "HS256",
    auth_base_url: str | None = None,
) -> None:
    """Initialize the auth client with JWT signing parameters.

    Must be called once at service startup before using require_superuser.

    Args:
        secret_key: The HMAC key for HS256 (must match jarvis-auth's SECRET_KEY)
        algorithm: Legacy parameter. Verification now accepts HS256 and RS256
            from an allowlist regardless of this value — a verifier pinned to one
            algorithm makes jarvis-auth's staged RS256 rollout impossible, since
            tokens minted before the flip must keep working after it. Retained so
            existing callers keep working; it no longer gates anything.
        auth_base_url: jarvis-auth's base URL. Required to verify RS256 tokens —
            the public key is fetched from {auth_base_url}/auth/public-key. Without
            it, RS256 tokens fail closed (401) while HS256 keeps working, which is
            the correct behaviour for a service not yet rolled forward.
    """
    global _secret_key, _algorithm, _auth_base_url, _public_key_cache
    _secret_key = secret_key
    _algorithm = algorithm
    _auth_base_url = auth_base_url
    _public_key_cache = None


def reset() -> None:
    """Clear all module state, including the cached public key. For tests."""
    global _secret_key, _algorithm, _auth_base_url, _public_key_cache
    _secret_key = None
    _algorithm = "HS256"
    _auth_base_url = None
    _public_key_cache = None


def _rs256_public_key() -> str | None:
    """Fetch and cache jarvis-auth's public key.

    Cached for the process lifetime so a RUNNING service keeps verifying if
    jarvis-auth goes down; only a cold start during an outage fails, and it fails
    closed. A failed fetch is not cached, so recovery needs no restart.
    """
    global _public_key_cache
    if _public_key_cache:
        return _public_key_cache
    if not _auth_base_url:
        return None
    try:
        with httpx.Client(timeout=5.0) as client:
            resp = client.get(f"{_auth_base_url.rstrip('/')}/auth/public-key")
            resp.raise_for_status()
            _public_key_cache = resp.json().get("public_key")
    except (httpx.HTTPError, ValueError):
        return None
    return _public_key_cache


def _decode_jwt(token: str) -> dict:
    """Decode and validate a JWT token.

    Returns:
        The decoded payload

    Raises:
        HTTPException: If the token is invalid, expired, or client not initialized
    """
    if not _secret_key:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="jarvis-auth-client not initialized: call init(secret_key=...) at startup",
        )

    try:
        algorithm = jwt.get_unverified_header(token).get("alg")
        if algorithm not in SUPPORTED_ALGORITHMS:
            # Covers "none" and anything else exotic.
            raise JWTError(f"Unsupported token algorithm: {algorithm!r}")
        if algorithm in ASYMMETRIC_ALGORITHMS:
            key = _rs256_public_key()
            if not key:
                # Fail CLOSED: a token we cannot check is not accepted.
                raise JWTError("No RS256 public key available")
        else:
            key = _secret_key
        return jwt.decode(token, key, algorithms=[algorithm])
    except ExpiredSignatureError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        ) from exc
    except JWTError as exc:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        ) from exc


def require_superuser(
    authorization: str | None = Header(None),
) -> SuperuserUser:
    """FastAPI dependency that requires a superuser JWT token.

    Args:
        authorization: The Authorization header (Bearer <token>)

    Returns:
        SuperuserUser with the authenticated user's information

    Raises:
        HTTPException: If not authenticated or not a superuser
    """
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid Authorization header format. Expected: Bearer <token>",
            headers={"WWW-Authenticate": "Bearer"},
        )

    token = authorization[7:]
    payload = _decode_jwt(token)

    is_superuser = payload.get("is_superuser", False)
    if not is_superuser:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Superuser access required",
        )

    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token: missing user ID",
        )

    return SuperuserUser(
        user_id=int(user_id),
        email=payload.get("email"),
    )
