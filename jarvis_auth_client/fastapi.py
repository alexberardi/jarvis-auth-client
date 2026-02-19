"""FastAPI dependencies for app-to-app authentication.

Provides the require_app_auth dependency for validating incoming
app-to-app authentication against the jarvis-auth service.
"""

import asyncio
import hashlib
import os
import time
from typing import Callable

import httpx
from fastapi import Header, HTTPException, status

from jarvis_auth_client.headers import (
    HEADER_CONTEXT_HOUSEHOLD_ID,
    HEADER_CONTEXT_HOUSEHOLD_MEMBER_IDS,
    HEADER_CONTEXT_NODE_ID,
    HEADER_CONTEXT_USER_ID,
    parse_household_member_ids,
)
from jarvis_auth_client.models import AppAuthResult, AppValidationResult, RequestContext

# Module-level state
_auth_base_url: str | None = None
_http_client: httpx.AsyncClient | None = None
_client_lock: asyncio.Lock | None = None
_cache_ttl: int = 60

# TTL cache: sha256(app_id:app_key) -> (AppValidationResult, timestamp)
# Keys are hashed so raw credentials are never retained in memory.
_validation_cache: dict[str, tuple[AppValidationResult, float]] = {}
_MAX_CACHE_SIZE: int = 256


def _make_cache_key(app_id: str, app_key: str) -> str:
    """Create a non-reversible cache key from credentials."""
    return hashlib.sha256(f"{app_id}:{app_key}".encode()).hexdigest()


def _get_cached_validation(app_id: str, app_key: str) -> AppValidationResult | None:
    """Return cached validation result if within TTL, else None."""
    key = _make_cache_key(app_id, app_key)
    if key in _validation_cache:
        result, timestamp = _validation_cache[key]
        if time.time() - timestamp < _cache_ttl:
            return result
        del _validation_cache[key]
    return None


def _cache_validation_result(app_id: str, app_key: str, result: AppValidationResult) -> None:
    """Store a validation result with the current timestamp."""
    if len(_validation_cache) >= _MAX_CACHE_SIZE:
        # Evict oldest entry
        oldest_key = min(_validation_cache, key=lambda k: _validation_cache[k][1])
        del _validation_cache[oldest_key]
    _validation_cache[_make_cache_key(app_id, app_key)] = (result, time.time())


def clear_validation_cache() -> None:
    """Clear the app-credential validation cache."""
    _validation_cache.clear()


def init(
    auth_base_url: str | None = None,
    cache_ttl: int = 60,
) -> None:
    """Initialize app-to-app auth settings.

    Args:
        auth_base_url: Base URL for jarvis-auth service. Defaults to
            JARVIS_AUTH_BASE_URL environment variable.
        cache_ttl: Cache TTL in seconds for validation results.
    """
    global _auth_base_url, _cache_ttl

    _auth_base_url = auth_base_url or os.getenv("JARVIS_AUTH_BASE_URL")
    _cache_ttl = cache_ttl


async def shutdown() -> None:
    """Shutdown and cleanup resources."""
    global _http_client, _client_lock

    if _http_client:
        await _http_client.aclose()
        _http_client = None

    _client_lock = None
    clear_validation_cache()


def _get_auth_url() -> str:
    """Get the auth service URL.

    Resolution order:
    1. Explicit URL from init(auth_base_url=...)
    2. JARVIS_AUTH_BASE_URL env var
    3. jarvis-config-client (if installed and initialized)
    """
    url = _auth_base_url or os.getenv("JARVIS_AUTH_BASE_URL")
    if url:
        return url

    # Try config-client as last resort
    try:
        from jarvis_config_client import get_service_url
        url = get_service_url("auth")
        if url:
            return url
    except (ImportError, RuntimeError):
        pass

    raise ValueError(
        "jarvis-auth-client not initialized: "
        "call init(auth_base_url=...), set JARVIS_AUTH_BASE_URL, "
        "or initialize jarvis-config-client"
    )


async def _get_client() -> httpx.AsyncClient:
    """Get or create the HTTP client (thread-safe via asyncio.Lock)."""
    global _http_client, _client_lock

    if _client_lock is None:
        _client_lock = asyncio.Lock()

    if _http_client is None:
        async with _client_lock:
            if _http_client is None:
                _http_client = httpx.AsyncClient(timeout=10.0)

    return _http_client


async def validate_app_credentials(
    app_id: str,
    app_key: str,
) -> AppValidationResult:
    """Validate app credentials against jarvis-auth service.

    Results with valid=True are cached for up to `_cache_ttl` seconds.
    Invalid / error results are never cached so retries work immediately.

    Args:
        app_id: The app ID to validate
        app_key: The app key to validate

    Returns:
        AppValidationResult with validation status
    """
    # Check cache first
    cached = _get_cached_validation(app_id, app_key)
    if cached is not None:
        return cached

    auth_url = _get_auth_url()
    client = await _get_client()

    try:
        response = await client.get(
            f"{auth_url}/internal/app-ping",
            headers={
                "X-Jarvis-App-Id": app_id,
                "X-Jarvis-App-Key": app_key,
            },
        )

        if response.status_code == 200:
            try:
                data = response.json()
            except (ValueError, TypeError):
                return AppValidationResult(
                    valid=False,
                    error="Invalid JSON response from auth service",
                )
            result = AppValidationResult(
                valid=True,
                app_id=data.get("app_id"),
                name=data.get("name"),
            )
            _cache_validation_result(app_id, app_key, result)
            return result
        elif response.status_code == 401:
            return AppValidationResult(
                valid=False,
                error="Invalid app credentials",
            )
        else:
            return AppValidationResult(
                valid=False,
                error=f"Auth service error: {response.status_code}",
            )
    except httpx.RequestError as e:
        return AppValidationResult(
            valid=False,
            error=f"Auth service unavailable: {e}",
        )


def require_app_auth() -> Callable[..., AppAuthResult]:
    """Create a FastAPI dependency for app-to-app authentication.

    Usage:
        _app_auth = require_app_auth()

        @app.get("/endpoint")
        async def endpoint(auth: AppAuthResult = Depends(_app_auth)):
            print(auth.app.app_id)
            print(auth.context.household_id)

    Returns:
        A FastAPI dependency function
    """

    async def _dependency(
        x_jarvis_app_id: str | None = Header(None),
        x_jarvis_app_key: str | None = Header(None),
        x_context_household_id: str | None = Header(None, alias=HEADER_CONTEXT_HOUSEHOLD_ID),
        x_context_node_id: str | None = Header(None, alias=HEADER_CONTEXT_NODE_ID),
        x_context_user_id: int | None = Header(None, alias=HEADER_CONTEXT_USER_ID),
        x_context_household_member_ids: str | None = Header(
            None, alias=HEADER_CONTEXT_HOUSEHOLD_MEMBER_IDS
        ),
    ) -> AppAuthResult:
        """Validate app credentials and extract context."""
        if not x_jarvis_app_id or not x_jarvis_app_key:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Missing app credentials",
            )

        # Validate against jarvis-auth
        validation = await validate_app_credentials(x_jarvis_app_id, x_jarvis_app_key)

        if not validation.valid:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=validation.error or "Invalid app credentials",
            )

        # Build context from headers
        context = RequestContext(
            household_id=x_context_household_id,
            node_id=x_context_node_id,
            user_id=x_context_user_id,
            household_member_ids=parse_household_member_ids(x_context_household_member_ids),
        )

        return AppAuthResult(app=validation, context=context)

    return _dependency
