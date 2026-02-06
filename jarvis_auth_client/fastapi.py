"""FastAPI dependencies for app-to-app authentication.

Provides the require_app_auth dependency for validating incoming
app-to-app authentication against the jarvis-auth service.
"""

import os
from functools import lru_cache
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
_cache_ttl: int = 60


@lru_cache(maxsize=128)
def _cached_validation(app_id: str, app_key: str) -> AppValidationResult:
    """Cached synchronous validation (for simple cases)."""
    # Note: This is a placeholder - actual caching happens at a higher level
    pass


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
    global _http_client

    if _http_client:
        await _http_client.aclose()
        _http_client = None


def _get_auth_url() -> str:
    """Get the auth service URL."""
    url = _auth_base_url or os.getenv("JARVIS_AUTH_BASE_URL")
    if not url:
        raise ValueError(
            "jarvis-auth-client not initialized: "
            "call init(auth_base_url=...) or set JARVIS_AUTH_BASE_URL"
        )
    return url


async def _get_client() -> httpx.AsyncClient:
    """Get or create the HTTP client."""
    global _http_client

    if _http_client is None:
        _http_client = httpx.AsyncClient(timeout=10.0)

    return _http_client


async def validate_app_credentials(
    app_id: str,
    app_key: str,
) -> AppValidationResult:
    """Validate app credentials against jarvis-auth service.

    Args:
        app_id: The app ID to validate
        app_key: The app key to validate

    Returns:
        AppValidationResult with validation status
    """
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
            data = response.json()
            return AppValidationResult(
                valid=True,
                app_id=data.get("app_id"),
                name=data.get("name"),
            )
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
