"""jarvis-auth-client: Authentication utilities for Jarvis services.

This library provides:
1. Superuser JWT validation (require_superuser)
2. App-to-app authentication (require_app_auth)
3. Header utilities for inter-service communication
"""

from jarvis_auth_client.client import init as _init_superuser
from jarvis_auth_client.client import require_superuser
from jarvis_auth_client.fastapi import init as _init_app_auth
from jarvis_auth_client.fastapi import require_app_auth
from jarvis_auth_client.fastapi import shutdown as _shutdown_app_auth
from jarvis_auth_client.models import (
    AppAuthResult,
    AppValidationResult,
    RequestContext,
    SuperuserUser,
)

# Module-level state for tracking initialization
_superuser_initialized = False
_app_auth_initialized = False


def init(
    secret_key: str | None = None,
    algorithm: str = "HS256",
    auth_base_url: str | None = None,
    cache_ttl: int = 60,
) -> None:
    """Initialize jarvis-auth-client.

    Args:
        secret_key: JWT secret key for superuser validation (for require_superuser)
        algorithm: JWT algorithm (default: HS256)
        auth_base_url: Base URL for jarvis-auth service (for require_app_auth)
        cache_ttl: Cache TTL in seconds for app validation results
    """
    global _superuser_initialized, _app_auth_initialized

    if secret_key:
        _init_superuser(secret_key=secret_key, algorithm=algorithm)
        _superuser_initialized = True

    if auth_base_url:
        _init_app_auth(auth_base_url=auth_base_url, cache_ttl=cache_ttl)
        _app_auth_initialized = True


async def shutdown() -> None:
    """Shutdown and cleanup resources."""
    await _shutdown_app_auth()


__all__ = [
    # Initialization
    "init",
    "shutdown",
    # Superuser JWT
    "require_superuser",
    "SuperuserUser",
    # App-to-app auth
    "require_app_auth",
    "AppAuthResult",
    "AppValidationResult",
    "RequestContext",
]
