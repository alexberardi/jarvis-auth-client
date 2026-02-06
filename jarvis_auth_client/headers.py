"""Header utilities for app-to-app authentication.

Provides functions to build authentication and context headers for
inter-service communication.
"""

import os

# Header names
HEADER_APP_ID = "X-Jarvis-App-Id"
HEADER_APP_KEY = "X-Jarvis-App-Key"
HEADER_CONTEXT_HOUSEHOLD_ID = "X-Context-Household-Id"
HEADER_CONTEXT_NODE_ID = "X-Context-Node-Id"
HEADER_CONTEXT_USER_ID = "X-Context-User-Id"
HEADER_CONTEXT_HOUSEHOLD_MEMBER_IDS = "X-Context-Household-Member-Ids"


def get_app_headers() -> dict[str, str]:
    """Get app-to-app authentication headers from environment.

    Reads JARVIS_AUTH_APP_ID and JARVIS_AUTH_APP_KEY from environment
    and returns them as headers for authenticating with other services.

    Returns:
        Dict with X-Jarvis-App-Id and X-Jarvis-App-Key headers.

    Raises:
        ValueError: If environment variables are not set.
    """
    app_id = os.getenv("JARVIS_AUTH_APP_ID")
    app_key = os.getenv("JARVIS_AUTH_APP_KEY")

    if not app_id or not app_key:
        raise ValueError(
            "JARVIS_AUTH_APP_ID and JARVIS_AUTH_APP_KEY must be set in environment"
        )

    return {
        HEADER_APP_ID: app_id,
        HEADER_APP_KEY: app_key,
    }


def build_context_headers(
    household_id: str | None = None,
    node_id: str | None = None,
    user_id: int | None = None,
    household_member_ids: list[int] | None = None,
) -> dict[str, str]:
    """Build context headers for passing request context to downstream services.

    These headers convey information about the original request context
    (household, node, user) to services that need it for scoped operations.

    Args:
        household_id: The household making the request
        node_id: The specific node making the request
        user_id: The user associated with the request
        household_member_ids: List of member IDs in household (for voice recognition)

    Returns:
        Dict with context headers (only non-None values included)
    """
    headers: dict[str, str] = {}

    if household_id:
        headers[HEADER_CONTEXT_HOUSEHOLD_ID] = household_id

    if node_id:
        headers[HEADER_CONTEXT_NODE_ID] = node_id

    if user_id is not None:
        headers[HEADER_CONTEXT_USER_ID] = str(user_id)

    if household_member_ids:
        headers[HEADER_CONTEXT_HOUSEHOLD_MEMBER_IDS] = ",".join(
            str(mid) for mid in household_member_ids
        )

    return headers


def parse_household_member_ids(header_value: str | None) -> list[int]:
    """Parse the household member IDs from header value.

    Args:
        header_value: Comma-separated list of member IDs (e.g., "1,2,3")

    Returns:
        List of parsed integer member IDs
    """
    if not header_value:
        return []

    try:
        return [int(mid.strip()) for mid in header_value.split(",") if mid.strip()]
    except ValueError:
        return []
