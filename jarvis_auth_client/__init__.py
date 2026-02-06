"""jarvis-auth-client: Shared superuser JWT validation for Jarvis services."""

from jarvis_auth_client.client import init, require_superuser
from jarvis_auth_client.models import SuperuserUser

__all__ = ["init", "require_superuser", "SuperuserUser"]
