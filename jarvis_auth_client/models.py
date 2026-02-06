"""Models for jarvis-auth-client."""

from pydantic import BaseModel


class SuperuserUser(BaseModel):
    """Authenticated superuser information extracted from JWT."""

    user_id: int
    email: str | None = None
    auth_type: str = "superuser_jwt"
