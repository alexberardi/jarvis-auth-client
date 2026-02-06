"""Models for jarvis-auth-client."""

from pydantic import BaseModel


class SuperuserUser(BaseModel):
    """Authenticated superuser information extracted from JWT."""

    user_id: int
    email: str | None = None
    auth_type: str = "superuser_jwt"


class RequestContext(BaseModel):
    """Context from request headers about the original caller."""

    household_id: str | None = None
    node_id: str | None = None
    user_id: int | None = None
    household_member_ids: list[int] = []


class AppValidationResult(BaseModel):
    """Result from validating app credentials against jarvis-auth."""

    valid: bool
    app_id: str | None = None
    name: str | None = None
    error: str | None = None


class AppAuthResult(BaseModel):
    """Combined result from app auth validation with request context."""

    app: AppValidationResult
    context: RequestContext
