"""Core JWT validation logic for superuser authentication."""

from fastapi import Header, HTTPException, status
from jose import ExpiredSignatureError, JWTError, jwt

from jarvis_auth_client.models import SuperuserUser

_secret_key: str | None = None
_algorithm: str = "HS256"


def init(secret_key: str, algorithm: str = "HS256") -> None:
    """Initialize the auth client with JWT signing parameters.

    Must be called once at service startup before using require_superuser.

    Args:
        secret_key: The JWT signing key (must match jarvis-auth's SECRET_KEY)
        algorithm: The JWT algorithm (default: HS256)
    """
    global _secret_key, _algorithm
    _secret_key = secret_key
    _algorithm = algorithm


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
        return jwt.decode(token, _secret_key, algorithms=[_algorithm])
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
