"""Tests for jarvis-auth-client."""

from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from jose import jwt

from jarvis_auth_client import init, require_superuser, SuperuserUser

SECRET = "test-secret-key"
ALGORITHM = "HS256"


def _make_token(
    user_id: int = 1,
    email: str = "admin@example.com",
    is_superuser: bool = True,
    expired: bool = False,
    secret: str = SECRET,
) -> str:
    now = datetime.now(timezone.utc)
    exp = now - timedelta(hours=1) if expired else now + timedelta(hours=1)
    payload = {
        "sub": str(user_id),
        "email": email,
        "is_superuser": is_superuser,
        "exp": exp,
        "iat": now,
    }
    return jwt.encode(payload, secret, algorithm=ALGORITHM)


@pytest.fixture(autouse=True)
def _init_client():
    """Initialize the auth client before each test."""
    init(secret_key=SECRET, algorithm=ALGORITHM)


class TestInit:
    def test_missing_init_raises_500(self):
        """Should raise 500 if init() was not called."""
        import jarvis_auth_client.client as mod
        original = mod._secret_key
        mod._secret_key = None
        try:
            token = _make_token()
            with pytest.raises(HTTPException) as exc:
                require_superuser(authorization=f"Bearer {token}")
            assert exc.value.status_code == 500
            assert "not initialized" in exc.value.detail
        finally:
            mod._secret_key = original


class TestRequireSuperuser:
    def test_valid_superuser_returns_user(self):
        token = _make_token(user_id=42, email="admin@test.com")
        user = require_superuser(authorization=f"Bearer {token}")

        assert isinstance(user, SuperuserUser)
        assert user.user_id == 42
        assert user.email == "admin@test.com"
        assert user.auth_type == "superuser_jwt"

    def test_non_superuser_returns_403(self):
        token = _make_token(is_superuser=False)
        with pytest.raises(HTTPException) as exc:
            require_superuser(authorization=f"Bearer {token}")
        assert exc.value.status_code == 403
        assert "superuser" in exc.value.detail.lower()

    def test_expired_token_returns_401(self):
        token = _make_token(expired=True)
        with pytest.raises(HTTPException) as exc:
            require_superuser(authorization=f"Bearer {token}")
        assert exc.value.status_code == 401
        assert "expired" in exc.value.detail.lower()

    def test_missing_authorization_returns_401(self):
        with pytest.raises(HTTPException) as exc:
            require_superuser(authorization=None)
        assert exc.value.status_code == 401
        assert "Missing" in exc.value.detail

    def test_invalid_format_returns_401(self):
        with pytest.raises(HTTPException) as exc:
            require_superuser(authorization="Basic abc123")
        assert exc.value.status_code == 401
        assert "format" in exc.value.detail.lower()

    def test_malformed_token_returns_401(self):
        with pytest.raises(HTTPException) as exc:
            require_superuser(authorization="Bearer not-a-jwt")
        assert exc.value.status_code == 401

    def test_wrong_secret_returns_401(self):
        token = _make_token(secret="wrong-secret")
        with pytest.raises(HTTPException) as exc:
            require_superuser(authorization=f"Bearer {token}")
        assert exc.value.status_code == 401

    def test_missing_sub_claim_returns_401(self):
        """Token without sub claim should be rejected."""
        now = datetime.now(timezone.utc)
        payload = {
            "email": "test@test.com",
            "is_superuser": True,
            "exp": now + timedelta(hours=1),
            "iat": now,
        }
        token = jwt.encode(payload, SECRET, algorithm=ALGORITHM)
        with pytest.raises(HTTPException) as exc:
            require_superuser(authorization=f"Bearer {token}")
        assert exc.value.status_code == 401
        assert "missing user ID" in exc.value.detail
