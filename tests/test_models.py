"""Tests for data models."""

from jarvis_auth_client.models import (
    AppAuthResult,
    AppValidationResult,
    RequestContext,
    SuperuserUser,
)


class TestSuperuserUser:
    def test_defaults(self):
        user = SuperuserUser(user_id=1)
        assert user.user_id == 1
        assert user.email is None
        assert user.auth_type == "superuser_jwt"

    def test_with_email(self):
        user = SuperuserUser(user_id=42, email="admin@test.com")
        assert user.email == "admin@test.com"

    def test_custom_auth_type(self):
        user = SuperuserUser(user_id=1, auth_type="custom")
        assert user.auth_type == "custom"


class TestRequestContext:
    def test_defaults(self):
        ctx = RequestContext()
        assert ctx.household_id is None
        assert ctx.node_id is None
        assert ctx.user_id is None
        assert ctx.household_member_ids == []

    def test_all_fields(self):
        ctx = RequestContext(
            household_id="hh1",
            node_id="n1",
            user_id=5,
            household_member_ids=[1, 2],
        )
        assert ctx.household_id == "hh1"
        assert ctx.node_id == "n1"
        assert ctx.user_id == 5
        assert ctx.household_member_ids == [1, 2]


class TestAppValidationResult:
    def test_valid_result(self):
        r = AppValidationResult(valid=True, app_id="app1", name="My App")
        assert r.valid is True
        assert r.app_id == "app1"
        assert r.name == "My App"
        assert r.error is None

    def test_invalid_result(self):
        r = AppValidationResult(valid=False, error="bad creds")
        assert r.valid is False
        assert r.app_id is None
        assert r.error == "bad creds"


class TestAppAuthResult:
    def test_combined(self):
        app = AppValidationResult(valid=True, app_id="a1")
        ctx = RequestContext(household_id="hh1")
        result = AppAuthResult(app=app, context=ctx)
        assert result.app.app_id == "a1"
        assert result.context.household_id == "hh1"
