"""Tests for app-to-app authentication (fastapi module)."""

import time

import pytest
import httpx
import respx

import jarvis_auth_client.fastapi as mod
from jarvis_auth_client.fastapi import (
    _get_auth_url,
    clear_validation_cache,
    require_app_auth,
    shutdown,
    validate_app_credentials,
)
from jarvis_auth_client.models import AppAuthResult
from fastapi import HTTPException


AUTH_BASE_URL = "https://auth.test.local"


@pytest.fixture(autouse=True)
def _reset_module_state(monkeypatch):
    """Reset fastapi module state before each test."""
    mod._auth_base_url = None
    mod._http_client = None
    mod._cache_ttl = 60
    clear_validation_cache()
    monkeypatch.delenv("JARVIS_AUTH_BASE_URL", raising=False)
    yield
    # Cleanup any open client after test
    if mod._http_client:
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            if loop.is_running():
                pass  # Can't close in running loop; test cleanup handles it
            else:
                loop.run_until_complete(shutdown())
        except RuntimeError:
            pass


class TestInit:
    def test_init_sets_url(self):
        mod.init(auth_base_url="https://auth.example.com")
        assert mod._auth_base_url == "https://auth.example.com"

    def test_init_sets_cache_ttl(self):
        mod.init(auth_base_url="https://auth.example.com", cache_ttl=120)
        assert mod._cache_ttl == 120

    def test_init_reads_env(self, monkeypatch):
        monkeypatch.setenv("JARVIS_AUTH_BASE_URL", "https://env.auth.local")
        mod.init()
        assert mod._auth_base_url == "https://env.auth.local"

    def test_init_explicit_overrides_env(self, monkeypatch):
        monkeypatch.setenv("JARVIS_AUTH_BASE_URL", "https://env.auth.local")
        mod.init(auth_base_url="https://explicit.auth.local")
        assert mod._auth_base_url == "https://explicit.auth.local"


class TestGetAuthUrl:
    def test_returns_initialized_url(self):
        mod._auth_base_url = "https://init.auth.local"
        assert _get_auth_url() == "https://init.auth.local"

    def test_falls_back_to_env(self, monkeypatch):
        monkeypatch.setenv("JARVIS_AUTH_BASE_URL", "https://env.auth.local")
        assert _get_auth_url() == "https://env.auth.local"

    def test_raises_when_no_url(self):
        with pytest.raises(ValueError, match="not initialized"):
            _get_auth_url()


class TestValidateAppCredentials:
    @pytest.mark.asyncio
    @respx.mock
    async def test_valid_credentials(self):
        mod._auth_base_url = AUTH_BASE_URL
        respx.get(f"{AUTH_BASE_URL}/internal/app-ping").mock(
            return_value=httpx.Response(
                200,
                json={"app_id": "app1", "name": "Test App"},
            )
        )

        result = await validate_app_credentials("app1", "key1")

        assert result.valid is True
        assert result.app_id == "app1"
        assert result.name == "Test App"

    @pytest.mark.asyncio
    @respx.mock
    async def test_invalid_credentials_401(self):
        mod._auth_base_url = AUTH_BASE_URL
        respx.get(f"{AUTH_BASE_URL}/internal/app-ping").mock(
            return_value=httpx.Response(401)
        )

        result = await validate_app_credentials("bad", "creds")

        assert result.valid is False
        assert "Invalid app credentials" in result.error

    @pytest.mark.asyncio
    @respx.mock
    async def test_server_error(self):
        mod._auth_base_url = AUTH_BASE_URL
        respx.get(f"{AUTH_BASE_URL}/internal/app-ping").mock(
            return_value=httpx.Response(500)
        )

        result = await validate_app_credentials("app1", "key1")

        assert result.valid is False
        assert "500" in result.error

    @pytest.mark.asyncio
    @respx.mock
    async def test_connection_error(self):
        mod._auth_base_url = AUTH_BASE_URL
        respx.get(f"{AUTH_BASE_URL}/internal/app-ping").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )

        result = await validate_app_credentials("app1", "key1")

        assert result.valid is False
        assert "unavailable" in result.error.lower()


class TestValidationCache:
    @pytest.mark.asyncio
    @respx.mock
    async def test_cache_hit_avoids_http_call(self):
        """Second call with same credentials uses cache."""
        mod._auth_base_url = AUTH_BASE_URL
        route = respx.get(f"{AUTH_BASE_URL}/internal/app-ping").mock(
            return_value=httpx.Response(
                200,
                json={"app_id": "my-app", "name": "My App"},
            )
        )

        result1 = await validate_app_credentials("my-app", "my-key")
        result2 = await validate_app_credentials("my-app", "my-key")

        assert result1.valid is True
        assert result2.valid is True
        assert route.call_count == 1

    @pytest.mark.asyncio
    @respx.mock
    async def test_cache_miss_after_ttl_expires(self, monkeypatch):
        """After TTL expires, a new HTTP call is made."""
        mod._auth_base_url = AUTH_BASE_URL
        route = respx.get(f"{AUTH_BASE_URL}/internal/app-ping").mock(
            return_value=httpx.Response(
                200,
                json={"app_id": "ttl-app", "name": "TTL App"},
            )
        )

        now = time.time()
        monkeypatch.setattr(time, "time", lambda: now)

        await validate_app_credentials("ttl-app", "ttl-key")

        # Advance time past TTL (default 60s)
        monkeypatch.setattr(time, "time", lambda: now + 61)

        await validate_app_credentials("ttl-app", "ttl-key")

        assert route.call_count == 2

    @pytest.mark.asyncio
    @respx.mock
    async def test_invalid_results_not_cached(self):
        """Invalid credentials are NOT cached, allowing immediate retry."""
        mod._auth_base_url = AUTH_BASE_URL
        route = respx.get(f"{AUTH_BASE_URL}/internal/app-ping").mock(
            return_value=httpx.Response(401)
        )

        result1 = await validate_app_credentials("bad-app", "bad-key")
        result2 = await validate_app_credentials("bad-app", "bad-key")

        assert result1.valid is False
        assert result2.valid is False
        assert route.call_count == 2

    @pytest.mark.asyncio
    @respx.mock
    async def test_clear_cache_forces_revalidation(self):
        """clear_validation_cache() forces next call to hit the network."""
        mod._auth_base_url = AUTH_BASE_URL
        route = respx.get(f"{AUTH_BASE_URL}/internal/app-ping").mock(
            return_value=httpx.Response(
                200,
                json={"app_id": "clear-app", "name": "Clear App"},
            )
        )

        await validate_app_credentials("clear-app", "clear-key")
        assert route.call_count == 1

        clear_validation_cache()

        await validate_app_credentials("clear-app", "clear-key")
        assert route.call_count == 2

    @pytest.mark.asyncio
    @respx.mock
    async def test_different_credentials_cached_separately(self):
        """Different credential pairs have separate cache entries."""
        mod._auth_base_url = AUTH_BASE_URL
        route = respx.get(f"{AUTH_BASE_URL}/internal/app-ping").mock(
            return_value=httpx.Response(
                200,
                json={"app_id": "app-a", "name": "App A"},
            )
        )

        await validate_app_credentials("app-a", "key-a")
        await validate_app_credentials("app-b", "key-b")
        assert route.call_count == 2

        # Repeating first one should be cached
        await validate_app_credentials("app-a", "key-a")
        assert route.call_count == 2


class TestRequireAppAuth:
    @pytest.mark.asyncio
    @respx.mock
    async def test_valid_request(self):
        mod._auth_base_url = AUTH_BASE_URL
        respx.get(f"{AUTH_BASE_URL}/internal/app-ping").mock(
            return_value=httpx.Response(
                200,
                json={"app_id": "app1", "name": "Test App"},
            )
        )

        dep = require_app_auth()
        result = await dep(
            x_jarvis_app_id="app1",
            x_jarvis_app_key="key1",
            x_context_household_id="hh1",
            x_context_node_id="n1",
            x_context_user_id=42,
            x_context_household_member_ids="1,2,3",
        )

        assert isinstance(result, AppAuthResult)
        assert result.app.valid is True
        assert result.app.app_id == "app1"
        assert result.context.household_id == "hh1"
        assert result.context.node_id == "n1"
        assert result.context.user_id == 42
        assert result.context.household_member_ids == [1, 2, 3]

    @pytest.mark.asyncio
    async def test_missing_app_id_raises_401(self):
        dep = require_app_auth()
        with pytest.raises(HTTPException) as exc:
            await dep(
                x_jarvis_app_id=None,
                x_jarvis_app_key="key1",
                x_context_household_id=None,
                x_context_node_id=None,
                x_context_user_id=None,
                x_context_household_member_ids=None,
            )
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    async def test_missing_app_key_raises_401(self):
        dep = require_app_auth()
        with pytest.raises(HTTPException) as exc:
            await dep(
                x_jarvis_app_id="app1",
                x_jarvis_app_key=None,
                x_context_household_id=None,
                x_context_node_id=None,
                x_context_user_id=None,
                x_context_household_member_ids=None,
            )
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    @respx.mock
    async def test_invalid_credentials_raises_401(self):
        mod._auth_base_url = AUTH_BASE_URL
        respx.get(f"{AUTH_BASE_URL}/internal/app-ping").mock(
            return_value=httpx.Response(401)
        )

        dep = require_app_auth()
        with pytest.raises(HTTPException) as exc:
            await dep(
                x_jarvis_app_id="bad",
                x_jarvis_app_key="creds",
                x_context_household_id=None,
                x_context_node_id=None,
                x_context_user_id=None,
                x_context_household_member_ids=None,
            )
        assert exc.value.status_code == 401

    @pytest.mark.asyncio
    @respx.mock
    async def test_no_context_headers(self):
        mod._auth_base_url = AUTH_BASE_URL
        respx.get(f"{AUTH_BASE_URL}/internal/app-ping").mock(
            return_value=httpx.Response(
                200,
                json={"app_id": "app1", "name": "Test App"},
            )
        )

        dep = require_app_auth()
        result = await dep(
            x_jarvis_app_id="app1",
            x_jarvis_app_key="key1",
            x_context_household_id=None,
            x_context_node_id=None,
            x_context_user_id=None,
            x_context_household_member_ids=None,
        )

        assert result.context.household_id is None
        assert result.context.node_id is None
        assert result.context.user_id is None
        assert result.context.household_member_ids == []


class TestShutdown:
    @pytest.mark.asyncio
    async def test_shutdown_closes_client(self):
        mod._http_client = httpx.AsyncClient()
        await shutdown()
        assert mod._http_client is None

    @pytest.mark.asyncio
    async def test_shutdown_noop_when_no_client(self):
        mod._http_client = None
        await shutdown()  # Should not raise
        assert mod._http_client is None

    @pytest.mark.asyncio
    @respx.mock
    async def test_shutdown_clears_cache(self):
        mod._auth_base_url = AUTH_BASE_URL
        route = respx.get(f"{AUTH_BASE_URL}/internal/app-ping").mock(
            return_value=httpx.Response(
                200,
                json={"app_id": "shut-app", "name": "Shut App"},
            )
        )

        await validate_app_credentials("shut-app", "shut-key")
        assert route.call_count == 1

        await shutdown()

        mod._auth_base_url = AUTH_BASE_URL
        await validate_app_credentials("shut-app", "shut-key")
        assert route.call_count == 2
