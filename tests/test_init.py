"""Tests for package-level init and shutdown."""

import pytest

import jarvis_auth_client
import jarvis_auth_client.client as client_mod
import jarvis_auth_client.fastapi as fastapi_mod


@pytest.fixture(autouse=True)
def _reset_state():
    """Reset module state before each test."""
    original_key = client_mod._secret_key
    original_alg = client_mod._algorithm
    original_url = fastapi_mod._auth_base_url
    original_ttl = fastapi_mod._cache_ttl

    jarvis_auth_client._superuser_initialized = False
    jarvis_auth_client._app_auth_initialized = False
    client_mod._secret_key = None
    client_mod._algorithm = "HS256"
    fastapi_mod._auth_base_url = None
    fastapi_mod._cache_ttl = 60

    yield

    client_mod._secret_key = original_key
    client_mod._algorithm = original_alg
    fastapi_mod._auth_base_url = original_url
    fastapi_mod._cache_ttl = original_ttl


class TestInit:
    def test_init_superuser_only(self):
        jarvis_auth_client.init(secret_key="my-secret")

        assert jarvis_auth_client._superuser_initialized is True
        assert jarvis_auth_client._app_auth_initialized is False
        assert client_mod._secret_key == "my-secret"

    def test_init_app_auth_only(self):
        jarvis_auth_client.init(auth_base_url="https://auth.local")

        assert jarvis_auth_client._superuser_initialized is False
        assert jarvis_auth_client._app_auth_initialized is True
        assert fastapi_mod._auth_base_url == "https://auth.local"

    def test_init_both(self):
        jarvis_auth_client.init(
            secret_key="s3cret",
            auth_base_url="https://auth.local",
        )

        assert jarvis_auth_client._superuser_initialized is True
        assert jarvis_auth_client._app_auth_initialized is True

    def test_init_custom_algorithm(self):
        jarvis_auth_client.init(secret_key="key", algorithm="HS384")
        assert client_mod._algorithm == "HS384"

    def test_init_custom_cache_ttl(self):
        jarvis_auth_client.init(auth_base_url="https://auth.local", cache_ttl=300)
        assert fastapi_mod._cache_ttl == 300

    def test_init_no_args_does_nothing(self):
        jarvis_auth_client.init()

        assert jarvis_auth_client._superuser_initialized is False
        assert jarvis_auth_client._app_auth_initialized is False


class TestShutdown:
    @pytest.mark.asyncio
    async def test_shutdown_calls_fastapi_shutdown(self):
        fastapi_mod._http_client = None
        await jarvis_auth_client.shutdown()
        # Should not raise; verifies the shutdown path works


class TestPublicExports:
    def test_all_exports_accessible(self):
        """Verify all __all__ members are importable."""
        for name in jarvis_auth_client.__all__:
            assert hasattr(jarvis_auth_client, name), f"{name} not found in package"
