"""Dual-accept verification in require_superuser, for jarvis-auth's RS256 window.

This client verifies tokens locally with key material, which makes it the one
place in the stack (besides jarvis-auth itself) where algorithm confusion is
possible. jarvis-auth publishes its RSA public key, so the family binding below
is load-bearing, not defensive tidiness.
"""
import base64
import hashlib
import hmac
import json

import httpx
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import HTTPException
from jose import jwt

from jarvis_auth_client import client as client_module

SECRET = "shared-hmac-secret"


@pytest.fixture(autouse=True)
def _reset():
    client_module.reset()
    yield
    client_module.reset()


@pytest.fixture
def keypair():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode()
    public_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode()
    return private_pem, public_pem


def _fake_httpx(monkeypatch, *, public_key=None, error=None):
    """Stand in for the /auth/public-key fetch. Returns the list of URLs hit."""
    calls: list[str] = []

    class _Response:
        def raise_for_status(self):
            return None

        def json(self):
            return {"public_key": public_key}

    class _Client:
        def __init__(self, *a, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, url):
            calls.append(url)
            if error is not None:
                raise error
            return _Response()

    monkeypatch.setattr(client_module.httpx, "Client", _Client)
    return calls


def _superuser_claims() -> dict:
    return {"sub": "1", "is_superuser": True, "email": "admin@example.com"}


class TestDualAccept:
    def test_hs256_still_verifies(self):
        client_module.init(secret_key=SECRET)
        token = jwt.encode(_superuser_claims(), SECRET, algorithm="HS256")

        assert client_module._decode_jwt(token)["sub"] == "1"

    def test_rs256_verifies_against_the_fetched_public_key(self, monkeypatch, keypair):
        private_pem, public_pem = keypair
        client_module.init(secret_key=SECRET, auth_base_url="http://auth.invalid")
        calls = _fake_httpx(monkeypatch, public_key=public_pem)

        token = jwt.encode(_superuser_claims(), private_pem, algorithm="RS256")

        assert client_module._decode_jwt(token)["sub"] == "1"
        assert calls == ["http://auth.invalid/auth/public-key"]

    def test_legacy_algorithm_argument_no_longer_pins_verification(
        self, monkeypatch, keypair
    ):
        """A caller still passing algorithm="HS256" must accept RS256 anyway —
        otherwise every un-updated service breaks the moment jarvis-auth flips."""
        private_pem, public_pem = keypair
        client_module.init(
            secret_key=SECRET, algorithm="HS256", auth_base_url="http://auth.invalid"
        )
        _fake_httpx(monkeypatch, public_key=public_pem)

        token = jwt.encode(_superuser_claims(), private_pem, algorithm="RS256")

        assert client_module._decode_jwt(token)["sub"] == "1"

    def test_public_key_is_fetched_once_then_cached(self, monkeypatch, keypair):
        private_pem, public_pem = keypair
        client_module.init(secret_key=SECRET, auth_base_url="http://auth.invalid")
        calls = _fake_httpx(monkeypatch, public_key=public_pem)

        token = jwt.encode(_superuser_claims(), private_pem, algorithm="RS256")
        client_module._decode_jwt(token)
        client_module._decode_jwt(token)

        assert len(calls) == 1


class TestFailsClosed:
    def test_rs256_without_an_auth_url_is_rejected(self, keypair):
        """A service not yet rolled forward: HS256 keeps working, RS256 401s."""
        private_pem, _ = keypair
        client_module.init(secret_key=SECRET)  # no auth_base_url

        token = jwt.encode(_superuser_claims(), private_pem, algorithm="RS256")

        with pytest.raises(HTTPException) as exc:
            client_module._decode_jwt(token)
        assert exc.value.status_code == 401

    def test_rs256_when_the_key_cannot_be_fetched_is_rejected(
        self, monkeypatch, keypair
    ):
        private_pem, _ = keypair
        client_module.init(secret_key=SECRET, auth_base_url="http://auth.invalid")
        _fake_httpx(monkeypatch, error=httpx.ConnectError("down"))

        token = jwt.encode(_superuser_claims(), private_pem, algorithm="RS256")

        with pytest.raises(HTTPException) as exc:
            client_module._decode_jwt(token)
        assert exc.value.status_code == 401

    def test_a_failed_fetch_is_not_cached(self, monkeypatch, keypair):
        private_pem, public_pem = keypair
        client_module.init(secret_key=SECRET, auth_base_url="http://auth.invalid")

        _fake_httpx(monkeypatch, error=httpx.ConnectError("down"))
        assert client_module._rs256_public_key() is None

        _fake_httpx(monkeypatch, public_key=public_pem)
        assert client_module._rs256_public_key() == public_pem

    def test_alg_none_is_rejected(self):
        client_module.init(secret_key=SECRET)

        def b64(obj) -> str:
            return base64.urlsafe_b64encode(json.dumps(obj).encode()).rstrip(b"=").decode()

        forged = f"{b64({'alg': 'none', 'typ': 'JWT'})}.{b64(_superuser_claims())}."

        with pytest.raises(HTTPException) as exc:
            client_module._decode_jwt(forged)
        assert exc.value.status_code == 401

    def test_algorithm_outside_the_allowlist_is_rejected(self):
        client_module.init(secret_key=SECRET)
        token = jwt.encode(_superuser_claims(), SECRET, algorithm="HS512")

        with pytest.raises(HTTPException) as exc:
            client_module._decode_jwt(token)
        assert exc.value.status_code == 401


def test_hs256_signed_with_the_published_public_key_is_rejected(monkeypatch, keypair):
    """Algorithm confusion — a superuser bypass if the family binding is lost.

    jarvis-auth publishes this public key to anyone who asks. Forged by hand
    because python-jose refuses to sign HS256 with a PEM; an attacker won't be
    using python-jose.
    """
    _, public_pem = keypair
    client_module.init(secret_key=SECRET, auth_base_url="http://auth.invalid")
    _fake_httpx(monkeypatch, public_key=public_pem)
    client_module._rs256_public_key()  # warm the cache, as a live service would

    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    header = b64(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    payload = b64(json.dumps(_superuser_claims()).encode())
    sig = b64(
        hmac.new(public_pem.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    )

    with pytest.raises(HTTPException) as exc:
        client_module._decode_jwt(f"{header}.{payload}.{sig}")
    assert exc.value.status_code == 401
