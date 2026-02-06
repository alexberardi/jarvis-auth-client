# jarvis-auth-client

Shared Python library for authentication across Jarvis microservices.

Provides two auth mechanisms:
1. **Superuser JWT** - For admin endpoints requiring superuser access
2. **App-to-App** - For inter-service authentication with context headers

## Quick Reference

```bash
# Setup
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Test
pytest
```

## Usage

### Superuser JWT Authentication

```python
from jarvis_auth_client import init, require_superuser, SuperuserUser

# One-time init at service startup
init(secret_key=os.getenv("JARVIS_AUTH_SECRET_KEY"))

# FastAPI dependency — returns SuperuserUser or raises 401/403
@app.get("/admin/something")
def admin_endpoint(user: SuperuserUser = Depends(require_superuser)):
    print(user.user_id, user.email)
```

### App-to-App Authentication

```python
from jarvis_auth_client import init, require_app_auth, AppAuthResult
from jarvis_auth_client.headers import get_app_headers, build_context_headers

# Init for app auth (at startup)
init(auth_base_url=os.getenv("JARVIS_AUTH_BASE_URL"))

# FastAPI dependency — validates app credentials via jarvis-auth
_app_auth = require_app_auth()

@app.post("/transcribe")
async def transcribe(auth: AppAuthResult = Depends(_app_auth)):
    print(auth.app.app_id)
    print(auth.context.household_id)
```

### Making Authenticated Requests

```python
from jarvis_auth_client.headers import get_app_headers, build_context_headers

# Build headers for calling another service
headers = {
    **get_app_headers(),  # X-Jarvis-App-Id, X-Jarvis-App-Key from env
    **build_context_headers(
        household_id="hh123",
        node_id="node456",
        user_id=789,
        household_member_ids=[1, 2, 3],
    ),
}
response = await client.post("http://whisper/transcribe", headers=headers)
```

## Public API

### Initialization

| Symbol | Description |
|--------|-------------|
| `init(secret_key, algorithm, auth_base_url, cache_ttl)` | Initialize auth settings |
| `shutdown()` | Cleanup resources (call on app shutdown) |

### Superuser JWT

| Symbol | Type | Description |
|--------|------|-------------|
| `require_superuser` | FastAPI Dependency | Validates Bearer token, checks `is_superuser` claim |
| `SuperuserUser` | Pydantic Model | `user_id: int`, `email: str \| None`, `auth_type: str` |

### App-to-App Auth

| Symbol | Type | Description |
|--------|------|-------------|
| `require_app_auth()` | Factory | Creates FastAPI dependency for app auth |
| `AppAuthResult` | Model | Combined app validation + request context |
| `AppValidationResult` | Model | Result of validating app credentials |
| `RequestContext` | Model | Context from X-Context-* headers |

### Header Utilities

| Symbol | Description |
|--------|-------------|
| `get_app_headers()` | Returns auth headers from JARVIS_AUTH_APP_ID/KEY env vars |
| `build_context_headers(...)` | Returns X-Context-* headers for passing request context |

## Environment Variables

| Variable | Used By | Description |
|----------|---------|-------------|
| `JARVIS_AUTH_SECRET_KEY` | require_superuser | JWT signing key |
| `JARVIS_AUTH_BASE_URL` | require_app_auth | URL for jarvis-auth service |
| `JARVIS_AUTH_APP_ID` | get_app_headers | App ID for outgoing requests |
| `JARVIS_AUTH_APP_KEY` | get_app_headers | App key for outgoing requests |

## Error Responses

### Superuser JWT

| Status | When |
|--------|------|
| 401 | Missing/invalid/expired token |
| 403 | Valid token but `is_superuser` is false |
| 500 | `init()` not called before first request |

### App-to-App

| Status | When |
|--------|------|
| 401 | Missing credentials or invalid app credentials |
| 503 | jarvis-auth service unavailable |

## Used By

- `jarvis-settings-server` — superuser auth for settings aggregation
- `jarvis-command-center` — app-to-app headers for calling whisper/tts
- `jarvis-whisper-api` — app auth for incoming requests
- `jarvis-tts` — app auth for incoming requests

## Known Limitations

**Superuser JWT - No database validation**: Validates JWT signature and `is_superuser` claim
but does not verify user still exists/is active in database. Tokens are valid until expiry
(default 30 minutes).

**App auth - No caching yet**: Each request validates against jarvis-auth. Future versions
may add caching with TTL.

## Dependencies

- fastapi, python-jose, pydantic, httpx
