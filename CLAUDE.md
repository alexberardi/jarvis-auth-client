# jarvis-auth-client

Shared Python library for superuser JWT validation across Jarvis microservices.

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

```python
from jarvis_auth_client import init, require_superuser, SuperuserUser

# One-time init at service startup
init(secret_key=os.getenv("JARVIS_AUTH_SECRET_KEY"), algorithm="HS256")

# FastAPI dependency — returns SuperuserUser or raises 401/403
@app.get("/admin/something")
def admin_endpoint(user: SuperuserUser = Depends(require_superuser)):
    print(user.user_id, user.email)
```

## Public API

| Symbol | Type | Description |
|--------|------|-------------|
| `init(secret_key, algorithm)` | Function | Initialize JWT settings (call once at startup) |
| `require_superuser` | FastAPI Dependency | Validates Bearer token, checks `is_superuser` claim |
| `SuperuserUser` | Pydantic Model | `user_id: int`, `email: str | None`, `auth_type: str` |

## Error Responses

| Status | When |
|--------|------|
| 401 | Missing/invalid/expired token |
| 403 | Valid token but `is_superuser` is false |
| 500 | `init()` not called before first request |

## Used By

- `jarvis-settings-server` — superuser auth for settings aggregation
- `jarvis-admin` (future) — admin dashboard backend

## Known Limitations

**No database validation**: This library validates the JWT signature and `is_superuser` claim
but does **not** verify that the user still exists or is active in the database. If a superuser
is deactivated or has their status revoked, they retain access until the token expires
(default 30 minutes). This is an intentional trade-off — the library has no database dependency.

For services that need stronger guarantees (e.g., jarvis-auth itself), use the DB-backed
`require_superuser` dependency from `jarvis_auth.app.api.deps` instead.

## Dependencies

- fastapi, python-jose, pydantic
