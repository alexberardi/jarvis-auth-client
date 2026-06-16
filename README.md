# jarvis-auth-client

A small shared Python library for authentication in Jarvis microservices. It provides FastAPI dependencies and helpers so services can validate superuser JWTs, perform app-to-app authentication against `jarvis-auth`, and build the headers used for inter-service calls.

## What it provides

- **Superuser JWT validation** — `require_superuser`, a FastAPI dependency that decodes and validates a superuser JWT locally using a shared secret key.
- **App-to-app auth** — `require_app_auth` (FastAPI dependency) and `validate_app_credentials`, which validate `X-Jarvis-App-Id` / `X-Jarvis-App-Key` by round-tripping to the `jarvis-auth` service (with a short-lived cache).
- **Header utilities** — `get_app_headers()` (reads `JARVIS_APP_ID` / `JARVIS_APP_KEY` from the environment) and `build_context_headers(...)` for forwarding request context (household / node / user) to downstream services.
- **Typed models** — `SuperuserUser`, `AppAuthResult`, `AppValidationResult`, `RequestContext`.

## Requirements

- Python 3.11+
- Depends on `fastapi`, `python-jose[cryptography]`, `pydantic`, `httpx`.

## Installation

From source (this repo):

```bash
pip install -e ".[dev]"     # editable install with dev/test deps
```

Or pin it from git in a consuming service's `pyproject.toml`:

```toml
dependencies = [
  "jarvis-auth-client @ git+https://github.com/alexberardi/jarvis-auth-client.git@<rev>",
]
```

## Usage

Initialize once at startup, then use the dependencies in your routes:

```python
import jarvis_auth_client

# Enable superuser JWT validation and/or app-to-app auth
jarvis_auth_client.init(
    secret_key="<AUTH_SECRET_KEY>",            # required for require_superuser
    algorithm="HS256",
    auth_base_url="http://localhost:7701",     # required for require_app_auth
    cache_ttl=60,
)
```

```python
from fastapi import Depends, FastAPI
from jarvis_auth_client import require_superuser, require_app_auth, SuperuserUser, AppAuthResult

app = FastAPI()

@app.get("/admin/thing")
def admin_only(user: SuperuserUser = Depends(require_superuser)):
    return {"superuser": user}

@app.get("/internal/thing")
def app_to_app(ctx: AppAuthResult = Depends(require_app_auth())):
    return {"app": ctx}
```

For outbound service-to-service calls, attach the auth/context headers:

```python
from jarvis_auth_client.headers import get_app_headers, build_context_headers

headers = {
    **get_app_headers(),  # reads JARVIS_APP_ID / JARVIS_APP_KEY from env
    **build_context_headers(household_id="...", node_id="...", user_id=1),
}
```

Call `await jarvis_auth_client.shutdown()` on application shutdown to release the HTTP client used for app validation.

## Testing

```bash
pytest
```

## License

Apache-2.0 (see `LICENSE`).
