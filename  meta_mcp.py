import os
import jwt
import httpx
from jwt import PyJWKClient
from fastapi import APIRouter, Request
from fastapi.responses import Response

router = APIRouter()

AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")
AUTH0_META_AUDIENCE = os.environ.get("AUTH0_META_AUDIENCE")  # set this
PRM_META_URL = "https://mcp.backyardbrains.com/.well-known/oauth-protected-resource/meta"

_jwks = None

def _jwks_client():
    global _jwks
    if _jwks is None:
        _jwks = PyJWKClient(f"https://{AUTH0_DOMAIN}/.well-known/jwks.json")
    return _jwks

def _challenge_401():
    r = Response(status_code=401)
    r.headers["WWW-Authenticate"] = f'Bearer realm="mcp", resource_metadata="{PRM_META_URL}"'
    return r

def _validate(token: str) -> dict:
    key = _jwks_client().get_signing_key_from_jwt(token).key
    return jwt.decode(
        token,
        key,
        algorithms=["RS256"],
        audience=AUTH0_META_AUDIENCE,
        issuer=f"https://{AUTH0_DOMAIN}/",
    )

def _has_scope(claims: dict, scope: str) -> bool:
    perms = claims.get("permissions") or []
    scopes = (claims.get("scope") or "").split()
    return scope in perms or scope in scopes

@router.post("/meta/")
async def meta_gateway(request: Request):
    # 1) Require bearer
    auth = request.headers.get("authorization", "")
    if not auth.lower().startswith("bearer "):
        return _challenge_401()
    token = auth.split(" ", 1)[1].strip()

    # 2) Validate JWT
    try:
        claims = _validate(token)
    except Exception:
        return _challenge_401()

    # 3) Enforce scope (simple default: require read)
    if not _has_scope(claims, "mcp:read:meta") and not _has_scope(claims, "mcp:write:meta"):
        return Response(status_code=403)

    # 4) Proxy body to meta container MCP endpoint
    body = await request.body()

    # Meta MCP requires Accept include both types
    accept = request.headers.get("accept") or "application/json, text/event-stream"

    headers = {
        "Content-Type": request.headers.get("content-type", "application/json"),
        "Accept": accept,
    }

    async with httpx.AsyncClient(timeout=60) as client:
        upstream = await client.post("http://127.0.0.1:8088/mcp", content=body, headers=headers)

    return Response(
        content=upstream.content,
        status_code=upstream.status_code,
        media_type=upstream.headers.get("content-type", "application/json"),
    )