import os
import jwt
import httpx
from jwt import PyJWKClient
from fastapi import APIRouter, Request
from fastapi.responses import Response, StreamingResponse

router = APIRouter()

# Upstream MCP endpoint
META_MCP_UPSTREAM = os.environ.get("META_MCP_UPSTREAM", "http://127.0.0.1:8088/mcp")

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

from auth import check_permissions

@router.post("/meta/")
async def meta_gateway(request: Request):
    # 1) Require bearer
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return _challenge_401()
    token = auth_header.split(" ", 1)[1].strip()

    # 2) Validate JWT
    try:
        claims = _validate(token)
    except Exception as e:
        # logger.warning(f"Meta JWT validation failed: {e}")
        return _challenge_401()

    # 3) Enforce scope (require mcp:read:meta or mcp:write:meta)
    if not check_permissions(claims, ["mcp:read:meta", "mcp:write:meta"]):
        return Response(status_code=403, content="Insufficient permissions")

    # 4) Proxy body to meta container MCP endpoint
    body = await request.body()

    # Meta MCP requires Accept include both types
    accept = request.headers.get("accept") or "application/json, text/event-stream"

    headers = {
        "Content-Type": request.headers.get("content-type", "application/json"),
        "Accept": accept,
    }

    # Check if client expects streaming (SSE)
    wants_stream = "text/event-stream" in accept

    if wants_stream:
        # Streaming proxy for SSE responses
        client = httpx.AsyncClient(timeout=300)

        async def stream_response():
            try:
                async with client.stream("POST", META_MCP_UPSTREAM, content=body, headers=headers) as resp:
                    async for chunk in resp.aiter_bytes():
                        yield chunk
            finally:
                await client.aclose()

        return StreamingResponse(
            stream_response(),
            media_type="text/event-stream",
            headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
        )
    else:
        # Standard request/response for JSON
        async with httpx.AsyncClient(timeout=60) as client:
            upstream = await client.post(META_MCP_UPSTREAM, content=body, headers=headers)

        return Response(
            content=upstream.content,
            status_code=upstream.status_code,
            media_type=upstream.headers.get("content-type", "application/json"),
        )