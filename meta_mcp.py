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

from auth import check_permissions, validate_opaque_token
from fastapi import HTTPException

from utils import logger

@router.api_route("/meta/", methods=["GET", "POST"])
async def meta_gateway_any(request: Request):
    method = request.method
    # 1) Require bearer
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("bearer "):
        return _challenge_401()
    token = auth_header.split(" ", 1)[1].strip()

    # 2) Validate Token
    try:
        claims = await validate_opaque_token(token)
    except Exception as e:
        logger.warning(f"Meta token validation failed: {e}")
        return _challenge_401()

    # 3) Enforce scope
    if not check_permissions(claims, ["mcp:read:meta", "mcp:write:meta"]):
        logger.warning(f"Insufficient permissions. Claims: {claims}")
        return Response(status_code=403, content="Insufficient permissions")

    # 4) Proxy to upstream
    body = await request.body()
    
    # Forward client's Accept header so upstream knows what to return
    accept = request.headers.get("accept") or "application/json, text/event-stream"
    headers = {
        "Content-Type": request.headers.get("content-type", "application/json"),
        "Accept": accept,
    }

    # Use a long timeout for SSE
    client = httpx.AsyncClient(timeout=300)
    
    # We must stream the request to inspect headers before deciding response type
    upstream_req = client.build_request(method, META_MCP_UPSTREAM, content=body, headers=headers)
    
    try:
        r = await client.send(upstream_req, stream=True)
    except Exception as e:
        await client.aclose()
        logger.error(f"Upstream connection failed: {e}")
        return Response(status_code=502, content=f"Upstream unavailable: {e}")

    upstream_content_type = r.headers.get("content-type", "")
    logger.info(f"Upstream response: {r.status_code} type={upstream_content_type}")

    if "text/event-stream" in upstream_content_type:
        # Pass through the stream for SSE
        async def iterate_stream():
            try:
                async for chunk in r.aiter_bytes():
                    yield chunk
            except Exception as e:
                logger.error(f"Stream error: {e}")
            finally:
                await r.aclose()
                await client.aclose()

        return StreamingResponse(
            iterate_stream(),
            status_code=r.status_code,
            media_type="text/event-stream",
            headers={
                "Cache-Control": "no-cache", 
                "X-Accel-Buffering": "no",
                "Connection": "keep-alive"
            },
        )
    else:
        # Standard response (JSON/text)
        # Read the whole body so we can release the client
        try:
            content = await r.aread()
        finally:
            await r.aclose()
            await client.aclose()

        logger.info(f"Upstream body len={len(content)}")
        return Response(
            content=content,
            status_code=r.status_code,
            media_type=upstream_content_type or "application/json",
        )