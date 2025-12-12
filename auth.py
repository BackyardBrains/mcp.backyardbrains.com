import os
import time
from typing import Optional, Dict, Any

import httpx
from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from utils import logger

# Auth0 configuration
AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")
AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE")
AUTH0_XERO_AUDIENCE = os.environ.get("AUTH0_XERO_AUDIENCE", "https://mcp.backyardbrains.com/xero")
AUTH0_METABASE_AUDIENCE = os.environ.get("AUTH0_METABASE_AUDIENCE", "https://mcp.backyardbrains.com/metabase")
AUTH0_NAMESPACE = "https://mcp.backyardbrains.com"

security = HTTPBearer(auto_error=False)

# Cache /userinfo responses to avoid hammering Auth0 and hitting rate limits
_USERINFO_CACHE: dict[str, tuple[float, Dict[str, Any]]] = {}
AUTH0_USERINFO_CACHE_SECONDS = int(os.environ.get("AUTH0_USERINFO_CACHE_SECONDS", "300"))

async def validate_opaque_token(token: str) -> Dict[str, Any]:
    """Validate an opaque/JWE token by calling Auth0's /userinfo endpoint."""

    if not AUTH0_DOMAIN:
        raise HTTPException(status_code=500, detail="Auth0 domain not configured")

    now = time.time()
    cached = _USERINFO_CACHE.get(token)
    if cached and cached[0] > now:
        return cached[1]

    userinfo_url = f"https://{AUTH0_DOMAIN}/userinfo"

    try:
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {token}"},
            )
    except httpx.HTTPError as exc:
        logger.error("Auth0 userinfo request failed: %s", exc)
        raise HTTPException(status_code=502, detail="Unable to validate token with Auth0")

    if response.status_code == 200:
        payload = response.json()
        _log_scope_claims(payload, context="userinfo")
        _USERINFO_CACHE[token] = (now + AUTH0_USERINFO_CACHE_SECONDS, payload)
        return payload

    if response.status_code == 401:
        raise HTTPException(status_code=401, detail="Invalid or expired token")

    if response.status_code == 429:
        retry_after = response.headers.get("Retry-After")
        logger.warning(
            "Auth0 rate limit hit for /userinfo: status=%s retry_after=%s", response.status_code, retry_after
        )
        raise HTTPException(status_code=429, detail="Auth0 rate limit on /userinfo")

    logger.warning(
        "Unexpected response from Auth0 userinfo: %s %s",
        response.status_code,
        response.text,
    )
    raise HTTPException(status_code=502, detail="Failed to validate token with Auth0")


def check_permissions(payload: Dict[str, Any], required_scopes: list[str]) -> bool:
    """
    Check if the token payload contains at least one of the required scopes.
    Looks at namespaced permissions, 'permissions' list, and 'scope' string.
    """
    # Check namespaced permissions set via Auth0 Action on the ID token
    namespaced_permissions = payload.get(f"{AUTH0_NAMESPACE}/permissions", [])
    if isinstance(namespaced_permissions, list):
        for scope in required_scopes:
            if scope in namespaced_permissions:
                return True

    # Check 'permissions' claim (list format)
    permissions = payload.get("permissions", [])
    if isinstance(permissions, list):
        for scope in required_scopes:
            if scope in permissions:
                return True

    # Check 'scope' claim (space-separated string format)
    scope_string = payload.get("scope", "")
    if isinstance(scope_string, str):
        scopes = scope_string.split()
        for scope in required_scopes:
            if scope in scopes:
                return True

    return False


def _log_scope_claims(payload: Dict[str, Any], *, context: str) -> None:
    """Log permissions/scope claims for debugging."""
    namespaced_permissions = payload.get(f"{AUTH0_NAMESPACE}/permissions")
    permissions = payload.get("permissions")
    scope_string = payload.get("scope")
    logger.info(
        "Auth0 claims for %s: namespaced_permissions=%s permissions=%s scope=%s",
        context,
        namespaced_permissions if namespaced_permissions is not None else "<missing>",
        permissions if permissions is not None else "<missing>",
        scope_string if scope_string is not None else "<missing>",
    )


async def _extract_credentials(request: Request, creds: Optional[HTTPAuthorizationCredentials]):
    if creds is None or creds.scheme.lower() != "bearer":
        logger.warning("Missing/invalid Authorization header for %s %s", request.method, request.url.path)
        raise HTTPException(
            status_code=401,
            detail="Authorization required",
            headers={
                "WWW-Authenticate": (
                    'Bearer '
                    'resource_metadata="https://mcp.backyardbrains.com/.well-known/oauth-protected-resource", '
                    'scope="mcp:read"'
                )
            },
        )
    return creds.credentials


async def require_auth(request: Request, creds: HTTPAuthorizationCredentials = Depends(security)):
    """Base auth - validates token via Auth0 /userinfo with no scope checking."""
    token = await _extract_credentials(request, creds)
    try:
        return await validate_opaque_token(token)
    except HTTPException as exc:
        logger.warning("Token validation failed for %s %s: %s", request.method, request.url.path, exc.detail)
        raise


async def require_xero_auth(request: Request, creds: HTTPAuthorizationCredentials = Depends(security)):
    """Xero-specific auth - requires mcp:read:xero or mcp:write:xero scope."""
    token = await _extract_credentials(request, creds)
    try:
        payload = await validate_opaque_token(token)
        if not check_permissions(payload, ["mcp:read:xero", "mcp:write:xero"]):
            logger.warning("Insufficient permissions for Xero MCP access for %s %s", request.method, request.url.path)
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions. Required: mcp:read:xero or mcp:write:xero",
            )
        return payload
    except HTTPException as exc:
        if exc.status_code == 403:
            raise
        logger.warning("Token validation failed for %s %s: %s", request.method, request.url.path, exc.detail)
        raise


async def require_metabase_auth(request: Request, creds: HTTPAuthorizationCredentials = Depends(security)):
    """Metabase-specific auth - requires mcp:read:metabase or mcp:write:metabase scope."""
    token = await _extract_credentials(request, creds)
    try:
        payload = await validate_opaque_token(token)
        if not check_permissions(payload, ["mcp:read:metabase", "mcp:write:metabase"]):
            logger.warning("Insufficient permissions for Metabase MCP access for %s %s", request.method, request.url.path)
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions. Required: mcp:read:metabase or mcp:write:metabase",
            )
        return payload
    except HTTPException as exc:
        if exc.status_code == 403:
            raise
        logger.warning("Token validation failed for %s %s: %s", request.method, request.url.path, exc.detail)
        raise
