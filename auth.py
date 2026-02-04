import os
import time
from typing import Optional, Dict, Any

import httpx
from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from utils import logger, safe_dumps
from jose import jwt, JWTError

# Auth0 configuration
AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")
# JWT_SECRET and attributes loaded dynamically to handle import order issues
ALGORITHM = "HS256"
AUTH0_XERO_AUDIENCE = os.environ.get("AUTH0_XERO_AUDIENCE", "https://mcp.backyardbrains.com/xero")
AUTH0_METABASE_AUDIENCE = os.environ.get("AUTH0_METABASE_AUDIENCE", "https://mcp.backyardbrains.com/metabase")
AUTH0_META_AUDIENCE = os.environ.get("AUTH0_META_AUDIENCE", "https://mcp.backyardbrains.com/meta")
AUTH0_MYSQL_AUDIENCE = os.environ.get("AUTH0_MYSQL_AUDIENCE", "https://mcp.backyardbrains.com/mysql")
# workshops audience usually same as mysql if they share the same backend, but user wants separate naming
AUTH0_WORKSHOPS_AUDIENCE = os.environ.get("AUTH0_WORKSHOPS_AUDIENCE", "https://mcp.backyardbrains.com/workshops")
AUTH0_ASSISTANT_AUDIENCE = os.environ.get("AUTH0_ASSISTANT_AUDIENCE", "https://mcp.backyardbrains.com/assistant")
AUTH0_NAMESPACE = "https://mcp.backyardbrains.com"

security = HTTPBearer(auto_error=False)

# Cache /userinfo responses to avoid hammering Auth0 and hitting rate limits
_USERINFO_CACHE: dict[str, tuple[float, Dict[str, Any]]] = {}
AUTH0_USERINFO_CACHE_SECONDS = int(os.environ.get("AUTH0_USERINFO_CACHE_SECONDS", "300"))

async def validate_opaque_token(token: str) -> Dict[str, Any]:
    """
    Validate a token. 
    First attempts to validate as a local long-lived JWT API Key.
    If that fails, validates as an opaque/JWE token by calling Auth0's /userinfo endpoint.
    """
    
    # 1. Try to validate as local JWT (API Key)
    # Load secret dynamically to support restart-less env updates if possible or import-order safety
    # Load secret dynamically to support restart-less env updates if possible or import-order safety
    jwt_secret = os.environ.get("JWT_SECRET")
    if not jwt_secret:
        # Try emergency reload
        from dotenv import load_dotenv
        from pathlib import Path
        env_path = Path(__file__).parent / ".env"
        load_dotenv(dotenv_path=env_path, override=True)
        jwt_secret = os.environ.get("JWT_SECRET")

    if jwt_secret:
        try:
            payload = jwt.decode(token, jwt_secret, algorithms=[ALGORITHM])
            # If successful, return payload directly
            # We might want to refresh the cache/log it, but for now just return it
            # Ensure it has necessary fields
            return payload
        except JWTError as e:
            # Not a valid local JWT, fall back to Auth0 opaque token validation
            # If it's just padding, it's likely an opaque token which is expected
            if "Invalid payload padding" in str(e):
                logger.debug(f"JWT Validation skipped (Opaque Token detected): {e}")
            else:
                logger.warning(f"JWT Validation failed ({type(e).__name__}): {e}")
            pass

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
        if cached:
            cached_payload = cached[1]
            logger.warning(
                "Serving cached /userinfo claims after Auth0 error for token: %s", exc
            )
            # Extend cache since we can't refresh it right now
            stale_seconds = int(os.environ.get("AUTH0_USERINFO_STALE_ON_429_SECONDS", "300"))
            _USERINFO_CACHE[token] = (
                now + stale_seconds,
                cached_payload,
            )
            return cached_payload
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


def extract_email(payload: Dict[str, Any]) -> Optional[str]:
    """
    Safely extract email from various possible claims in the Auth0 payload.
    Looks for standard 'email' claim first, then common namespaced or fallback ones.
    """
    # 1. Standard OIDC claim
    if payload.get("email"):
        logger.debug("Identity: Extracted email from 'email' claim")
        return payload["email"]
    
    # 2. Namespaced claim often used in Auth0
    if payload.get(f"{AUTH0_NAMESPACE}/email"):
        logger.debug(f"Identity: Extracted email from '{AUTH0_NAMESPACE}/email' claim")
        return payload[f"{AUTH0_NAMESPACE}/email"]
        
    # 3. Fallbacks common in some OAuth providers
    for fallback_key in ["unique_name", "preferred_username", "nickname"]:
        val = payload.get(fallback_key)
        if val:
            if "@" in str(val):
                logger.debug(f"Identity: Extracted email from '{fallback_key}' claim")
                return str(val)
            # Handle nicknames that might be missing the domain if we have a default (e.g. backyardbrains.com)
            if fallback_key == "nickname" and not "@" in str(val):
                # Only use nickname if it's likely the prefix for an internal email
                # This is a heuristic, but common in BYB setup
                email = f"{val}@backyardbrains.com"
                logger.debug(f"Identity: Constructed email from nickname '{val}' -> {email}")
                return email

    # 4. Check 'sub' if it contains an email (google-oauth2|user@domain.com)
    sub = payload.get("sub", "")
    if "|" in sub:
        parts = sub.split("|")
        if len(parts) > 1 and "@" in parts[1]:
            logger.debug(f"Identity: Extracted email from 'sub' claim: {parts[1]}")
            return parts[1]
            
    return None


def _log_scope_claims(payload: Dict[str, Any], *, context: str) -> None:
    """Log full payload for debugging identity issues."""
    logger.info("Auth0 Full Payload for %s: %s", context, safe_dumps(payload))
    
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


def create_api_token(user_info: Dict[str, Any], permissions: list[str], scopes: list[str], expiration_days: int = 365) -> str:
    """Create a long-lived JWT API key signed with our local secret."""
    jwt_secret = os.environ.get("JWT_SECRET")
    
    
    if not jwt_secret:
        # Emergency reload of .env in case it was updated while server running
        from dotenv import load_dotenv
        from pathlib import Path
        
        env_path = Path(__file__).parent / ".env"
        # logger.warning(f"JWT_SECRET not found in env, reloading .env file from: {env_path}")
        
        load_dotenv(dotenv_path=env_path, override=True)
        jwt_secret = os.environ.get("JWT_SECRET")

    if not jwt_secret:
        # logger.error("JWT_SECRET still not configured after reload")
        raise ValueError("JWT_SECRET not configured")
        
    now = time.time()
    exp = now + (expiration_days * 24 * 60 * 60)
    
    payload = {
        "sub": user_info.get("sub", "api-key-user"),
        "email": user_info.get("email"),
        "name": user_info.get("name"),
        "permissions": permissions,
        "scope": " ".join(scopes),
        "iat": now,
        "exp": exp,
        "iss": "byb-mcp-server-apikey"
    }
    
    # Add namespaced permissions/email if needed by other tools
    if user_info.get("email"):
        payload[f"{AUTH0_NAMESPACE}/email"] = user_info["email"]
    
    return jwt.encode(payload, jwt_secret, algorithm=ALGORITHM)


async def _extract_credentials(request: Request, creds: Optional[HTTPAuthorizationCredentials]):
    # 1. Check for Bearer Header (Standard)
    if creds is not None and creds.scheme.lower() == "bearer":
        return creds.credentials
        
    # 2. Manual Header Check (Fallback)
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        return auth_header.split(" ", 1)[1].strip()

    # 3. NEW: Check Query Parameter (Required for Claude Desktop SSE)
    # Allows: https://.../sse?token=eyJ...
    token_param = request.query_params.get("token")
    if token_param:
        return token_param

    # 4. If all fail, raise 401
    logger.warning("Missing/invalid Authorization credential for %s %s", request.method, request.url.path)
    raise HTTPException(
        status_code=401,
        detail="Authorization required",
        headers={"WWW-Authenticate": "Bearer"},
    )


async def require_auth(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """Base auth - validates token via Auth0 /userinfo with no scope checking."""
    token = await _extract_credentials(request, creds)
    try:
        return await validate_opaque_token(token)
    except HTTPException as exc:
        logger.warning("Token validation failed for %s %s: %s", request.method, request.url.path, exc.detail)
        raise


async def require_xero_auth(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(security)):
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


async def require_metabase_auth(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(security)):
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

async def require_mysql_auth(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """MySQL-specific auth - requires mcp:read:mysql or mcp:write:mysql scope."""
    token = await _extract_credentials(request, creds)
    try:
        payload = await validate_opaque_token(token)
        if not check_permissions(payload, ["mcp:read:mysql", "mcp:write:mysql"]):
            logger.warning("Insufficient permissions for MySQL MCP access for %s %s", request.method, request.url.path)
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions. Required: mcp:read:mysql or mcp:write:mysql",
            )
        return payload
    except HTTPException as exc:
        if exc.status_code == 403:
            raise
        logger.warning("Token validation failed for %s %s: %s", request.method, request.url.path, exc.detail)
        raise

async def require_workshops_auth(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """Workshops-specific auth - requires mcp:read:workshops, mcp:write:workshops, or mcp:admin:workshops scope."""
    token = await _extract_credentials(request, creds)
    try:
        payload = await validate_opaque_token(token)
        allowed_scopes = ["mcp:read:workshops", "mcp:write:workshops", "mcp:admin:workshops"]
        if not check_permissions(payload, allowed_scopes):
            logger.warning("Insufficient permissions for Workshops MCP access for %s %s", request.method, request.url.path)
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions. Required one of: {allowed_scopes}",
            )
        return payload
    except HTTPException as exc:
        if exc.status_code == 403:
            raise
        logger.warning("Token validation failed for %s %s: %s", request.method, request.url.path, exc.detail)
        raise


async def require_assistant_auth(request: Request, creds: Optional[HTTPAuthorizationCredentials] = Depends(security)):
    """Assistant-specific auth - requires mcp:read:assistant or mcp:write:assistant scope."""
    token = await _extract_credentials(request, creds)
    try:
        payload = await validate_opaque_token(token)
        allowed_scopes = ["mcp:read:assistant", "mcp:write:assistant"]
        if not check_permissions(payload, allowed_scopes):
            logger.warning("Insufficient permissions for Assistant MCP access for %s %s", request.method, request.url.path)
            raise HTTPException(
                status_code=403,
                detail=f"Insufficient permissions. Required one of: {allowed_scopes}",
            )
        return payload
    except HTTPException as exc:
        if exc.status_code == 403:
            raise
        logger.warning("Token validation failed for %s %s: %s", request.method, request.url.path, exc.detail)
        raise
