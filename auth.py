import os
import requests
from typing import Optional, Dict, Any
from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, JWTError

from utils import logger

# Auth0 configuration
AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")
AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE")
AUTH0_XERO_AUDIENCE = os.environ.get("AUTH0_XERO_AUDIENCE", "https://mcp.backyardbrains.com/xero")
AUTH0_METABASE_AUDIENCE = os.environ.get("AUTH0_METABASE_AUDIENCE", "https://mcp.backyardbrains.com/metabase")
AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID")
AUTH0_JWKS_URL = os.environ.get("AUTH0_JWKS_URL")
AUTH0_ISSUER = f"https://{AUTH0_DOMAIN}/" if AUTH0_DOMAIN else None

# Use explicit JWKS URL if provided, otherwise construct from domain
JWKS_URL = AUTH0_JWKS_URL or (f"{AUTH0_ISSUER}.well-known/jwks.json" if AUTH0_ISSUER else None)
ALGORITHMS = ["RS256"]

security = HTTPBearer(auto_error=False)
_jwks_cache = None


def _validate_jwt_format(token: str, *, context: str) -> None:
    """Basic structural validation before decoding a JWT."""
    logger.warning("FULL TOKEN RECEIVED: %s", token[:100])
    parts = token.split(".")
    if len(parts) != 3:
        logger.warning(
            "Malformed bearer token for %s: expected 3 segments, got %s", context, len(parts)
        )
        raise HTTPException(
            status_code=401,
            detail=(
                "Invalid token format: expected a JWT access token issued by Auth0. "
                "Make sure your MCP client is sending the access token from the /auth/token flow, "
                "not the client secret or some other value."
            ),
        )

def get_jwks(force_refresh: bool = False):
    """Fetch JWKS, optionally bypassing the cache when keys rotate."""
    global _jwks_cache

    if JWKS_URL is None:
        raise HTTPException(status_code=500, detail="Auth not configured")

    if _jwks_cache is None or force_refresh:
        try:
            resp = requests.get(JWKS_URL, timeout=5)
            resp.raise_for_status()
            _jwks_cache = resp.json()
            logger.info("JWKS fetched%s", " (force refresh)" if force_refresh else "")
        except Exception as e:
            logger.error(f"Failed to fetch JWKS: {e}")
            raise HTTPException(status_code=500, detail="Failed to fetch JWKS")
    return _jwks_cache

def _gather_audiences(explicit_audiences: Optional[list[str]] = None) -> list[str]:
    """Return unique, non-empty audiences to try when validating tokens."""
    audiences = []
    if explicit_audiences:
        audiences.extend([aud for aud in explicit_audiences if aud])
    else:
        audiences.extend([
            AUTH0_XERO_AUDIENCE,
            AUTH0_METABASE_AUDIENCE,
            AUTH0_AUDIENCE,  # Legacy fallback
        ])
    # Preserve order while removing duplicates/empties
    seen = set()
    unique_audiences = []
    for aud in audiences:
        if aud and aud not in seen:
            seen.add(aud)
            unique_audiences.append(aud)
    return unique_audiences

def _find_rsa_key(token: str, *, refresh_on_miss: bool = True) -> Dict[str, Any]:
    """Locate RSA key for the token's kid, refreshing JWKS on cache misses."""
    jwks = get_jwks(force_refresh=False)
    unverified_header = jwt.get_unverified_header(token)

    def _match_key(jwks_payload):
        for key in jwks_payload.get("keys", []):
            if key.get("kid") == unverified_header.get("kid"):
                return {
                    "kty": key.get("kty"),
                    "kid": key.get("kid"),
                    "use": key.get("use"),
                    "n": key.get("n"),
                    "e": key.get("e"),
                }
        return None

    rsa_key = _match_key(jwks)
    if not rsa_key and refresh_on_miss:
        # Key rotation or stale cache — refresh once and try again
        jwks = get_jwks(force_refresh=True)
        rsa_key = _match_key(jwks)

    return rsa_key or {}


def verify_jwt(token: str, audiences: Optional[list[str]] = None):
    try:
        rsa_key = _find_rsa_key(token)
        if not rsa_key:
            unverified_header = jwt.get_unverified_header(token)
            kid_hint = unverified_header.get("kid") if isinstance(unverified_header, dict) else None
            raise HTTPException(
                status_code=401,
                detail=(
                    "Invalid token: signing key not found. "
                    f"Received kid={kid_hint!r}; ensure the token is issued by {AUTH0_DOMAIN} "
                    "for the configured audience."
                ),
            )
        
        last_error = None
        
        # Try validating with configured audiences
        for audience in _gather_audiences(audiences):
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=audience,
                    issuer=AUTH0_ISSUER,
                    options={"verify_at_hash": False}
                )
                return payload
            except JWTError as e:
                logger.warning("JWT decode with audience %s failed: %s", audience, e)
                last_error = e
        
        # Try validating with Client ID (sometimes used as audience)
        if AUTH0_CLIENT_ID:
            try:
                payload = jwt.decode(
                    token,
                    rsa_key,
                    algorithms=ALGORITHMS,
                    audience=AUTH0_CLIENT_ID,
                    issuer=AUTH0_ISSUER,
                    options={"verify_at_hash": False}
                )
                return payload
            except JWTError as e:
                last_error = e
        
        # Fallback: Validate issuer but ignore audience (if configured to be lenient, or check azp)
        # For stricter security, we should probably enforce audience, but existing code had this fallback.
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                issuer=AUTH0_ISSUER,
                options={"verify_aud": False, "verify_at_hash": False}
            )
            if AUTH0_CLIENT_ID and payload.get("azp") == AUTH0_CLIENT_ID:
                return payload
        except JWTError as e:
            last_error = e
            
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(last_error) if last_error else 'audience mismatch'}")
    except JWTError as e:
        logger.warning("JWT decode failed: %s", e)
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token validation error: {str(e)}")

def check_permissions(payload: Dict[str, Any], required_scopes: list[str]) -> bool:
    """
    Check if the JWT payload contains at least one of the required scopes.
    Scopes can be in 'scope' (space-separated string) or 'permissions' (list).
    """
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
    permissions = payload.get("permissions")
    scope_string = payload.get("scope")
    logger.info(
        "Auth0 claims for %s: permissions=%s scope=%s",
        context,
        permissions if permissions is not None else "<missing>",
        scope_string if scope_string is not None else "<missing>",
    )

def require_auth(request: Request, creds: HTTPAuthorizationCredentials = Depends(security)):
    """Base auth - just validates JWT, no scope checking"""
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
    try:
        return verify_jwt(creds.credentials)
    except HTTPException as exc:
        logger.warning("JWT validation failed for %s %s: %s", request.method, request.url.path, exc.detail)
        raise

def require_xero_auth(request: Request, creds: HTTPAuthorizationCredentials = Depends(security)):
    """Xero-specific auth - requires mcp:read:xero or mcp:write:xero scope"""
    if creds is None or creds.scheme.lower() != "bearer":
        logger.warning("Missing/invalid Authorization header for %s %s", request.method, request.url.path)
        raise HTTPException(
            status_code=401,
            detail="Authorization required",
            headers={
                "WWW-Authenticate": (
                    'Bearer '
                    'resource_metadata="https://mcp.backyardbrains.com/.well-known/oauth-protected-resource/xero", '
                    'scope="mcp:read:xero mcp:write:xero"'
                )
            },
        )
    try:
        _validate_jwt_format(creds.credentials, context=f"{request.method} {request.url.path}")
        try:
            unverified_claims = jwt.get_unverified_claims(creds.credentials)
            _log_scope_claims(unverified_claims, context="Xero request (unverified)")
        except JWTError as e:
            logger.warning("Unable to parse unverified claims for %s %s: %s", request.method, request.url.path, e)
            raise HTTPException(
                status_code=401,
                detail=(
                    "Invalid token format: unable to parse claims. "
                    "Ensure you are sending the Auth0-issued access token for the Xero MCP audience "
                    "(not the client secret or a partial token)."
                ),
            )

        payload = verify_jwt(creds.credentials, audiences=[AUTH0_XERO_AUDIENCE])
        _log_scope_claims(payload, context="Xero request")
        if not check_permissions(payload, ["mcp:read:xero", "mcp:write:xero"]):
            logger.warning("Insufficient permissions for Xero MCP access for %s %s", request.method, request.url.path)
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions. Required: mcp:read:xero or mcp:write:xero"
            )
        return payload
    except HTTPException as exc:
        if exc.status_code == 403:
            raise
        logger.warning("JWT validation failed for %s %s: %s", request.method, request.url.path, exc.detail)
        raise

def require_metabase_auth(request: Request, creds: HTTPAuthorizationCredentials = Depends(security)):
    """Metabase-specific auth - requires mcp:read:metabase or mcp:write:metabase scope"""
    if creds is None or creds.scheme.lower() != "bearer":
        logger.warning("Missing/invalid Authorization header for %s %s", request.method, request.url.path)
        raise HTTPException(
            status_code=401,
            detail="Authorization required",
            headers={
                "WWW-Authenticate": (
                    'Bearer '
                    'resource_metadata="https://mcp.backyardbrains.com/.well-known/oauth-protected-resource/metabase", '
                    'scope="mcp:read:metabase mcp:write:metabase"'
                )
            },
        )
    try:
        _validate_jwt_format(creds.credentials, context=f"{request.method} {request.url.path}")
        try:
            unverified_claims = jwt.get_unverified_claims(creds.credentials)
            _log_scope_claims(unverified_claims, context="Metabase request (unverified)")
        except JWTError as e:
            logger.warning("Unable to parse unverified claims for %s %s: %s", request.method, request.url.path, e)
            raise HTTPException(
                status_code=401,
                detail=(
                    "Invalid token format: unable to parse claims. "
                    "Ensure you are sending the Auth0-issued access token for the Metabase MCP audience."
                ),
            )

        payload = verify_jwt(creds.credentials, audiences=[AUTH0_METABASE_AUDIENCE])
        _log_scope_claims(payload, context="Metabase request")
        if not check_permissions(payload, ["mcp:read:metabase", "mcp:write:metabase"]):
            logger.warning("Insufficient permissions for Metabase MCP access for %s %s", request.method, request.url.path)
            raise HTTPException(
                status_code=403,
                detail="Insufficient permissions. Required: mcp:read:metabase or mcp:write:metabase"
            )
        return payload
    except HTTPException as exc:
        if exc.status_code == 403:
            raise
        logger.warning("JWT validation failed for %s %s: %s", request.method, request.url.path, exc.detail)
        raise
