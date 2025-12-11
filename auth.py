import base64
import json
import os
import time
import requests
from typing import Optional, Dict, Any
from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import jwt, jwe, JWTError

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


def _client_secret_key(raw_secret: str) -> bytes:
    """Return a 256-bit key from the Auth0 client secret.

    Auth0 client secrets for Symmetric Encryption use base64url encoding to
    represent 256-bit keys. If the provided secret is already 32 bytes, use it
    directly; otherwise attempt base64url decoding and validate the length.
    """

    secret_bytes = raw_secret.encode()
    if len(secret_bytes) == 32:
        return secret_bytes

    try:
        # Add padding so urlsafe_b64decode can accept unpadded secrets
        padded = raw_secret + "=" * (-len(raw_secret) % 4)
        decoded = base64.urlsafe_b64decode(padded)
    except Exception as exc:  # pragma: no cover - defensive guard
        logger.warning("Failed to base64url-decode AUTH0_CLIENT_SECRET: %s", exc)
        raise HTTPException(status_code=401, detail="Invalid token: decrypt failed")

    if len(decoded) != 32:
        logger.warning(
            "Invalid AUTH0_CLIENT_SECRET length: %s bytes after decoding; expected 32",
            len(decoded),
        )
        raise HTTPException(status_code=401, detail="Invalid token: decrypt failed")

    return decoded

def get_jwks():
    global _jwks_cache
    if _jwks_cache is None:
        if not JWKS_URL:
            raise HTTPException(status_code=500, detail="Auth not configured")
        try:
            resp = requests.get(JWKS_URL, timeout=5)
            resp.raise_for_status()
            _jwks_cache = resp.json()
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

def verify_jwt(token: str, audiences: Optional[list[str]] = None):
    try:
        jwks = get_jwks()
        unverified_header = jwt.get_unverified_header(token)

        # Handle encrypted (JWE) tokens that use symmetric "dir" algorithm.
        # ChatGPT may request tokens encrypted with the client secret instead of signed with a JWKS key.
        if unverified_header.get("alg") == "dir" and unverified_header.get("enc"):
            client_secret = os.environ.get("AUTH0_CLIENT_SECRET")
            if not client_secret:
                logger.error("Received encrypted token but AUTH0_CLIENT_SECRET is not configured")
                raise HTTPException(status_code=401, detail="Invalid token: encryption key unavailable")

            try:
                decrypted_bytes = jwe.decrypt(token, _client_secret_key(client_secret))
                payload = json.loads(decrypted_bytes)
            except Exception as e:
                logger.warning("Failed to decrypt encrypted token: %s", e)
                raise HTTPException(status_code=401, detail="Invalid token: decrypt failed")

            # Validate minimal claims for decrypted tokens
            if AUTH0_ISSUER and payload.get("iss") != AUTH0_ISSUER:
                raise HTTPException(status_code=401, detail="Invalid token: issuer mismatch")

            aud_claim = payload.get("aud")
            valid_audiences = _gather_audiences(audiences)
            if aud_claim:
                if isinstance(aud_claim, str):
                    aud_claims = [aud_claim]
                else:
                    aud_claims = list(aud_claim)
                if not any(aud in valid_audiences for aud in aud_claims):
                    raise HTTPException(status_code=401, detail="Invalid token: audience mismatch")
            elif valid_audiences:
                raise HTTPException(status_code=401, detail="Invalid token: audience missing")

            exp = payload.get("exp")
            if exp and time.time() > exp:
                raise HTTPException(status_code=401, detail="Invalid token: token expired")

            return payload

        rsa_key = {}
        for key in jwks.get("keys", []):
            if key.get("kid") == unverified_header.get("kid"):
                rsa_key = {
                    "kty": key.get("kty"),
                    "kid": key.get("kid"),
                    "use": key.get("use"),
                    "n": key.get("n"),
                    "e": key.get("e"),
                }
                break
        if not rsa_key:
            # Debug logging for "key not found"
            available_kids = [k.get("kid") for k in jwks.get("keys", [])]
            logger.error(
                f"JWT Key Not Found. Token Header: {unverified_header}. "
                f"Available KIDs in JWKS: {available_kids}. "
                f"JWKS URL: {JWKS_URL}"
            )
            raise HTTPException(status_code=401, detail="Invalid token: key not found")
        
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
        payload = verify_jwt(creds.credentials, audiences=[AUTH0_XERO_AUDIENCE])
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
        payload = verify_jwt(creds.credentials, audiences=[AUTH0_METABASE_AUDIENCE])
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
