import os
import logging
import uvicorn
import requests
import secrets
from urllib.parse import urlencode
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware.sessions import SessionMiddleware

# Load environment variables
load_dotenv()

from utils import logger, MCP_PROTOCOL_VERSION
from auth import AUTH0_AUDIENCE, AUTH0_XERO_AUDIENCE, AUTH0_METABASE_AUDIENCE
import xero_mcp
import metabase_mcp

# Initialize FastAPI app
app = FastAPI(title="BYB Xero & Metabase MCP Server", version="1.0.0")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Session middleware for OAuth flow
app.add_middleware(
    SessionMiddleware,
    secret_key=os.environ.get("TOKEN_ENC_KEY", secrets.token_urlsafe(32))
)

# Request Logging Middleware
class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        logger.info(f"Incoming request: {request.method} {request.url}")
        try:
            response = await call_next(request)
            logger.info(f"Request completed: {response.status_code}")
            return response
        except Exception as e:
            logger.error(f"Request failed: {e}")
            raise

app.add_middleware(RequestLoggingMiddleware)

# Mount Routers
app.include_router(xero_mcp.router, prefix="/xero", tags=["xero"])
app.include_router(metabase_mcp.router, prefix="/metabase", tags=["metabase"])

# Serve static files (for token generation page)
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")


@app.get("/")
async def root():
    """Simple landing endpoint that points to the token generation page."""
    return RedirectResponse(url="/auth/token", status_code=307)

# Audience helpers
def _default_audience():
    """Choose the primary audience to use for the combined landing endpoints."""
    return AUTH0_XERO_AUDIENCE or AUTH0_METABASE_AUDIENCE or AUTH0_AUDIENCE

# Global MCP Manifest
@app.get("/.well-known/mcp.json")
async def mcp_manifest():
    """
    Combined MCP manifest for both Xero and Metabase.
    """
    # Get tools from both modules
    xero_tools = xero_mcp._list_tools_payload().get("tools", [])
    metabase_tools = metabase_mcp._list_metabase_tools().get("tools", [])

    # Get resources from Metabase (Xero doesn't have resources in this implementation yet)
    metabase_resources = metabase_mcp._list_metabase_resources().get("resources", [])

    return {
        "mcpVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": {
                "listChanged": False
            },
            "resources": {
                "listChanged": False,
                "subscribe": False
            },
            "prompts": {
                "listChanged": False
            },
            "logging": {}
        },
        "serverInfo": {
            "name": "xero-metabase-mcp",
            "version": "1.0.0"
        }
    }

# OAuth 2.0 Authorization Server Metadata (RFC 8414)
@app.get("/.well-known/oauth-authorization-server")
@app.get("/.well-known/oauth-authorization-server/xero")
@app.get("/.well-known/oauth-authorization-server/metabase")
async def oauth_authorization_server(request: Request):
    """
    OAuth 2.0 Authorization Server Metadata endpoint.
    Points to Auth0 as the authorization server.
    """
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    if not auth0_domain:
        return Response(status_code=404)
    
    base_url = f"https://{auth0_domain}"
    
    return {
        "issuer": f"{base_url}/",
        "authorization_endpoint": f"{base_url}/authorize",
        "token_endpoint": f"{base_url}/oauth/token",
        "userinfo_endpoint": f"{base_url}/userinfo",
        "jwks_uri": f"{base_url}/.well-known/jwks.json",
        "registration_endpoint": f"{base_url}/oidc/register",
        "scopes_supported": [
            "openid",
            "profile",
            "email",
            "mcp:read",
            "mcp:write",
            "mcp:read:xero",
            "mcp:write:xero",
            "mcp:read:metabase",
            "mcp:write:metabase"
        ],
        "response_types_supported": [
            "code",
            "token",
            "id_token",
            "code token",
            "code id_token",
            "token id_token",
            "code token id_token"
        ],
        "grant_types_supported": [
            "authorization_code",
            "implicit",
            "client_credentials",
            "refresh_token"
        ],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post"
        ]
    }

# OAuth 2.0 Protected Resource Metadata (RFC 9470)
@app.get("/.well-known/oauth-protected-resource")
async def oauth_protected_resource_root():
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    audience = _default_audience()
    if not auth0_domain or not audience:
        return Response(status_code=404)
    
    return {
        "resource": audience,
        "authorization_servers": [f"https://{auth0_domain}/"],
        "scopes_supported": ["mcp:read:xero", "mcp:write:xero",
            "mcp:read:metabase", "mcp:write:metabase"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": "https://mcp.backyardbrains.com/static/get-token.html",
    }

@app.get("/.well-known/oauth-protected-resource/xero")
async def oauth_protected_resource_xero():
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    audience = AUTH0_XERO_AUDIENCE or _default_audience()
    if not auth0_domain or not audience:
        return Response(status_code=404)

    return {
        "resource": audience,  # <— USE THE SAME IDENTIFIER
        "authorization_servers": [f"https://{auth0_domain}/"],
        "scopes_supported": ["mcp:read:xero", "mcp:write:xero"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": "https://mcp.backyardbrains.com/static/get-token.html",
    }

@app.get("/.well-known/oauth-protected-resource/metabase")
async def oauth_protected_resource_metabase():
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    audience = AUTH0_METABASE_AUDIENCE or _default_audience()
    if not auth0_domain or not audience:
        return Response(status_code=404)

    return {
        "resource": audience,  # <— SAME HERE
        "authorization_servers": [f"https://{auth0_domain}/"],
        "scopes_supported": ["mcp:read:metabase", "mcp:write:metabase"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": "https://mcp.backyardbrains.com/static/get-token.html",
    }

# Auth0 OIDC Discovery Passthrough (for Xero auth flow mostly)
@app.get("/.well-known/openid-configuration")
async def openid_configuration():
    # Proxy to Auth0
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    if not auth0_domain:
        return Response(status_code=404)
    
    resp = requests.get(f"https://{auth0_domain}/.well-known/openid-configuration")
    return Response(content=resp.content, media_type="application/json", status_code=resp.status_code)

@app.get("/.well-known/jwks.json")
async def jwks_json():
    # Proxy to Auth0
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    if not auth0_domain:
        return Response(status_code=404)
    
    resp = requests.get(f"https://{auth0_domain}/.well-known/jwks.json")
    return Response(content=resp.content, media_type="application/json", status_code=resp.status_code)

# OAuth Token Generation Endpoints
@app.get("/auth/token", response_class=HTMLResponse)
async def get_token_page(request: Request):
    """Redirect to static token generation page with API selector."""
    return RedirectResponse(url="/static/get-token.html", status_code=307)

@app.get("/auth/login")
async def auth_login(request: Request):
    """Initiate OAuth login flow."""
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    client_id = os.environ.get("AUTH0_CLIENT_ID")
    audience = _default_audience()
    
    if not all([auth0_domain, client_id, audience]):
        raise HTTPException(status_code=500, detail="Auth0 not configured")
    
    # Generate state for CSRF protection
    state = secrets.token_urlsafe(32)
    request.session["oauth_state"] = state
    
    # Build authorization URL
    base_url = request.url_for("root")
    redirect_uri = f"{base_url.scheme}://{base_url.netloc}/auth/callback"
    
    params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": "openid profile email mcp:read:xero mcp:write:xero mcp:read:metabase mcp:write:metabase",
        "audience": audience,
        "state": state
    }
    
    auth_url = f"https://{auth0_domain}/authorize?{urlencode(params)}"
    return RedirectResponse(url=auth_url)

@app.get("/auth/callback")
async def auth_callback(request: Request, code: str = None, state: str = None, error: str = None):
    """Handle OAuth callback and exchange code for token."""
    if error:
        raise HTTPException(status_code=400, detail=f"Auth error: {error}")
    
    if not code:
        raise HTTPException(status_code=400, detail="No authorization code provided")
    
    # Verify state for CSRF protection
    stored_state = request.session.get("oauth_state")
    if not stored_state or stored_state != state:
        raise HTTPException(status_code=400, detail="Invalid state parameter")
    
    # Exchange code for token
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    client_id = os.environ.get("AUTH0_CLIENT_ID")
    client_secret = os.environ.get("AUTH0_CLIENT_SECRET")
    
    if not all([auth0_domain, client_id, client_secret]):
        raise HTTPException(status_code=500, detail="Auth0 not configured")
    
    base_url = request.url_for("root")
    redirect_uri = f"{base_url.scheme}://{base_url.netloc}/auth/callback"
    
    token_url = f"https://{auth0_domain}/oauth/token"
    token_data = {
        "grant_type": "authorization_code",
        "client_id": client_id,
        "client_secret": client_secret,
        "code": code,
        "redirect_uri": redirect_uri
    }
    
    try:
        response = requests.post(token_url, json=token_data, timeout=10)
        response.raise_for_status()
        token_response = response.json()
        
        access_token = token_response.get("access_token")
        if not access_token:
            raise HTTPException(status_code=500, detail="No access token in response")
        
        # Get user info
        userinfo_url = f"https://{auth0_domain}/userinfo"
        headers = {"Authorization": f"Bearer {access_token}"}
        user_response = requests.get(userinfo_url, headers=headers, timeout=10)
        user_response.raise_for_status()
        user_info = user_response.json()
        
        # Store token and user info in session
        request.session["access_token"] = access_token
        request.session["user_info"] = user_info
        request.session.pop("oauth_state", None)
        
        # Redirect to token display page
        return RedirectResponse(url="/auth/token", status_code=303)
        
    except requests.RequestException as e:
        logger.error(f"Token exchange failed: {e}")
        raise HTTPException(status_code=500, detail=f"Token exchange failed: {str(e)}")

@app.get("/auth/logout")
async def auth_logout(request: Request):
    """Logout and clear session."""
    request.session.clear()
    return RedirectResponse(url="/auth/token", status_code=303)

# Health Check
@app.get("/health")
def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)