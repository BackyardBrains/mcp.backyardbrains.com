import os
import logging
import uvicorn
import httpx
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
from auth import AUTH0_XERO_AUDIENCE, AUTH0_METABASE_AUDIENCE, AUTH0_META_AUDIENCE, create_api_token, validate_opaque_token
import auth
import xero_mcp
import metabase_mcp
import meta_mcp
import workshops_mcp
import assistant_mcp

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

app.include_router(xero_mcp.router, prefix="/xero", tags=["xero"])
app.include_router(metabase_mcp.router, prefix="/metabase", tags=["metabase"])
app.include_router(workshops_mcp.router, prefix="/workshops", tags=["workshops"])
app.include_router(assistant_mcp.router, prefix="/assistant", tags=["assistant"])
app.include_router(meta_mcp.router, prefix="", tags=["meta"])

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
    return AUTH0_XERO_AUDIENCE or AUTH0_METABASE_AUDIENCE or AUTH0_META_AUDIENCE or getattr(auth, "AUTH0_WORKSHOPS_AUDIENCE", None) or getattr(auth, "AUTH0_ASSISTANT_AUDIENCE", None)

from auth import AUTH0_WORKSHOPS_AUDIENCE, AUTH0_ASSISTANT_AUDIENCE

# Global MCP Manifest
@app.get("/.well-known/mcp.json")
async def mcp_manifest():
    """
    Combined MCP manifest for all MCP modules.
    """
    # Get tools from all modules
    xero_tools = xero_mcp._list_tools_payload().get("tools", [])
    metabase_tools = metabase_mcp._list_metabase_tools().get("tools", [])
    workshop_tools = workshops_mcp._list_workshop_tools().get("tools", [])
    assistant_tools = assistant_mcp._list_assistant_tools().get("tools", [])

    # Get resources from Metabase
    metabase_resources = metabase_mcp._list_metabase_resources().get("resources", [])

    return {
        "mcpVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": {
                "listChanged": False,
                "tools": xero_tools + metabase_tools + workshop_tools + assistant_tools
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
            "name": "byb-mcp-server",
            "version": "1.0.0"
        }
    }


# OAuth 2.0 Authorization Server Metadata (RFC 8414)
@app.get("/.well-known/oauth-authorization-server")
@app.get("/.well-known/oauth-authorization-server/xero")
@app.get("/.well-known/oauth-authorization-server/metabase")
@app.get("/.well-known/oauth-authorization-server/meta")
@app.get("/.well-known/oauth-authorization-server/workshops")
@app.get("/.well-known/oauth-authorization-server/assistant")
async def oauth_authorization_server(request: Request, api: str = "xero"):
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
            "mcp:write:metabase",
            "mcp:read:workshops",
            "mcp:write:workshops",
            "mcp:admin:workshops",
            "mcp:read:assistant",
            "mcp:write:assistant"
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
            "mcp:read:metabase", "mcp:write:metabase",
            "mcp:read:workshops", "mcp:write:workshops", "mcp:admin:workshops",
            "mcp:read:assistant", "mcp:write:assistant"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": "https://mcp.backyardbrains.com/static/get-token.html",
    }

@app.get("/.well-known/oauth-protected-resource/xero{subpath:path}")
async def oauth_protected_resource_xero(subpath: str = ""):
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    audience = AUTH0_XERO_AUDIENCE or _default_audience()
    if not auth0_domain or not audience:
        return Response(status_code=404)
        
    return {
        "resource": audience, # <— USE THE SAME IDENTIFIER
        "authorization_servers": [f"https://{auth0_domain}/"],
        "scopes_supported": ["mcp:read:xero", "mcp:write:xero"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": "https://mcp.backyardbrains.com/static/get-token.html?api=xero",
    }

@app.get("/.well-known/oauth-protected-resource/metabase{subpath:path}")
async def oauth_protected_resource_metabase(subpath: str = ""):
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    audience = AUTH0_METABASE_AUDIENCE or _default_audience()
    if not auth0_domain or not audience:
        return Response(status_code=404)
        
    return {
        "resource": audience, # <— SAME HERE
        "authorization_servers": [f"https://{auth0_domain}/"],
        "scopes_supported": ["mcp:read:metabase", "mcp:write:metabase"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": "https://mcp.backyardbrains.com/static/get-token.html?api=metabase",
    }

@app.get("/.well-known/oauth-protected-resource/meta{subpath:path}")
async def oauth_protected_resource_meta(subpath: str = ""):
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    audience = AUTH0_META_AUDIENCE or _default_audience()
    if not auth0_domain or not audience:
        return Response(status_code=404)
        
    return {
        "resource": audience,
        "authorization_servers": [f"https://{auth0_domain}/"],
        "scopes_supported": ["mcp:read:meta", "mcp:write:meta"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": "https://mcp.backyardbrains.com/static/get-token.html?api=meta",
    }

@app.get("/.well-known/oauth-protected-resource/workshops{subpath:path}")
async def oauth_protected_resource_workshops(subpath: str = ""):
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    audience = AUTH0_WORKSHOPS_AUDIENCE or _default_audience()
    if not auth0_domain or not audience:
        return Response(status_code=404)
        
    return {
        "resource": audience,
        "authorization_servers": [f"https://{auth0_domain}/"],
        "scopes_supported": ["mcp:read:workshops", "mcp:write:workshops", "mcp:admin:workshops"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": "https://mcp.backyardbrains.com/static/get-token.html?api=workshops",
    }

@app.get("/.well-known/oauth-protected-resource/assistant{subpath:path}")
async def oauth_protected_resource_assistant(subpath: str = ""):
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    audience = AUTH0_ASSISTANT_AUDIENCE or _default_audience()
    if not auth0_domain or not audience:
        return Response(status_code=404)
        
    return {
        "resource": audience,
        "authorization_servers": [f"https://{auth0_domain}/"],
        "scopes_supported": ["mcp:read:assistant", "mcp:write:assistant"],
        "bearer_methods_supported": ["header"],
        "resource_documentation": "https://mcp.backyardbrains.com/static/get-token.html?api=assistant",
    }

# Auth0 OIDC Discovery Passthrough (for Xero auth flow mostly)
@app.get("/.well-known/openid-configuration")
async def openid_configuration():
    # Proxy to Auth0
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    if not auth0_domain:
        return Response(status_code=404)
    
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"https://{auth0_domain}/.well-known/openid-configuration")
    return Response(content=resp.content, media_type="application/json", status_code=resp.status_code)

@app.get("/.well-known/jwks.json")
async def jwks_json():
    # Proxy to Auth0
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    if not auth0_domain:
        return Response(status_code=404)
    
    async with httpx.AsyncClient() as client:
        resp = await client.get(f"https://{auth0_domain}/.well-known/jwks.json")
    return Response(content=resp.content, media_type="application/json", status_code=resp.status_code)

# OAuth Token Generation Endpoints
# API Key Generation Endpoint
@app.post("/auth/create-api-key")
async def create_api_key_endpoint(request: Request):
    token = request.session.get("access_token")
    user_info = request.session.get("user_info")
    
    if not token or not user_info:
        raise HTTPException(status_code=401, detail="Not logged in")

    # validate_opaque_token to get full claims (permissions, etc.) from Auth0
    # We re-fetch this to ensure we are baking in the current permissions
    try:
        full_payload = await validate_opaque_token(token)
    except HTTPException:
        # Token might be expired
        raise HTTPException(status_code=401, detail="Session expired, please log in again")

    permissions = full_payload.get("permissions", [])
    scope_string = full_payload.get("scope", "")
    scopes = scope_string.split() if scope_string else []
    
    # Merge namespaced permissions
    namespaced = full_payload.get(f"{auth.AUTH0_NAMESPACE}/permissions", [])
    if namespaced:
        permissions.extend(namespaced)
        permissions = list(set(permissions))

    try:
        api_key = create_api_token(full_payload, permissions, scopes, expiration_days=365)
        return {"api_key": api_key}
    except ValueError as e:
         raise HTTPException(status_code=500, detail=str(e))


@app.get("/auth/token", response_class=HTMLResponse)
async def get_token_page(request: Request):
    """Display token generation page with API selector and login button."""
    token = request.session.get("access_token")
    user_info = request.session.get("user_info")
    
    logger.info(f"Token Page: Session keys: {list(request.session.keys())}")
    token = request.session.get("access_token")
    user_info = request.session.get("user_info")
    logger.info(f"Token Page: Found token: {bool(token)}, Found user_info: {bool(user_info)}")
    
    if token and user_info:
        # Parse token to show permissions
        import base64
        import json
        try:
            token_parts = token.split('.')
            payload = json.loads(base64.urlsafe_b64decode(token_parts[1] + '=='))
            permissions = payload.get('permissions', [])
            scopes = payload.get('scope', '').split() if payload.get('scope') else []
            all_perms = list(set(permissions + scopes))
            mcp_perms = [p for p in all_perms if p.startswith('mcp:')]
        except:
            mcp_perms = []
        
        html = f"""
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <title>Backyard Brains | MCP Token</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <link rel="preconnect" href="https://fonts.googleapis.com">
            <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
            <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
            <style>
                /* ==========================================================================
                   BYB Design System - CSS Variables
                   ========================================================================== */
                :root {{
                    /* COLORS */
                    --byb-color-dark: #000000;
                    --byb-color-orange: #ff805f;
                    --byb-color-purpure: #FFD90F;
                    --byb-color-white: #ffffff;
                    
                    /* Support */
                    --byb-color-hover-orange: #f07859;
                    --byb-color-tinted-orange: #ffcdbf;
                    --byb-color-very-light-tinted-orange: #fff5f2;
                    
                    /* Grey Scale */
                    --byb-color-grey-text: #707070;
                    --byb-color-grey: #dbdbdb;
                    --byb-color-grey-divider: #e9e9e9;
                    --byb-color-grey-bg: #eeeeee;
                    --byb-color-grey-bg-light: #f5f5f5;
                    
                    /* Helper/Semantic */
                    --byb-color-success: #00aa4f;
                    --byb-color-success-bg: #c8ebd8;
                    --byb-color-info-bg: #FFF4B8;
                    --byb-color-info-border: #FFD90F;
                    --byb-color-info-text: #854d0e;

                    /* TYPOGRAPHY */
                    --byb-font-display: 'Boldoa Mat', 'Impact', sans-serif;
                    --byb-font-body: 'Roboto', -apple-system, BlinkMacSystemFont, sans-serif;
                    
                    --byb-font-weight-regular: 400;
                    --byb-font-weight-medium: 500;
                    --byb-font-weight-bold: 700;

                    /* SPACING */
                    --byb-space-1: 4px;
                    --byb-space-2: 8px;
                    --byb-space-3: 12px;
                    --byb-space-4: 16px;
                    --byb-space-6: 24px;
                    --byb-space-8: 32px;
                    
                    /* BORDERS */
                    --byb-border-radius-md: 4px;
                    --byb-border-radius-lg: 6px;
                    --byb-border-radius-full: 999px;
                    
                    /* SHADOWS */
                    --byb-shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.05);
                    --byb-shadow-md: 0 4px 6px rgba(0, 0, 0, 0.1);
                    --byb-shadow-lg: 0 10px 15px rgba(0, 0, 0, 0.1);
                    
                    /* ANIMATION */
                    --byb-duration-fast: 100ms;
                    --byb-ease-default: cubic-bezier(0.4, 0, 0.2, 1);
                }}

                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                
                body {{
                    font-family: var(--byb-font-body);
                    background-color: var(--byb-color-grey-bg);
                    color: var(--byb-color-dark);
                    min-height: 100vh;
                    display: flex;
                    flex-direction: column;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                    -webkit-font-smoothing: antialiased;
                }}

                .container {{
                    background: var(--byb-color-white);
                    border-radius: var(--byb-border-radius-lg);
                    box-shadow: var(--byb-shadow-lg);
                    max-width: 600px;
                    width: 100%;
                    padding: 48px;
                    text-align: center;
                }}

                h1 {{ 
                    font-family: var(--byb-font-body);
                    font-weight: var(--byb-font-weight-bold);
                    color: var(--byb-color-dark);
                    margin-bottom: var(--byb-space-2);
                    font-size: 24px;
                }}
                
                .subtitle {{
                    font-family: var(--byb-font-body);
                    color: var(--byb-color-grey-text);
                    margin-bottom: var(--byb-space-6);
                    font-size: 16px;
                }}

                .user-badge {{
                    display: inline-flex;
                    align-items: center;
                    background-color: var(--byb-color-very-light-tinted-orange);
                    color: var(--byb-color-orange);
                    padding: 8px 16px;
                    border-radius: var(--byb-border-radius-full);
                    font-size: 14px;
                    font-weight: var(--byb-font-weight-medium);
                    margin-bottom: var(--byb-space-8);
                }}

                /* Section Label */
                .section-label {{
                    text-align: left;
                    font-size: 12px;
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                    color: var(--byb-color-grey-text);
                    margin-bottom: var(--byb-space-2);
                    font-weight: var(--byb-font-weight-bold);
                }}

                /* Token Display */
                .token-display {{
                    background-color: var(--byb-color-grey-bg-light);
                    border: 1px solid var(--byb-color-grey);
                    border-radius: var(--byb-border-radius-md);
                    padding: var(--byb-space-4);
                    margin-bottom: var(--byb-space-6);
                    font-family: 'Roboto Mono', monospace;
                    font-size: 13px;
                    color: var(--byb-color-dark);
                    word-break: break-all;
                    text-align: left;
                    max-height: 150px;
                    overflow-y: auto;
                    line-height: 1.5;
                }}

                /* Action Buttons */
                .btn-row {{
                    display: flex;
                    gap: var(--byb-space-3);
                    margin-bottom: var(--byb-space-6);
                    flex-wrap: wrap;
                }}

                .byb-btn {{
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                    height: 48px;
                    padding: 0 24px;
                    border-radius: var(--byb-border-radius-lg);
                    font-family: var(--byb-font-body);
                    font-weight: var(--byb-font-weight-medium);
                    text-transform: uppercase;
                    letter-spacing: 0.05em;
                    font-size: 14px;
                    cursor: pointer;
                    text-decoration: none;
                    transition: all var(--byb-duration-fast) var(--byb-ease-default);
                    border: 1px solid transparent;
                    flex: 1;
                }}
                
                .byb-btn--primary {{
                    background-color: var(--byb-color-success); /* Green for copy */
                    color: var(--byb-color-white);
                }}
                .byb-btn--primary:hover {{ background-color: #008f42; margin-top: -1px; margin-bottom: 1px; box-shadow: var(--byb-shadow-md); }}
                
                .byb-btn--secondary {{
                    background-color: var(--byb-color-orange);
                    color: var(--byb-color-white);
                }}
                .byb-btn--secondary:hover {{ background-color: var(--byb-color-hover-orange); margin-top: -1px; margin-bottom: 1px; box-shadow: var(--byb-shadow-md); }}
                
                .byb-btn--outline {{
                    background-color: transparent;
                    color: var(--byb-color-grey-text);
                    border-color: var(--byb-color-grey);
                    flex: 0 0 auto;
                }}
                .byb-btn--outline:hover {{ color: var(--byb-color-dark); border-color: var(--byb-color-dark); }}

                /* Info Info */
                .info-box {{
                    background: var(--byb-color-info-bg);
                    border-left: 4px solid var(--byb-color-info-border);
                    padding: 16px;
                    border-radius: var(--byb-border-radius-md);
                    font-size: 14px;
                    color: var(--byb-color-info-text);
                    text-align: left;
                    margin-bottom: var(--byb-space-6);
                    line-height: 1.6;
                }}

                
                /* Logo Component */
                .byb-logo {{
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                    text-decoration: none;
                    transition: opacity var(--byb-duration-fast) var(--byb-ease-default);
                }}
                .byb-logo:hover {{ opacity: 0.85; }}
                .byb-logo__img {{ display: block; width: auto; height: 80px; max-width: 100%; }}
                
                @media (max-width: 768px) {{
                    .byb-logo__img {{ height: 48px; }}
                }}

                /* Scopes */
                .scopes-container {{
                    text-align: left;
                    margin-bottom: var(--byb-space-6);
                }}
                .scope-tag {{
                    display: inline-block;
                    background: var(--byb-color-grey-bg);
                    color: var(--byb-color-grey-text);
                    padding: 4px 10px;
                    border-radius: 99px;
                    font-size: 11px;
                    margin: 0 4px 4px 0;
                    font-family: 'Roboto Mono', monospace;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                            <div class="logo-area">
                <a href="/" class="byb-logo byb-logo--horizontal">
                    <img src="/static/logo.svg" alt="Backyard Brains" class="byb-logo__img">
                </a>
            </div>
                <h1>MCP Access Token</h1>
                <p class="subtitle">Secure Bearer Token Generated</p>
                
                <div class="user-badge">
                    {user_info.get('email', user_info.get('name', 'User'))}
                </div>
                
                <div class="section-label">Your Token</div>
                <div class="token-display" id="tokenBox">{token}</div>
                
                <div class="btn-row">
                    <button class="byb-btn byb-btn--primary" onclick="copyToken()">Copy Token</button>
                    <button class="byb-btn byb-btn--secondary" onclick="createApiKey()">Create 1-Year Key</button>
                    <a href="/auth/logout" class="byb-btn byb-btn--outline">Logout</a>
                </div>
                
                {f'<div class="scopes-container"><div class="section-label">Active Permissions</div>' + "".join([f'<span class="scope-tag">{p}</span>' for p in mcp_perms]) + '</div>' if mcp_perms else ''}
                
                <div class="info-box">
                    <strong>Instructions:</strong><br>
                    1. Copy the token above.<br>
                    2. Paste it into your MCP Client configuration as: <code>Bearer YOUR_TOKEN</code><br>
                    3. Save and restart your client.
                </div>
            </div>
            <script>
                function copyToken() {{
                    const token = document.getElementById('tokenBox').textContent;
                    navigator.clipboard.writeText(token).then(() => {{
                        const btn = document.querySelector('.byb-btn--primary');
                        const originalText = btn.textContent;
                        btn.textContent = 'Copied!';
                        setTimeout(() => {{ btn.textContent = originalText; }}, 2000);
                    }});
                }}
                
                async function createApiKey() {{
                    if (!confirm("Create a 1-year API Key? This key will have the same permissions as your current session.")) return;
                    
                    try {{
                        const response = await fetch('/auth/create-api-key', {{ method: 'POST' }});
                        if (!response.ok) throw new Error(await response.text());
                        
                        const data = await response.json();
                        const tokenBox = document.getElementById('tokenBox');
                        tokenBox.textContent = data.api_key;
                        tokenBox.style.border = "2px solid var(--byb-color-success)";
                        tokenBox.style.backgroundColor = "var(--byb-color-success-bg)";
                        tokenBox.style.color = "#005a2b";
                        
                        // Show success message
                        const btn = document.querySelector('.byb-btn--secondary');
                        btn.textContent = 'Key Created!';
                        setTimeout(() => {{ btn.textContent = 'Create 1-Year Key'; }}, 3000);
                        
                    }} catch (e) {{
                        console.error("API Key Error:", e);
                        alert("Error: " + e.message + "\n\nSee server logs for details.");
                    }}
                }}
            </script>
        </body>
        </html>
        """

    
    # Not logged in - show login page with API selector
    html = """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <title>Backyard Brains | MCP Access</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <link rel="preconnect" href="https://fonts.googleapis.com">
        <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
        <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@400;500;700&display=swap" rel="stylesheet">
        <style>
            /* ==========================================================================
               BYB Design System - CSS Variables
               ========================================================================== */
            :root {
                /* COLORS */
                --byb-color-dark: #000000;
                --byb-color-orange: #ff805f;
                --byb-color-purpure: #FFD90F;
                --byb-color-yellow: #ffc600;
                --byb-color-green: #00aa4f;
                --byb-color-blue: #0093ff;
                --byb-color-white: #ffffff;
                
                --byb-color-hover-orange: #f07859;
                --byb-color-tinted-orange: #ffcdbf;
                --byb-color-light-tinted-orange: #ffe3db;
                --byb-color-very-light-tinted-orange: #fff5f2;
                
                --byb-color-grey-text: #707070;
                --byb-color-grey: #dbdbdb;
                --byb-color-grey-divider: #e9e9e9;
                --byb-color-grey-bg: #eeeeee;
                --byb-color-grey-bg-light: #f5f5f5;

                /* TYPOGRAPHY */
                --byb-font-display: 'Boldoa Mat', 'Impact', sans-serif;
                --byb-font-hand: 'BYB Hand Drawn', cursive;
                --byb-font-body: 'Roboto', -apple-system, BlinkMacSystemFont, sans-serif;
                
                --byb-font-weight-regular: 400;
                --byb-font-weight-medium: 500;
                --byb-font-weight-bold: 700;

                /* SPACING */
                --byb-space-1: 4px;
                --byb-space-2: 8px;
                --byb-space-3: 12px;
                --byb-space-4: 16px;
                --byb-space-6: 24px;
                --byb-space-8: 32px;
                
                /* BORDERS */
                --byb-border-radius-md: 4px;
                --byb-border-radius-lg: 6px;
                --byb-border-radius-full: 999px;
                
                /* SHADOWS */
                --byb-shadow-sm: 0 1px 2px rgba(0, 0, 0, 0.05);
                --byb-shadow-md: 0 4px 6px rgba(0, 0, 0, 0.1);
                --byb-shadow-lg: 0 10px 15px rgba(0, 0, 0, 0.1);
                
                /* ANIMATION */
                --byb-duration-fast: 100ms;
                --byb-ease-default: cubic-bezier(0.4, 0, 0.2, 1);
            }

            * { margin: 0; padding: 0; box-sizing: border-box; }
            
            body {
                font-family: var(--byb-font-body);
                background-color: var(--byb-color-grey-bg);
                color: var(--byb-color-dark);
                min-height: 100vh;
                display: flex;
                flex-direction: column;
                align-items: center;
                justify-content: center;
                padding: 20px;
                -webkit-font-smoothing: antialiased;
            }

            .container {
                background: var(--byb-color-white);
                border-radius: var(--byb-border-radius-lg);
                box-shadow: var(--byb-shadow-lg);
                max-width: 480px;
                width: 100%;
                padding: 48px;
                text-align: center;
            }

            .logo-area {
                margin-bottom: var(--byb-space-6);
                display: flex;
                align-items: center;
                justify-content: center;
            }
            
            /* Mimicking the logo with text if image fails, but using the official BYB orange */
            .logo-text {
                font-family: var(--byb-font-display), var(--byb-font-body); /* Fallback */
                font-size: 24px;
                font-weight: var(--byb-font-weight-bold);
                letter-spacing: -0.5px;
            }
            .logo-text span { color: var(--byb-color-orange); }

            h1 { 
                font-family: var(--byb-font-body);
                font-weight: var(--byb-font-weight-bold);
                color: var(--byb-color-dark);
                margin-bottom: var(--byb-space-2);
                font-size: 24px;
            }
            
            .subtitle {
                font-family: var(--byb-font-body);
                color: var(--byb-color-grey-text);
                margin-bottom: var(--byb-space-8);
                font-size: 16px;
                line-height: 1.5;
            }

            
                /* Logo Component */
                .byb-logo {
                    display: inline-flex;
                    align-items: center;
                    justify-content: center;
                    text-decoration: none;
                    transition: opacity var(--byb-duration-fast) var(--byb-ease-default);
                }
                .byb-logo:hover { opacity: 0.85; }
                .byb-logo__img { display: block; width: auto; height: 80px; max-width: 100%; }
                
                @media (max-width: 768px) {
                    .byb-logo__img { height: 48px; }
                }

                /* API Selector List */
            .api-selector {
                text-align: left;
                margin-bottom: var(--byb-space-8);
            }
            
            .api-group-label {
                font-size: 12px;
                text-transform: uppercase;
                letter-spacing: 0.05em;
                color: var(--byb-color-grey-text);
                margin-bottom: var(--byb-space-3);
                font-weight: var(--byb-font-weight-bold);
            }

            /* Custom Radio Card */
            .radio-card {
                position: relative;
                margin-bottom: var(--byb-space-3);
            }
            
            .radio-card input[type="radio"] {
                position: absolute;
                opacity: 0;
                width: 0;
                height: 0;
            }

            .radio-card label {
                display: flex;
                align-items: flex-start;
                padding: var(--byb-space-4);
                background-color: var(--byb-color-white);
                border: 2px solid var(--byb-color-grey);
                border-radius: var(--byb-border-radius-md);
                cursor: pointer;
                transition: all var(--byb-duration-fast) var(--byb-ease-default);
            }
            
            .radio-card label:hover {
                border-color: var(--byb-color-dark);
            }

            .radio-card input:checked + label {
                border-color: var(--byb-color-orange);
                background-color: var(--byb-color-very-light-tinted-orange);
            }
            
            /* Custom Radio Circle */
            .radio-circle {
                flex-shrink: 0;
                width: 20px;
                height: 20px;
                border: 2px solid var(--byb-color-grey);
                border-radius: 50%;
                margin-right: var(--byb-space-3);
                position: relative;
                margin-top: 2px; /* Align with title text */
                transition: border-color var(--byb-duration-fast) var(--byb-ease-default);
            }
            
            .radio-card input:checked + label .radio-circle {
                border-color: var(--byb-color-orange);
            }
            
            .radio-circle::after {
                content: '';
                position: absolute;
                top: 50%;
                left: 50%;
                transform: translate(-50%, -50%) scale(0);
                width: 10px;
                height: 10px;
                background-color: var(--byb-color-orange);
                border-radius: 50%;
                transition: transform var(--byb-duration-fast) var(--byb-ease-default);
            }
            
            .radio-card input:checked + label .radio-circle::after {
                transform: translate(-50%, -50%) scale(1);
            }

            .radio-content {
                display: flex;
                flex-direction: column;
            }
            .radio-title {
                font-weight: var(--byb-font-weight-bold);
                color: var(--byb-color-dark);
                font-size: 15px;
            }
            .radio-desc {
                font-size: 13px;
                color: var(--byb-color-grey-text);
                margin-top: 2px;
            }

            /* BYB Button */
            .byb-btn {
                display: inline-flex;
                align-items: center;
                justify-content: center;
                width: 100%;
                height: 48px;
                padding: 0 24px;
                background-color: var(--byb-color-orange);
                color: var(--byb-color-white);
                border: 1px solid var(--byb-color-orange);
                border-radius: var(--byb-border-radius-lg);
                
                font-family: var(--byb-font-body);
                font-weight: var(--byb-font-weight-medium);
                text-transform: uppercase;
                letter-spacing: 0.05em;
                font-size: 15px;
                cursor: pointer;
                text-decoration: none;
                
                transition: all var(--byb-duration-fast) var(--byb-ease-default);
            }
            
            .byb-btn:hover {
                background-color: var(--byb-color-hover-orange);
                border-color: var(--byb-color-hover-orange);
                transform: translateY(-1px);
                box-shadow: var(--byb-shadow-md);
            }
            
            .byb-btn:active {
                transform: translateY(0);
                background-color: #e56847;
            }

            .footer {
                margin-top: 32px;
                font-size: 12px;
                color: var(--byb-color-grey-text);
                border-top: 1px solid var(--byb-color-grey-divider);
                padding-top: 24px;
            }
        </style>
    </head>
    <body>
        <div class="container">
                        <div class="logo-area">
                <a href="/" class="byb-logo byb-logo--horizontal">
                    <img src="/static/logo.svg" alt="Backyard Brains" class="byb-logo__img">
                </a>
            </div>
            
            <h1>Intranet Access</h1>
            <p class="subtitle">Select your workspace and login to generate your secure MCP token.</p>
            
            <div class="api-selector">
                <div class="api-group-label">Select Workspace</div>
                
                <div class="radio-card">
                    <input type="radio" id="apiAssistant" name="apiChoice" value="assistant" checked>
                    <label for="apiAssistant">
                        <div class="radio-circle"></div>
                        <div class="radio-content">
                            <span class="radio-title">Assistant (General)</span>
                            <span class="radio-desc">Admin, Drive, Gmail, Calendar Access</span>
                        </div>
                    </label>
                </div>
                
                <div class="radio-card">
                    <input type="radio" id="apiXero" name="apiChoice" value="xero">
                    <label for="apiXero">
                        <div class="radio-circle"></div>
                        <div class="radio-content">
                            <span class="radio-title">Xero Accounting</span>
                            <span class="radio-desc">Invoices, Bills, and Financial Data</span>
                        </div>
                    </label>
                </div>
                
                <div class="radio-card">
                    <input type="radio" id="apiMetabase" name="apiChoice" value="metabase">
                    <label for="apiMetabase">
                        <div class="radio-circle"></div>
                        <div class="radio-content">
                            <span class="radio-title">Metabase Analytics</span>
                            <span class="radio-desc">Business Dashboards & Reporting</span>
                        </div>
                    </label>
                </div>

                <div class="radio-card">
                    <input type="radio" id="apiMeta" name="apiChoice" value="meta">
                    <label for="apiMeta">
                        <div class="radio-circle"></div>
                        <div class="radio-content">
                            <span class="radio-title">Meta Ads</span>
                            <span class="radio-desc">Marketing & Campaign Data</span>
                        </div>
                    </label>
                </div>
            </div>
            
            <button onclick="login()" class="byb-btn">Login via Auth0</button>
            
            <div class="footer">
                Secure access for Backyard Brains internal tools.<br>
                Powered by Antigravity MCP.
            </div>
        </div>
        <script>
            function login() {
                const api = document.querySelector('input[name="apiChoice"]:checked').value;
                window.location.href = '/auth/login?api=' + api;
            }
        </script>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

@app.get("/auth/login")
async def auth_login(request: Request, api: str = "xero"):
    """Initiate OAuth login flow with selected API audience."""
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    client_id = os.environ.get("AUTH0_CLIENT_ID")
    
    # Select audience and scope based on API choice
    if api == "assistant":
        audience = AUTH0_ASSISTANT_AUDIENCE
        scope = "openid profile email mcp:read:assistant mcp:write:assistant"
    elif api == "metabase":
        audience = AUTH0_METABASE_AUDIENCE
        scope = "openid profile email mcp:read:metabase mcp:write:metabase"
    elif api == "meta":
        audience = AUTH0_META_AUDIENCE
        scope = "openid profile email mcp:read:meta mcp:write:meta"
    elif api == "workshops":
        audience = AUTH0_WORKSHOPS_AUDIENCE
        scope = "openid profile email mcp:read:workshops mcp:write:workshops mcp:admin:workshops"
    elif api == "xero":
        audience = AUTH0_XERO_AUDIENCE
        scope = "openid profile email mcp:read:xero mcp:write:xero"
    else:
        # Default to Assistant
        audience = AUTH0_ASSISTANT_AUDIENCE
        scope = "openid profile email mcp:read:assistant mcp:write:assistant"
    
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
        "scope": scope,
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
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.post(token_url, json=token_data)
            response.raise_for_status()
            token_response = response.json()
            
            access_token = token_response.get("access_token")
            if not access_token:
                raise HTTPException(status_code=500, detail="No access token in response")
            
            # Get user info
            userinfo_url = f"https://{auth0_domain}/userinfo"
            headers = {"Authorization": f"Bearer {access_token}"}
            user_response = await client.get(userinfo_url, headers=headers)
            user_response.raise_for_status()
            user_info = user_response.json()
            
        # Store token and user info in session
        # Only store necessary fields to keep cookie size small
        request.session["access_token"] = access_token
        request.session["user_info"] = {"email": user_info.get("email"), "name": user_info.get("name")}
        request.session.pop("oauth_state", None)
        
        # DEBUG: Check session size
        import json
        session_size = len(json.dumps(dict(request.session)))
        logger.info(f"Callback: Storing session. Access Token len: {len(access_token)}. Approx session JSON size: {session_size} bytes")
        
        # Redirect to token display page
        return RedirectResponse(url="/auth/token", status_code=303)
        
    except httpx.HTTPStatusError as e:
        logger.error(f"Token exchange failed: {e.response.text}")
        raise HTTPException(status_code=e.response.status_code, detail=f"Token exchange failed: {str(e)}")
    except httpx.RequestError as e:
        logger.error(f"Token exchange connection error: {e}")
        raise HTTPException(status_code=500, detail=f"Token exchange connection error: {str(e)}")


@app.get("/auth/logout")
async def auth_logout(request: Request):
    """Log out of the application and Auth0."""
    # Clear local session
    request.session.clear()
    
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    client_id = os.environ.get("AUTH0_CLIENT_ID")
    
    if not auth0_domain or not client_id:
        return RedirectResponse(url="/")
        
    # Build Auth0 logout URL
    base_url = request.url_for("root")
    # returnTo must be in the Allowed Logout URLs in Auth0 application settings
    # We'll assume the root URL is allowed
    params = {
        "client_id": client_id,
        "returnTo": str(base_url) 
    }
    logout_url = f"https://{auth0_domain}/v2/logout?{urlencode(params)}"
    
    return RedirectResponse(url=logout_url)

# Health Check
@app.get("/health")
def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)