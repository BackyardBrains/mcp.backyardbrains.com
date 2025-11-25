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
    audience = os.environ.get("AUTH0_AUDIENCE")
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
    audience = os.environ.get("AUTH0_AUDIENCE")
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
    audience = os.environ.get("AUTH0_AUDIENCE")
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
    """Display token generation page with login button or current token."""
    token = request.session.get("access_token")
    user_info = request.session.get("user_info")
    
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
        <html>
        <head>
            <title>Your MCP Token</title>
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <style>
                * {{ margin: 0; padding: 0; box-sizing: border-box; }}
                body {{
                    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    min-height: 100vh;
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    padding: 20px;
                }}
                .container {{
                    background: white;
                    border-radius: 16px;
                    box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                    max-width: 600px;
                    width: 100%;
                    padding: 40px;
                }}
                h1 {{ color: #333; margin-bottom: 10px; font-size: 28px; }}
                .subtitle {{ color: #666; margin-bottom: 30px; font-size: 14px; }}
                .user-info {{
                    background: #dbeafe;
                    border-radius: 8px;
                    padding: 12px;
                    margin-bottom: 20px;
                    font-size: 14px;
                    color: #1e40af;
                }}
                .token-box {{
                    background: #f7f9fc;
                    border: 2px solid #e1e8ed;
                    border-radius: 8px;
                    padding: 20px;
                    margin: 20px 0;
                    word-break: break-all;
                    font-family: 'Courier New', monospace;
                    font-size: 12px;
                    color: #333;
                    max-height: 200px;
                    overflow-y: auto;
                }}
                .btn {{
                    background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                    color: white;
                    border: none;
                    padding: 14px 32px;
                    border-radius: 8px;
                    font-size: 16px;
                    font-weight: 600;
                    cursor: pointer;
                    transition: transform 0.2s, box-shadow 0.2s;
                    display: inline-block;
                    text-decoration: none;
                }}
                .btn:hover {{
                    transform: translateY(-2px);
                    box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
                }}
                .copy-btn {{ background: #10b981; margin-right: 10px; }}
                .logout-btn {{ background: #6b7280; }}
                .info {{
                    background: #fef3c7;
                    border-left: 4px solid #f59e0b;
                    padding: 12px 16px;
                    margin: 20px 0;
                    border-radius: 4px;
                    font-size: 14px;
                    color: #92400e;
                }}
                .scope-tag {{
                    display: inline-block;
                    background: #e0e7ff;
                    color: #4338ca;
                    padding: 4px 12px;
                    border-radius: 12px;
                    font-size: 12px;
                    margin: 4px;
                    font-family: 'Courier New', monospace;
                }}
            </style>
        </head>
        <body>
            <div class="container">
                <h1>🔐 MCP Access Token</h1>
                <p class="subtitle">Your personal bearer token for Antigravity MCP</p>
                
                <div class="user-info">
                    Logged in as <strong>{user_info.get('email', user_info.get('name', 'User'))}</strong>
                </div>
                
                <h2 style="font-size: 18px; margin-bottom: 10px; color: #333;">Your Access Token</h2>
                <div class="token-box" id="tokenBox">{token}</div>
                
                <button class="btn copy-btn" onclick="copyToken()">📋 Copy Token</button>
                <a href="/auth/logout" class="btn logout-btn">Logout</a>
                
                {'<div style="margin-top: 15px;"><h3 style="font-size: 14px; color: #666; margin-bottom: 8px;">Your Permissions:</h3>' + "".join([f'<span class="scope-tag">{p}</span>' for p in mcp_perms]) + '</div>' if mcp_perms else ''}
                
                <div class="info">
                    <strong>How to use:</strong><br>
                    1. Copy the token above<br>
                    2. Open your Antigravity MCP config<br>
                    3. Replace the Authorization header value with: <code>Bearer YOUR_TOKEN</code><br>
                    4. Save and reconnect
                </div>
            </div>
            <script>
                function copyToken() {{
                    const token = document.getElementById('tokenBox').textContent;
                    navigator.clipboard.writeText(token).then(() => {{
                        const btn = event.target;
                        btn.textContent = '✅ Copied!';
                        setTimeout(() => {{ btn.textContent = '📋 Copy Token'; }}, 2000);
                    }});
                }}
            </script>
        </body>
        </html>
        """
        return HTMLResponse(content=html)
    
    # Not logged in - show login page
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Get Your MCP Token</title>
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            * { margin: 0; padding: 0; box-sizing: border-box; }
            body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                min-height: 100vh;
                display: flex;
                align-items: center;
                justify-content: center;
                padding: 20px;
            }
            .container {
                background: white;
                border-radius: 16px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                max-width: 600px;
                width: 100%;
                padding: 40px;
                text-align: center;
            }
            h1 { color: #333; margin-bottom: 10px; font-size: 28px; }
            .subtitle { color: #666; margin-bottom: 30px; font-size: 14px; }
            .btn {
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                color: white;
                border: none;
                padding: 14px 32px;
                border-radius: 8px;
                font-size: 16px;
                font-weight: 600;
                cursor: pointer;
                transition: transform 0.2s, box-shadow 0.2s;
                display: inline-block;
                text-decoration: none;
            }
            .btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
            }
            .info {
                background: #fef3c7;
                border-left: 4px solid #f59e0b;
                padding: 12px 16px;
                margin: 20px 0;
                border-radius: 4px;
                font-size: 14px;
                text-align: left;
                color: #92400e;
            }
        </style>
    </head>
    <body>
        <div class="container">
            <h1>🔐 MCP Access Token</h1>
            <p class="subtitle">Get your personal bearer token for Antigravity MCP</p>
            
            <p style="margin-bottom: 20px; color: #666;">
                Click below to log in with your Backyard Brains account and generate your personal MCP access token.
            </p>
            
            <a href="/auth/login" class="btn">Login with Auth0</a>
            
            <div class="info" style="margin-top: 30px;">
                <strong>What is this?</strong><br>
                This page generates a personal bearer token you can use in Antigravity's MCP configuration. Your token
                will only have the permissions assigned to your account.
            </div>
        </div>
    </body>
    </html>
    """
    return HTMLResponse(content=html)

@app.get("/auth/login")
async def auth_login(request: Request):
    """Initiate OAuth login flow."""
    auth0_domain = os.environ.get("AUTH0_DOMAIN")
    client_id = os.environ.get("AUTH0_CLIENT_ID")
    audience = os.environ.get("AUTH0_AUDIENCE")
    
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