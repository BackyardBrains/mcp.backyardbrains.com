import os
import logging
import uvicorn
import requests
from dotenv import load_dotenv
from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from starlette.middleware.base import BaseHTTPMiddleware

# Load environment variables
load_dotenv()

from utils import logger, MCP_PROTOCOL_VERSION
import xero_mcp
import metabase_mcp
import oauth_endpoints

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
app.include_router(oauth_endpoints.router, tags=["oauth"])
app.include_router(xero_mcp.router, prefix="/xero", tags=["xero"])
app.include_router(metabase_mcp.router, prefix="/metabase", tags=["metabase"])

# Serve static files (for token generation page)
if os.path.exists("static"):
    app.mount("/static", StaticFiles(directory="static"), name="static")

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
        },
        # We can optionally list tools/resources here if the client supports it in manifest,
        # but typically they are discovered via tools/list and resources/list.
        # However, some MCP clients might look for them here or just the capabilities.
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

# Health Check
@app.get("/health")
def health_check():
    return {"status": "ok"}

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    uvicorn.run(app, host="0.0.0.0", port=port)