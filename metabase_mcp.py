import os
import logging
import requests
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import JSONResponse

from utils import _rpc_result, _rpc_error, logger, safe_dumps

# Environment variables
METABASE_URL = os.environ.get("METABASE_URL")
METABASE_USERNAME = os.environ.get("METABASE_USERNAME")
METABASE_PASSWORD = os.environ.get("METABASE_PASSWORD")
METABASE_API_KEY = os.environ.get("METABASE_API_KEY")

router = APIRouter()

@router.get("/")
def metabase_index():
    """Basic index endpoint so /metabase/ doesn't 404 behind nginx."""
    return {
        "service": "metabase-mcp",
        "status": "ok",
        "endpoints": {
            "health": "/metabase/healthz",
            "mcp": "/metabase/mcp",
        },
    }

@router.post("/")
async def metabase_index_post(request: Request, payload: Dict = Depends(require_metabase_auth)):
    """
    Handle MCP JSON-RPC requests at the root /metabase/ endpoint.
    Delegates to the same logic as /metabase/mcp for convenience.
    """
    return await handle_metabase_mcp(request, payload)

@router.get("/healthz")
def metabase_healthz():
    return {"status": "ok", "service": "metabase"}

class MetabaseClient:
    def __init__(self):
        if not METABASE_URL:
            logger.error("METABASE_URL environment variable not set")
            raise ValueError("METABASE_URL not set")
        
        self.base_url = METABASE_URL.rstrip("/")
        self.session_token = None
        self.api_key = METABASE_API_KEY
        
        if self.api_key:
            logger.info("Using Metabase API Key for authentication.")
        elif METABASE_USERNAME and METABASE_PASSWORD:
            logger.info("Using Metabase username/password for authentication.")
        else:
            logger.error("Metabase credentials not found (API Key or Username/Password).")

    def _get_headers(self) -> Dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json"
        }
        if self.api_key:
            headers["X-API-Key"] = self.api_key
        elif self.session_token:
            headers["X-Metabase-Session"] = self.session_token
        return headers

    def authenticate(self):
        if self.api_key:
            return # API Key doesn't need session login
        
        if not METABASE_USERNAME or not METABASE_PASSWORD:
             raise ValueError("Missing Metabase credentials")

        try:
            resp = requests.post(
                f"{self.base_url}/api/session",
                json={"username": METABASE_USERNAME, "password": METABASE_PASSWORD},
                timeout=10
            )
            resp.raise_for_status()
            self.session_token = resp.json().get("id")
            logger.info("Successfully authenticated with Metabase")
        except Exception as e:
            logger.error(f"Failed to authenticate with Metabase: {e}")
            raise

    def request(self, method: str, endpoint: str, **kwargs) -> Any:
        # Auto-authenticate if needed (and not using API key)
        if not self.api_key and not self.session_token:
            self.authenticate()

        url = f"{self.base_url}{endpoint}"
        headers = self._get_headers()
        
        # Merge headers if provided in kwargs
        if "headers" in kwargs:
            headers.update(kwargs.pop("headers"))

        try:
            response = requests.request(method, url, headers=headers, **kwargs)
            
            if response.status_code == 401 and not self.api_key:
                # Token might have expired, retry once
                logger.info("Metabase token expired, re-authenticating...")
                self.authenticate()
                headers = self._get_headers()
                response = requests.request(method, url, headers=headers, **kwargs)

            response.raise_for_status()
            return response.json()
        except requests.exceptions.HTTPError as e:
            logger.error(f"Metabase API error {e.response.status_code}: {e.response.text}")
            raise HTTPException(status_code=e.response.status_code, detail=f"Metabase API Error: {e.response.text}")
        except Exception as e:
            logger.error(f"Metabase request failed: {e}")
            raise HTTPException(status_code=500, detail=str(e))

_metabase_client = None

def get_metabase_client():
    global _metabase_client
    if _metabase_client is None:
        try:
            _metabase_client = MetabaseClient()
        except Exception as e:
            logger.error(f"Failed to initialize Metabase client: {e}")
            return None
    return _metabase_client

def _list_metabase_tools():
    return {
        "tools": [
            {
                "name": "metabase_list_dashboards",
                "description": "List all dashboards",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "metabase_list_databases",
                "description": "List all databases connected to Metabase",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "metabase_list_cards",
                "description": "List all cards (saved questions)",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "metabase_get_dashboard",
                "description": "Get dashboard details including ordered cards",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dashboard_id": {"type": "integer", "description": "ID of the dashboard"}
                    },
                    "required": ["dashboard_id"]
                }
            },
            {
                "name": "metabase_execute_card",
                "description": "Execute a saved card (question) and get results",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "card_id": {"type": "integer", "description": "ID of the card to execute"},
                        "parameters": {"type": "array", "items": {"type": "object"}, "description": "Optional parameters for the card"}
                    },
                    "required": ["card_id"]
                }
            },
            {
                "name": "metabase_execute_sql",
                "description": "Execute a raw SQL query against a database",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "database_id": {"type": "integer", "description": "ID of the database to query"},
                        "query": {"type": "string", "description": "SQL query to execute"}
                    },
                    "required": ["database_id", "query"]
                }
            },
            {
                "name": "metabase_create_card",
                "description": "Create a new card (saved question)",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "dataset_query": {"type": "object", "description": "The query definition (MBQL or native)"},
                        "display": {"type": "string", "description": "Display type (table, line, etc)"},
                        "visualization_settings": {"type": "object"},
                        "database_id": {"type": "integer"},
                        "collection_id": {"type": "integer", "description": "Optional collection ID"}
                    },
                    "required": ["name", "dataset_query", "database_id"]
                }
            },
            {
                "name": "metabase_update_card",
                "description": "Update an existing card",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "card_id": {"type": "integer"},
                        "name": {"type": "string"},
                        "dataset_query": {"type": "object"},
                        "display": {"type": "string"},
                        "visualization_settings": {"type": "object"},
                        "description": {"type": "string"},
                        "archived": {"type": "boolean"}
                    },
                    "required": ["card_id"]
                }
            },
            {
                "name": "metabase_create_dashboard",
                "description": "Create a new dashboard",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "name": {"type": "string"},
                        "description": {"type": "string"},
                        "parameters": {"type": "array", "items": {"type": "object"}},
                        "collection_id": {"type": "integer"}
                    },
                    "required": ["name"]
                }
            }
        ]
    }

async def handle_metabase_tool_call(name: str, args: Dict):
    client = get_metabase_client()
    if not client:
        return {"isError": True, "content": [{"type": "text", "text": "Metabase client not initialized"}]}

    try:
        if name == "metabase_list_dashboards":
            dashboards = client.request("GET", "/api/dashboard")
            # Simplify output
            simple_dashboards = [
                {"id": d.get("id"), "name": d.get("name"), "description": d.get("description")}
                for d in dashboards
            ]
            return {"content": [{"type": "text", "text": safe_dumps(simple_dashboards)}]}

        elif name == "metabase_list_databases":
            databases = client.request("GET", "/api/database")
            simple_dbs = [
                {"id": d.get("id"), "name": d.get("name"), "engine": d.get("engine")}
                for d in databases
            ]
            return {"content": [{"type": "text", "text": safe_dumps(simple_dbs)}]}

        elif name == "metabase_list_cards":
            cards = client.request("GET", "/api/card")
            simple_cards = [
                {"id": c.get("id"), "name": c.get("name"), "collection_id": c.get("collection_id"), "database_id": c.get("database_id")}
                for c in cards
            ]
            return {"content": [{"type": "text", "text": safe_dumps(simple_cards)}]}

        elif name == "metabase_get_dashboard":
            dash_id = args.get("dashboard_id")
            dashboard = client.request("GET", f"/api/dashboard/{dash_id}")
            return {"content": [{"type": "text", "text": safe_dumps(dashboard)}]}

        elif name == "metabase_execute_card":
            card_id = args.get("card_id")
            params = args.get("parameters", [])
            
            # Use the card query endpoint
            result = client.request("POST", f"/api/card/{card_id}/query", json={"parameters": params})
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}

        elif name == "metabase_execute_sql":
            db_id = args.get("database_id")
            query = args.get("query")
            
            payload = {
                "database": db_id,
                "type": "native",
                "native": {"query": query}
            }
            result = client.request("POST", "/api/dataset", json=payload)
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}

        elif name == "metabase_create_card":
            # Construct payload from args
            payload = {
                "name": args.get("name"),
                "dataset_query": args.get("dataset_query"),
                "display": args.get("display", "table"),
                "visualization_settings": args.get("visualization_settings", {}),
                "database_id": args.get("database_id"),
                "collection_id": args.get("collection_id")
            }
            # Remove None values
            payload = {k: v for k, v in payload.items() if v is not None}
            
            card = client.request("POST", "/api/card", json=payload)
            return {"content": [{"type": "text", "text": safe_dumps(card)}]}

        elif name == "metabase_update_card":
            card_id = args.get("card_id")
            payload = {}
            for k in ["name", "dataset_query", "display", "visualization_settings", "description", "archived"]:
                if k in args:
                    payload[k] = args[k]
            
            card = client.request("PUT", f"/api/card/{card_id}", json=payload)
            return {"content": [{"type": "text", "text": safe_dumps(card)}]}

        elif name == "metabase_create_dashboard":
            payload = {
                "name": args.get("name"),
                "description": args.get("description"),
                "parameters": args.get("parameters", []),
                "collection_id": args.get("collection_id")
            }
            payload = {k: v for k, v in payload.items() if v is not None}
            
            dash = client.request("POST", "/api/dashboard", json=payload)
            return {"content": [{"type": "text", "text": safe_dumps(dash)}]}

        else:
            return {"isError": True, "content": [{"type": "text", "text": f"Unknown tool: {name}"}]}

    except Exception as e:
        logger.error(f"Error executing Metabase tool {name}: {e}")
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Error executing {name}: {str(e)}"}],
            "metadata": {"reason": "exception", "exceptionType": type(e).__name__}
        }

def _list_metabase_resources():
    client = get_metabase_client()
    if not client:
        return {"resources": []}
    
    resources = []
    try:
        # Dashboards
        dashboards = client.request("GET", "/api/dashboard")
        for d in dashboards:
            resources.append({
                "uri": f"metabase://dashboard/{d['id']}",
                "name": d['name'],
                "description": d.get('description', 'Metabase Dashboard'),
                "mimeType": "application/json"
            })
        
        # Cards
        cards = client.request("GET", "/api/card")
        for c in cards:
            resources.append({
                "uri": f"metabase://card/{c['id']}",
                "name": c['name'],
                "description": c.get('description', 'Metabase Card'),
                "mimeType": "application/json"
            })
    except Exception as e:
        logger.error(f"Error listing resources: {e}")
    
    return {"resources": resources}

def _read_metabase_resource(uri: str):
    client = get_metabase_client()
    if not client:
        raise ValueError("Metabase client not initialized")

    if uri.startswith("metabase://dashboard/"):
        dash_id = uri.split("/")[-1]
        data = client.request("GET", f"/api/dashboard/{dash_id}")
        return {
            "contents": [{
                "uri": uri,
                "mimeType": "application/json",
                "text": safe_dumps(data)
            }]
        }
    elif uri.startswith("metabase://card/"):
        card_id = uri.split("/")[-1]
        # For cards, we might want the query results or the card definition.
        # Let's return the card definition for now, as executing it might be heavy/require params.
        data = client.request("GET", f"/api/card/{card_id}")
        return {
            "contents": [{
                "uri": uri,
                "mimeType": "application/json",
                "text": safe_dumps(data)
            }]
        }
    else:
        raise ValueError(f"Unknown resource URI: {uri}")

from auth import require_metabase_auth

@router.post("/mcp")
async def handle_metabase_mcp(request: Request, payload: Dict = Depends(require_metabase_auth)):
    """
    Standard MCP endpoint for Metabase tools.
    JSON-RPC 2.0
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    rpc_id = body.get("id")
    method = body.get("method")
    params = body.get("params", {})

    if method == "tools/list":
        return _rpc_result(rpc_id, _list_metabase_tools())
    
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        result = await handle_metabase_tool_call(name, args)
        return _rpc_result(rpc_id, result)

    elif method == "resources/list":
        return _rpc_result(rpc_id, _list_metabase_resources())
    
    elif method == "resources/read":
        uri = params.get("uri")
        try:
            result = _read_metabase_resource(uri)
            return _rpc_result(rpc_id, result)
        except Exception as e:
             return _rpc_error(rpc_id, -32602, str(e))

    elif method == "prompts/list":
        return _rpc_result(rpc_id, {"prompts": []})

    elif method == "prompts/get":
         return _rpc_result(rpc_id, {"messages": []})

    else:
        return _rpc_error(rpc_id, -32601, f"Method {method} not found")


