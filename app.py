from dotenv import load_dotenv
load_dotenv() 

import logging
import os
import json
from typing import Dict, Any
import base64

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse
import requests
import uvicorn
from cryptography.fernet import Fernet, InvalidToken
from xero_python.accounting import AccountingApi, Contact, Contacts, BankTransaction, BankTransactions, Journal, Payment, Quote, Account, Organisation
from xero_python.api_client import ApiClient
from xero_python.api_client.configuration import Configuration
from urllib.parse import urlencode
from jose import jwt, JWTError
from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables
XERO_CLIENT_ID = os.environ.get("XERO_CLIENT_ID")
XERO_CLIENT_SECRET = os.environ.get("XERO_CLIENT_SECRET")
XERO_REDIRECT_URI = os.environ.get("XERO_REDIRECT_URI", "http://localhost:8000/xero/callback")
XERO_SCOPES = "offline_access openid profile accounting.transactions.read accounting.contacts.read accounting.journals.read accounting.reports.read"

# Encryption setup
TOKEN_ENC_KEY = os.environ.get("TOKEN_ENC_KEY")  # Base64-encoded 32-byte key
TOKEN_STORE_PATH = os.environ.get("TOKEN_STORE_PATH", ".xero_tokens.enc")
TENANT_FILE = "tenant_id.txt"  # Plain for simplicity; encrypt if needed

if not TOKEN_ENC_KEY:
    logger.warning("TOKEN_ENC_KEY not set; tokens will not be encrypted!")

fernet = Fernet(TOKEN_ENC_KEY) if TOKEN_ENC_KEY else None

# Auth0 configuration
AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN")  # e.g., "your-tenant.us.auth0.com"
AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE")  # e.g., "https://mcp.backyardbrains.com/xero"
AUTH0_ISSUER = f"https://{AUTH0_DOMAIN}/" if AUTH0_DOMAIN else None
JWKS_URL = f"{AUTH0_ISSUER}.well-known/jwks.json" if AUTH0_ISSUER else None
ALGORITHMS = ["RS256"]
security = HTTPBearer(auto_error=False)
_jwks_cache = None

def get_jwks():
    global _jwks_cache
    if _jwks_cache is None:
        if not JWKS_URL:
            raise HTTPException(status_code=500, detail="Auth not configured")
        resp = requests.get(JWKS_URL, timeout=5)
        resp.raise_for_status()
        _jwks_cache = resp.json()
    return _jwks_cache

def verify_jwt(token: str):
    try:
        jwks = get_jwks()
        unverified_header = jwt.get_unverified_header(token)
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
            raise HTTPException(status_code=401, detail="Invalid token: key not found")
        payload = jwt.decode(
            token,
            rsa_key,
            algorithms=ALGORITHMS,
            audience=AUTH0_AUDIENCE,
            issuer=AUTH0_ISSUER,
            options={"verify_at_hash": False}
        )
        return payload
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token validation error: {str(e)}")

def require_auth(creds: HTTPAuthorizationCredentials = Depends(security)):
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Authorization header missing or invalid")
    return verify_jwt(creds.credentials)

def encrypt_data(data: bytes) -> bytes:
    if not fernet:
        return data
    return fernet.encrypt(data)

def decrypt_data(encrypted: bytes) -> bytes:
    if not fernet:
        return encrypted
    try:
        return fernet.decrypt(encrypted)
    except InvalidToken:
        raise ValueError("Invalid encryption key or corrupted token file")

def load_tokens():
    if not os.path.exists(TOKEN_STORE_PATH):
        return None
    with open(TOKEN_STORE_PATH, 'rb') as f:
        encrypted = f.read()
    decrypted = decrypt_data(encrypted)
    return json.loads(decrypted)

def save_tokens(tokens: Dict):
    data = json.dumps(tokens).encode('utf-8')
    encrypted = encrypt_data(data)
    with open(TOKEN_STORE_PATH, 'wb') as f:
        f.write(encrypted)

def load_tenant_id():
    if os.path.exists(TENANT_FILE):
        with open(TENANT_FILE, 'r') as f:
            return f.read().strip()
    return None

def save_tenant_id(tenant_id: str):
    with open(TENANT_FILE, 'w') as f:
        f.write(tenant_id)

def get_xero_client():
    config = Configuration()
    config.api_base_url = "https://api.xero.com"
    api_client = ApiClient(configuration=config)
    tokens = load_tokens()
    if tokens:
        api_client.set_oauth_token(tokens['access_token'])
    return api_client

def refresh_token_if_needed():
    tokens = load_tokens()
    if not tokens:
        return
    # Simple check; in production, check expiry
    refresh_url = "https://identity.xero.com/connect/token"
    response = requests.post(refresh_url, data={
        "grant_type": "refresh_token",
        "refresh_token": tokens['refresh_token']
    }, auth=(XERO_CLIENT_ID, XERO_CLIENT_SECRET))
    if response.status_code == 200:
        new_tokens = response.json()
        save_tokens(new_tokens)

app = FastAPI()  # Define app here, after helpers but before routes

@app.get("/xero/auth")
def xero_auth():
    if not XERO_CLIENT_ID or not XERO_CLIENT_SECRET:
        raise HTTPException(status_code=400, detail="Xero credentials not configured")
    
    params = {
        "client_id": XERO_CLIENT_ID,
        "response_type": "code",
        "scope": XERO_SCOPES,
        "redirect_uri": XERO_REDIRECT_URI,
        "state": "123"  # Add proper state handling in production
    }
    auth_url = "https://login.xero.com/identity/connect/authorize?" + urlencode(params)
    return RedirectResponse(auth_url)

@app.get("/xero/callback")
def xero_callback(code: str = None, state: str = None):
    if not code:
        raise HTTPException(status_code=400, detail="No code provided")
    
    token_url = "https://identity.xero.com/connect/token"
    response = requests.post(token_url, data={
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": XERO_REDIRECT_URI
    }, auth=(XERO_CLIENT_ID, XERO_CLIENT_SECRET))
    
    if response.status_code != 200:
        raise HTTPException(status_code=400, detail="Token exchange failed")
    
    tokens = response.json()
    save_tokens(tokens)
    
    # Get connections (tenants)
    connections_url = "https://api.xero.com/connections"
    conn_response = requests.get(connections_url, headers={
        "Authorization": f"Bearer {tokens['access_token']}"
    })
    
    if conn_response.status_code != 200:
        raise HTTPException(status_code=400, detail="Failed to get tenants")
    
    tenants = conn_response.json()
    if not tenants:
        raise HTTPException(status_code=400, detail="No tenants found")
    
    tenant_id = tenants[0]['tenantId']
    save_tenant_id(tenant_id)
    
    return {"message": "Authentication successful. Tenant ID saved."}

def _rpc_result(rpc_id: Any, result: Dict[str, Any]):
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}

def _rpc_error(rpc_id: Any, code: int, message: str, data: Any = None):
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": rpc_id, "error": err}

def _list_tools_payload():
    return {
        "tools": [
            {
                "name": "xero.list_invoices",
                "description": "Retrieves sales invoices or purchase bills",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "xero.get_balance_sheet",
                "description": "Retrieves report for balancesheet",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "xero.list_contacts",
                "description": "Retrieves all contacts (customers/suppliers)",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "xero.create_contacts",
                "description": "Creates one or more contacts",
                "inputSchema": {"type": "object", "properties": {"contacts": {"type": "array"}}}
            },
            {
                "name": "xero.list_bank_transactions",
                "description": "Retrieves bank transactions",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "xero.create_bank_transactions",
                "description": "Creates one or more bank transactions",
                "inputSchema": {"type": "object", "properties": {"bank_transactions": {"type": "array"}}}
            },
            {
                "name": "xero.list_accounts",
                "description": "Retrieves the full chart of accounts",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "xero.list_journals",
                "description": "Retrieves journals",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "xero.list_organisations",
                "description": "Retrieves Xero organisation details",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "xero.list_payments",
                "description": "Retrieves payments",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "xero.list_quotes",
                "description": "Retrieves quotes",
                "inputSchema": {"type": "object", "properties": {}}
            }
        ]
    }

# MCP Endpoint
@app.post("/xero/mcp")
async def mcp_endpoint(request: Request, _=Depends(require_auth)):
    body = await request.json()

    # JSON-RPC 2.0 handling (MCP over HTTP)
    if isinstance(body, dict) and body.get("jsonrpc") == "2.0" and isinstance(body.get("method"), str):
        rpc_id = body.get("id")
        method = body.get("method")
        params = body.get("params", {})
        logger.info(f"MCP JSON-RPC method: {method}")

        if method == "initialize":
            result = {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "xero-mcp", "version": "1.0.0"},
                "capabilities": {
                    "tools": {}
                }
            }
            return _rpc_result(rpc_id, result)

        if method in ("tools/list", "tools.list"):
            return _rpc_result(rpc_id, _list_tools_payload())

        if method in ("tools/call", "tools.call", "call_tool"):
            tool_name = params.get("name") or params.get("tool")
            args = params.get("arguments") or params.get("args") or {}
            tool_result = await handle_tool_call(tool_name, args)
            return _rpc_result(rpc_id, tool_result)

        return _rpc_error(rpc_id, -32601, "Method not found")

    # Legacy/simple handling (non JSON-RPC)
    method = str(body.get("method", "")).lower()
    if method in ["", "discover", "tools/list"]:
        return _list_tools_payload()

    if method in ["tools/call", "call_tool"]:
        tool_name = body.get("params", {}).get("name")
        args = body.get("params", {}).get("arguments", {})
        return await handle_tool_call(tool_name, args)

    return {"error": "Method not found"}

# Accept base-path POSTs that some clients send to the MCP server root
@app.post("/xero/")
async def mcp_root_post(request: Request, _=Depends(require_auth)):
    return await mcp_endpoint(request)

# Also accept no-trailing-slash variant
@app.post("/xero")
async def mcp_root_post_no_slash(request: Request, _=Depends(require_auth)):
    return await mcp_endpoint(request)

# Provide a simple GET on the MCP root for basic diagnostics
@app.get("/xero/")
def mcp_root_get(_=Depends(require_auth)):
    return {"status": "ok", "message": "Xero MCP root. POST JSON with method=initialize/tools.list/tools.call."}

# No-trailing-slash variant
@app.get("/xero")
def mcp_root_get_no_slash(_=Depends(require_auth)):
    return {"status": "ok", "message": "Xero MCP root. POST JSON with method=initialize/tools.list/tools.call."}

async def handle_tool_call(name: str, args: Dict):
    try:
        refresh_token_if_needed()
        api_client = get_xero_client()
        tenant_id = load_tenant_id()
        if not tenant_id:
            return {"content": [{"type": "text", "text": "No tenant ID configured. Authenticate first."}]}

        accounting_api = AccountingApi(api_client)
        
        if name == "xero.list_invoices":
            invoices = accounting_api.get_invoices(tenant_id)
            return {"content": [{"type": "text", "text": json.dumps([inv.to_dict() for inv in invoices.invoices])}]}

        elif name == "xero.get_balance_sheet":
            balance_sheet = accounting_api.get_report_balance_sheet(tenant_id)
            return {"content": [{"type": "text", "text": json.dumps([rep.to_dict() for rep in balance_sheet.reports])}]}

        elif name == "xero.list_contacts":
            contacts = accounting_api.get_contacts(tenant_id)
            return {"content": [{"type": "text", "text": json.dumps([c.to_dict() for c in contacts.contacts])}]}

        elif name == "xero.create_contacts":
            contacts_data = args.get('contacts', [])
            contacts_obj = Contacts(contacts=[Contact(**data) for data in contacts_data])
            created = accounting_api.create_contacts(tenant_id, contacts_obj)
            return {"content": [{"type": "text", "text": json.dumps([c.to_dict() for c in created.contacts])}]}

        elif name == "xero.list_bank_transactions":
            transactions = accounting_api.get_bank_transactions(tenant_id)
            return {"content": [{"type": "text", "text": json.dumps([t.to_dict() for t in transactions.bank_transactions])}]}

        elif name == "xero.create_bank_transactions":
            bank_transactions_data = args.get('bank_transactions', [])
            bank_transactions_obj = BankTransactions(bank_transactions=[BankTransaction(**data) for data in bank_transactions_data])
            created = accounting_api.create_bank_transactions(tenant_id, bank_transactions_obj)
            return {"content": [{"type": "text", "text": json.dumps([t.to_dict() for t in created.bank_transactions])}]}

        elif name == "xero.list_accounts":
            accounts = accounting_api.get_accounts(tenant_id)
            return {"content": [{"type": "text", "text": json.dumps([a.to_dict() for a in accounts.accounts])}]}

        elif name == "xero.list_journals":
            journals = accounting_api.get_journals(tenant_id)
            return {"content": [{"type": "text", "text": json.dumps([j.to_dict() for j in journals.journals])}]}

        elif name == "xero.list_organisations":
            organisations = accounting_api.get_organisations(tenant_id)
            return {"content": [{"type": "text", "text": json.dumps([o.to_dict() for o in organisations.organisations])}]}

        elif name == "xero.list_payments":
            payments = accounting_api.get_payments(tenant_id)
            return {"content": [{"type": "text", "text": json.dumps([p.to_dict() for p in payments.payments])}]}

        elif name == "xero.list_quotes":
            quotes = accounting_api.get_quotes(tenant_id)
            return {"content": [{"type": "text", "text": json.dumps([q.to_dict() for q in quotes.quotes])}]}

        return {"content": [{"type": "text", "text": f"Tool {name} not implemented"}]}

    except Exception as e:
        logger.error(f"Tool error: {str(e)}")
        return {"content": [{"type": "text", "text": f"Error: {str(e)}"}]}

# Health check
@app.get("/xero/healthz")
def healthz():
    return {"status": "ok"}

# Run the server
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)