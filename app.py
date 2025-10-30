from dotenv import load_dotenv
load_dotenv()
import logging
import os
import json
from typing import Dict, Any
import base64
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
import requests
import uvicorn
from cryptography.fernet import Fernet, InvalidToken
from xero_python.accounting import AccountingApi, Contact, Contacts, BankTransaction, BankTransactions, Journal, Payment, Quote, Account, Organisation
from xero_python.api_client import ApiClient
from xero_python.api_client.oauth2 import OAuth2Token
from xero_python.api_client.configuration import Configuration
from urllib.parse import urlencode
from jose import jwt, JWTError
from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx

# ---- Safe JSON serialization helpers ----
from datetime import date, datetime
from decimal import Decimal
from uuid import UUID
from enum import Enum
import random

def _json_default(o):
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    if isinstance(o, Decimal):
        return float(o)
    if isinstance(o, UUID):
        return str(o)
    if isinstance(o, Enum):
        # Prefer value if it's simple, otherwise name
        return o.value if isinstance(o.value, (str, int, float, bool, type(None))) else o.name
    to_dict = getattr(o, "to_dict", None)
    if callable(to_dict):
        return to_dict()
    raise TypeError(f"Object of type {type(o).__name__} is not JSON serializable")

def safe_dumps(obj) -> str:
    return json.dumps(obj, default=_json_default, ensure_ascii=False)

# ---- Argument helpers ----
def _get_arg(args: Dict[str, Any], *names, default=None):
    for name in names:
        if name in args:
            return args[name]
        # also try snake/camel variants
        alt = name.replace("_", "")
        for k in args.keys():
            if k.replace("_", "").lower() == alt.lower():
                return args[k]
    return default

def _parse_iso_date(date_str: str):
    try:
        return datetime.fromisoformat(date_str).date()
    except Exception:
        return None

def _parse_iso_datetime(dt_str: str):
    try:
        return datetime.fromisoformat(dt_str.replace("Z", "+00:00"))
    except Exception:
        d = _parse_iso_date(dt_str)
        if d:
            return datetime(d.year, d.month, d.day)
        return None

def _xero_where_date_range(date_from: Any = None, date_to: Any = None) -> str:
    parts = []
    if date_from:
        if isinstance(date_from, str):
            date_from = _parse_iso_date(date_from)
        if isinstance(date_from, (date, datetime)):
            parts.append(f"Date >= DateTime({date_from.year},{date_from.month},{date_from.day})")
    if date_to:
        if isinstance(date_to, str):
            date_to = _parse_iso_date(date_to)
        if isinstance(date_to, (date, datetime)):
            parts.append(f"Date <= DateTime({date_to.year},{date_to.month},{date_to.day})")
    return " && ".join(parts)

def _xero_where_date_field(field: str, date_from: Any = None, date_to: Any = None) -> str:
    parts = []
    if date_from:
        if isinstance(date_from, str):
            date_from = _parse_iso_date(date_from)
        if isinstance(date_from, (date, datetime)):
            parts.append(f"{field} >= DateTime({date_from.year},{date_from.month},{date_from.day})")
    if date_to:
        if isinstance(date_to, str):
            date_to = _parse_iso_date(date_to)
        if isinstance(date_to, (date, datetime)):
            parts.append(f"{field} <= DateTime({date_to.year},{date_to.month},{date_to.day})")
    return " && ".join(parts)

def _xero_where_contact(contact_id: str | None) -> str:
    if contact_id:
        return f'Contact.ContactID==Guid("{contact_id}")'
    return ""

def _join_where(*clauses: str) -> str | None:
    parts = [c for c in clauses if c]
    return " && ".join(parts) if parts else None

def _invoice_country(inv) -> str | None:
    try:
        c = getattr(inv, "contact", None)
        if not c:
            return None

        # Check if contact has country directly (as user suggested)
        country = getattr(c, "country", None)
        if country and country.strip():
            return country.strip()

        # Fallback: check addresses if no direct country on contact
        addrs = getattr(c, "addresses", None) or []
        for addr in addrs:
            country = getattr(addr, "country", None)
            if country and country.strip():
                return country.strip()

        # No country found
        return None
    except Exception:
        return None

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Environment variables
XERO_CLIENT_ID = os.environ.get("XERO_CLIENT_ID")
XERO_CLIENT_SECRET = os.environ.get("XERO_CLIENT_SECRET")
XERO_REDIRECT_URI = os.environ.get("XERO_REDIRECT_URI")
XERO_SCOPES = os.environ.get("XERO_SCOPES")

# Encryption setup
TOKEN_ENC_KEY = os.environ.get("TOKEN_ENC_KEY") # Base64-encoded 32-byte key
TOKEN_STORE_PATH = os.environ.get("TOKEN_STORE_PATH", ".xero_tokens.enc")
TENANT_FILE = "tenant_id.txt" # Plain for simplicity; encrypt if needed
if not TOKEN_ENC_KEY:
    logger.warning("TOKEN_ENC_KEY not set; tokens will not be encrypted!")
fernet = Fernet(TOKEN_ENC_KEY) if TOKEN_ENC_KEY else None

# Auth0 configuration
AUTH0_DOMAIN = os.environ.get("AUTH0_DOMAIN") # e.g., "your-tenant.us.auth0.com"
AUTH0_AUDIENCE = os.environ.get("AUTH0_AUDIENCE") # e.g., "https://mcp.backyardbrains.com/xero"
AUTH0_CLIENT_ID = os.environ.get("AUTH0_CLIENT_ID") # accept ID tokens for this client when audience isn't available
AUTH0_CLIENT_SECRET = os.environ.get("AUTH0_CLIENT_SECRET") #
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
        last_error = None
        # Try validating as API access token first (with audience)
        if AUTH0_AUDIENCE:
            try:
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
                last_error = e
        # Try validating as ID token for our client (aud == client_id)
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
        # Fallback: accept tokens with correct issuer and signature, without audience, if azp matches our client
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
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token validation error: {str(e)}")

def require_auth(creds: HTTPAuthorizationCredentials = Depends(security)):
    if creds is None or creds.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=401,
            detail="Authorization required",
            headers={
                "WWW-Authenticate": (
                'Bearer '
                'resource_metadata="https://mcp.backyardbrains.com/.well-known/oauth-protected-resource/xero/", '
                'scope="read:xero"'
                )
            },
        )

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
    # Ensure an absolute expiry timestamp is present to avoid eager refreshes
    try:
        if tokens and "expires_at" not in tokens and "expires_in" in tokens:
            # Compute approximate wall-clock expiry; add small safety margin
            import time
            tokens = {**tokens, "expires_at": int(time.time()) + int(tokens["expires_in"]) - 60}
    except Exception:
        pass
    data = safe_dumps(tokens).encode('utf-8')
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

## removed duplicate get_xero_client (see singleton version below)

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

app = FastAPI() # Define app here, after helpers but before routes

@app.get("/xero/auth")
def xero_auth():
    if not XERO_CLIENT_ID or not XERO_CLIENT_SECRET:
        raise HTTPException(status_code=400, detail="Xero credentials not configured")
   
    params = {
        "client_id": XERO_CLIENT_ID,
        "response_type": "code",
        "scope": XERO_SCOPES,
        "redirect_uri": XERO_REDIRECT_URI,
        "state": "123" # Add proper state handling in production
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
                "description": "List or summarize invoices with filters (date, contact, status) and grouping.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dateFrom": {"type": "string", "description": "ISO date start (YYYY-MM-DD)"},
                        "dateTo": {"type": "string", "description": "ISO date end (YYYY-MM-DD)"},
                        "contactId": {"type": "string", "description": "Xero ContactID (UUID)"},
                        "statuses": {"type": "array", "items": {"type": "string"}, "description": "Invoice statuses (e.g., AUTHORISED, PAID)"},
                        "order": {"type": "string", "description": "Order clause, e.g. Date DESC"},
                        "page": {"type": "integer", "minimum": 1, "description": "Page number (Xero pagination)"},
                        "summarizeBy": {"type": "string", "enum": ["product", "quarter", "month", "year"], "description": "DEPRECATED: use groupBy for multiple dimensions"},
                        "groupBy": {"type": "array", "items": {"type": "string", "enum": ["product", "country", "customer", "status", "month", "quarter", "year"]}, "description": "Group results by one or more dimensions"},
                        "metrics": {"type": "array", "items": {"type": "string", "enum": ["countInvoices", "quantity", "subtotal", "tax", "total", "amountDue"]}, "description": "Metrics to compute per group"},
                        "itemCodes": {"type": "array", "items": {"type": "string"}, "description": "Only include line items with these item codes"},
                        "includeLineItems": {"type": "boolean", "description": "Return full line items in results (when not summarizing)"}
                    }
                },
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["read:xero"] }
                ]
            },
            {
                "name": "xero.get_balance_sheet",
                "description": "Retrieve Balance Sheet with optional parameters.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "date": {"type": "string", "description": "Report date (YYYY-MM-DD)"},
                        "periods": {"type": "integer", "description": "Number of periods"},
                        "timeframe": {"type": "string", "enum": ["MONTH", "QUARTER", "YEAR"], "description": "Period granularity"},
                        "trackingCategoryID": {"type": "string", "description": "Tracking Category ID (UUID)"},
                        "trackingOptionID": {"type": "string", "description": "Tracking Option ID (UUID)"},
                        "standardLayout": {"type": "boolean"},
                        "paymentsOnly": {"type": "boolean"}
                    }
                },
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["read:xero"] }
                ]
            },
            {
                "name": "xero.list_contacts",
                "description": "Retrieve contacts with optional filters and pagination.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "searchTerm": {"type": "string", "description": "Search across name/email/etc."},
                        "page": {"type": "integer", "minimum": 1},
                        "modifiedSince": {"type": "string", "description": "Only contacts updated since this ISO datetime"},
                        "includeArchived": {"type": "boolean"},
                        "summaryOnly": {"type": "boolean"},
                        "isCustomer": {"type": "boolean"},
                        "isSupplier": {"type": "boolean"}
                    }
                },
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["read:xero"] }
                ]
            },
            {
                "name": "xero.create_contacts",
                "description": "Creates one or more contacts",
                "inputSchema": {"type": "object", "properties": {"contacts": {"type": "array"}}},
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["write:xero"] }
                ]
            },
            {
                "name": "xero.list_bank_transactions",
                "description": "Retrieve bank transactions with filters.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dateFrom": {"type": "string", "description": "Start date (YYYY-MM-DD)"},
                        "dateTo": {"type": "string", "description": "End date (YYYY-MM-DD)"},
                        "accountId": {"type": "string", "description": "Bank AccountID (UUID)"},
                        "order": {"type": "string", "description": "Order clause"},
                        "page": {"type": "integer", "minimum": 1}
                    }
                },
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["read:xero"] }
                ]
            },
            {
                "name": "xero.create_bank_transactions",
                "description": "Creates one or more bank transactions",
                "inputSchema": {"type": "object", "properties": {"bank_transactions": {"type": "array"}}},
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["write:xero"] }
                ]
            },
            {
                "name": "xero.list_accounts",
                "description": "Retrieves the full chart of accounts",
                "inputSchema": {"type": "object", "properties": {}},
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["read:xero"] }
                ]
            },
            {
                "name": "xero.list_journals",
                "description": "Retrieve journals with date filters.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dateFrom": {"type": "string", "description": "JournalDate start (YYYY-MM-DD)"},
                        "dateTo": {"type": "string", "description": "JournalDate end (YYYY-MM-DD)"},
                        "order": {"type": "string"},
                        "page": {"type": "integer", "minimum": 1}
                    }
                },
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["read:xero"] }
                ]
            },
            {
                "name": "xero.list_organisations",
                "description": "Retrieves Xero organisation details",
                "inputSchema": {"type": "object", "properties": {}},
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["read:xero"] }
                ]
            },
            {
                "name": "xero.list_payments",
                "description": "Retrieve payments with optional filters.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "modifiedSince": {"type": "string", "description": "Only payments updated since this ISO datetime"},
                        "dateFrom": {"type": "string", "description": "Payment date start (YYYY-MM-DD)"},
                        "dateTo": {"type": "string", "description": "Payment date end (YYYY-MM-DD)"},
                        "invoiceId": {"type": "string", "description": "InvoiceID to filter (UUID)"},
                        "accountId": {"type": "string", "description": "AccountID to filter (UUID)"},
                        "isReconciled": {"type": "boolean"},
                        "order": {"type": "string"},
                        "page": {"type": "integer", "minimum": 1}
                    }
                },
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["read:xero"] }
                ]
            },
            {
                "name": "xero.get_sales_by_product",
                "description": "Get sales and quantity sold by product for a date range. Filters for sales revenue accounts only (default: account 4000). Perfect for analyzing product performance.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dateFrom": {"type": "string", "description": "Start date (YYYY-MM-DD) - e.g., '2025-07-01' for Q3 2025"},
                        "dateTo": {"type": "string", "description": "End date (YYYY-MM-DD) - e.g., '2025-09-30' for Q3 2025"},
                        "itemCodes": {"type": "array", "items": {"type": "string"}, "description": "Specific item codes to include (optional)"},
                        "groupByTime": {"type": "string", "enum": ["month", "quarter", "year"], "description": "Also group by time period (optional)"},
                        "accountCodes": {"type": "array", "items": {"type": "string"}, "description": "Account codes to include (default: ['4000'] for sales revenue)"}
                    }
                },
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["read:xero"] }
                ]
            },
            {
                "name": "xero.get_sales_by_country",
                "description": "Get sales revenue and invoice counts by customer country for a date range. Filters for sales revenue accounts only (default: account 4000). Perfect for geographic analysis.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dateFrom": {"type": "string", "description": "Start date (YYYY-MM-DD) - e.g., '2025-07-01' for Q3 2025"},
                        "dateTo": {"type": "string", "description": "End date (YYYY-MM-DD) - e.g., '2025-09-30' for Q3 2025"},
                        "groupByTime": {"type": "string", "enum": ["month", "quarter", "year"], "description": "Also group by time period (optional)"},
                        "accountCodes": {"type": "array", "items": {"type": "string"}, "description": "Account codes to include (default: ['4000'] for sales revenue)"}
                    }
                },
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["read:xero"] }
                ]
            },
            {
                "name": "xero.list_quotes",
                "description": "Retrieve quotes with optional filters.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dateFrom": {"type": "string", "description": "Quote date start (YYYY-MM-DD)"},
                        "dateTo": {"type": "string", "description": "Quote date end (YYYY-MM-DD)"},
                        "expiryDateFrom": {"type": "string", "description": "Expiry date start (YYYY-MM-DD)"},
                        "expiryDateTo": {"type": "string", "description": "Expiry date end (YYYY-MM-DD)"},
                        "contactId": {"type": "string", "description": "ContactID (UUID)"},
                        "statuses": {"type": "array", "items": {"type": "string"}},
                        "order": {"type": "string"},
                        "page": {"type": "integer", "minimum": 1}
                    }
                },
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["read:xero"] }
                ]
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

# ---- OIDC Discovery passthrough for Auth0 (unauthenticated) ----

# --- Protected Resource Metadata (RFC 9728) ---
PRM = {
    "resource": "https://mcp.backyardbrains.com/xero/", 
    "authorization_servers": [f"https://{AUTH0_DOMAIN}/"],  # issuer has trailing slash
    "scopes_supported": ["read:xero", "write:xero"],
    "bearer_methods_supported": ["header"],
}

@app.get("/.well-known/oauth-protected-resource")
def prm_root():
    return JSONResponse(PRM)

@app.get("/.well-known/oauth-protected-resource/xero")
def prm_for_xero():
    return JSONResponse(PRM)

@app.get("/.well-known/oauth-protected-resource/xero/")
def prm_for_xero_slash():
    return JSONResponse(PRM)

@app.get("/xero/.well-known/openid-configuration")
def oidc_discovery():
    if not AUTH0_ISSUER:
        raise HTTPException(status_code=500, detail="Auth0 not configured")
    url = f"{AUTH0_ISSUER}.well-known/openid-configuration"
    try:
        resp = requests.get(url, timeout=5)
        return JSONResponse(status_code=resp.status_code, content=resp.json())
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"Discovery fetch failed: {str(e)}")

# Accept accidental double-slash variant some clients probe
@app.get("/xero//.well-known/openid-configuration")
def oidc_discovery_double_slash():
    return oidc_discovery()

@app.get("/xero/.well-known/jwks.json")
def oidc_jwks():
    if not AUTH0_ISSUER:
        raise HTTPException(status_code=500, detail="Auth0 not configured")
    url = f"{AUTH0_ISSUER}.well-known/jwks.json"
    try:
        resp = requests.get(url, timeout=5)
        return JSONResponse(status_code=resp.status_code, content=resp.json())
    except Exception as e:
        raise HTTPException(status_code=502, detail=f"JWKS fetch failed: {str(e)}")

# Test MCP endpoint without authentication (for testing only)
@app.post("/xero/test-mcp")
async def test_mcp_endpoint(request: Request):
    """Test MCP endpoint without authentication for debugging"""
    return await mcp_endpoint(request)

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

# Proxy for /authorize to add audience
AUTH0_AUTHORIZE_URL = f"https://{AUTH0_DOMAIN}/authorize"
AUTH0_TOKEN_URL = f"https://{AUTH0_DOMAIN}/oauth/token"

@app.get("/xero/authorize")
async def authorize_proxy(request: Request):
    # Append audience to the query params from ChatGPT
    query_params = dict(request.query_params)
    if AUTH0_AUDIENCE:
        query_params["audience"] = AUTH0_AUDIENCE
    auth_url = f"{AUTH0_AUTHORIZE_URL}?{urlencode(query_params)}"
    return RedirectResponse(url=auth_url)

@app.post("/xero/token")
async def token_proxy(request: Request):
    # Forward the token request as-is to Auth0
    form_data = await request.form()
    async with httpx.AsyncClient() as client:
        response = await client.post(
            AUTH0_TOKEN_URL,
            data=form_data,
            auth=(AUTH0_CLIENT_ID, AUTH0_CLIENT_SECRET) if "client_id" not in form_data else None  # Handle if creds are in body
        )
        if response.status_code != 200:
            raise HTTPException(status_code=response.status_code, detail="Token exchange failed")
        return response.json()

def _token_getter():
    # Return the token dict you stored from /xero/callback
    return load_tokens() or {}

def _token_saver(token):
    """
    Xero SDK calls this after refresh. It passes a dict in modern versions.
    Persist exactly what you get so future calls use the newest refresh_token.
    """
    # In some versions token may be an OAuth2Token; normalize to dict
    try:
        if isinstance(token, OAuth2Token):
            # Prefer internal dict if present
            token = getattr(token, "token", {
                "access_token": getattr(token, "access_token", None),
                "refresh_token": getattr(token, "refresh_token", None),
                "expires_at": getattr(token, "expires_at", None),
                "scope": getattr(token, "scope", None),
                "token_type": getattr(token, "token_type", "Bearer"),
            })
    except Exception:
        pass
    save_tokens(token)

_xero_api_client = None

def get_xero_client():
    global _xero_api_client
    if _xero_api_client is not None:
        return _xero_api_client

    cfg = Configuration(
        oauth2_token=OAuth2Token(client_id=XERO_CLIENT_ID, client_secret=XERO_CLIENT_SECRET),
        debug=False,
    )
    client = ApiClient(configuration=cfg)

    # Register persistence callbacks (required for refresh)
    @client.oauth2_token_getter
    def _getter():
        return _token_getter()

    @client.oauth2_token_saver
    def _saver(token):
        _token_saver(token)

    # Preload the current token set onto the client
    tok = load_tokens()
    if tok:
        try:
            client.set_oauth2_token(tok)
        except TypeError:
            client.set_oauth2_token(tok["access_token"])

    _xero_api_client = client
    return _xero_api_client

async def _process_invoices_with_grouping(accounting_api, tenant_id, args: Dict) -> Dict:
    """Common invoice processing logic with grouping and aggregation."""
    # Parse filters
    date_from = _get_arg(args, "dateFrom", "date_from")
    date_to = _get_arg(args, "dateTo", "date_to")
    contact_id = _get_arg(args, "contactId", "contact_id")
    statuses = _get_arg(args, "statuses")
    order = _get_arg(args, "order")
    page = _get_arg(args, "page")
    summarize_by = _get_arg(args, "summarizeBy", "summarize_by")
    group_by = _get_arg(args, "groupBy", "group_by")
    metrics = _get_arg(args, "metrics")
    item_codes = _get_arg(args, "itemCodes", "item_codes")
    account_codes = _get_arg(args, "accountCodes", "account_codes")
    include_line_items = bool(_get_arg(args, "includeLineItems", "include_line_items", default=True))

    where = _join_where(
        _xero_where_date_range(date_from, date_to),
        _xero_where_contact(contact_id),
        ("(" + " || ".join([f'Status=="{s}"' for s in statuses]) + ")") if isinstance(statuses, list) and statuses else ""
    )

    inv_kwargs = {}
    if where:
        inv_kwargs["where"] = where
    if order:
        inv_kwargs["order"] = order
    if page:
        inv_kwargs["page"] = page
    # Ensure line items are included for product-level aggregation
    inv_kwargs["summary_only"] = False
    logger.info(f"Fetching invoices with filters: {inv_kwargs}")
    invoices = accounting_api.get_invoices(tenant_id, **inv_kwargs)

    inv_objs = invoices.invoices or []
    logger.info(f"Found {len(inv_objs)} total invoices")

    # Log invoice types and statuses for debugging
    sales_invoices = [inv for inv in inv_objs if getattr(inv, "type", None) == "ACCREC"]
    logger.info(f"Found {len(sales_invoices)} sales invoices (ACCREC)")
    if sales_invoices:
        statuses = [getattr(inv, "status", "UNKNOWN") for inv in sales_invoices]
        logger.info(f"Sales invoice statuses: {set(statuses)}")

    # Get full contact details for all unique contacts in the invoices
    contact_ids = list(set(
        getattr(getattr(inv, "contact", None), "contact_id", None)
        for inv in sales_invoices
        if getattr(inv, "contact", None)
    ))
    contact_ids = [cid for cid in contact_ids if cid]  # Remove None values

    # Fetch full contact details
    full_contacts = {}
    if contact_ids:
        try:
            # Xero API might have limits on number of IDs, so let's fetch in batches
            batch_size = 50  # Reasonable batch size
            for i in range(0, len(contact_ids), batch_size):
                batch_ids = contact_ids[i:i + batch_size]
                try:
                    contacts_response = accounting_api.get_contacts(
                        tenant_id,
                        i_ds=batch_ids,
                        summary_only=False
                    )
                    for contact in contacts_response.contacts or []:
                        full_contacts[contact.contact_id] = contact
                except Exception as batch_error:
                    logger.warning(f"Failed to fetch contact batch {i//batch_size + 1}: {batch_error}")
        except Exception as e:
            logger.warning(f"Could not fetch full contact details: {e}")
            # Continue without full contacts - use embedded data only

    # Normalize grouping/metrics
    if group_by is None and summarize_by:
        group_by = [summarize_by]
    if isinstance(group_by, str):
        group_by = [group_by]
    if not isinstance(group_by, list):
        group_by = []
    if not metrics:
        # default metrics
        metrics = ["total"] + (["quantity"] if "product" in group_by else [])

    # If no grouping requested, return raw list
    if not group_by:
        if include_line_items:
            return {"content": [{"type": "text", "text": safe_dumps([inv.to_dict() for inv in inv_objs])}]}
        else:
            slim = []
            for inv in inv_objs:
                d = inv.to_dict()
                d.pop("line_items", None)
                slim.append(d)
            return {"content": [{"type": "text", "text": safe_dumps(slim)}]}

    # Summaries with grouping
    # Consider only sales invoices (ACCREC)
    sales = [inv for inv in inv_objs if getattr(inv, "type", None) == "ACCREC"]

    # For product grouping, we need full invoice details with line items
    # The filtered get_invoices call doesn't include line items, so fetch them individually
    if "product" in group_by:
        full_invoices = {}
        invoice_ids = [getattr(inv, "invoice_id", None) for inv in sales if getattr(inv, "invoice_id", None)]

        # Fetch invoices in batches to avoid API limits
        batch_size = 10
        for i in range(0, len(invoice_ids), batch_size):
            batch_ids = invoice_ids[i:i + batch_size]
            try:
                batch_invoices = accounting_api.get_invoices(
                    tenant_id,
                    i_ds=batch_ids,
                    summary_only=False
                )
                for inv in batch_invoices.invoices or []:
                    full_invoices[inv.invoice_id] = inv
            except Exception as e:
                logger.warning(f"Error fetching invoice batch {i//batch_size + 1}: {e}")

        # Replace sales list with full invoice details
        sales = [full_invoices.get(getattr(inv, "invoice_id"), inv) for inv in sales]

    def _date_parts(dval: datetime | date | None):
        if not dval:
            return None, None, None
        if isinstance(dval, datetime):
            dval = dval.date()
        y, m = dval.year, dval.month
        q = (m - 1)//3 + 1
        return y, m, q

    def _invoice_country(inv) -> str | None:
        try:
            c = getattr(inv, "contact", None)
            if not c:
                return None

            contact_id = getattr(c, "contact_id", None)

            # Try to get full contact details first
            full_contact = full_contacts.get(contact_id) if contact_id else None
            if full_contact:
                # Check if full contact has country directly
                country = getattr(full_contact, "country", None)
                if country and country.strip():
                    return country.strip()

                # Check addresses in full contact
                addrs = getattr(full_contact, "addresses", None) or []
                for addr in addrs:
                    country = getattr(addr, "country", None)
                    if country and country.strip():
                        return country.strip()

            # Fallback to invoice-embedded contact data
            country = getattr(c, "country", None)
            if country and country.strip():
                return country.strip()

            # Fallback: check addresses if no direct country on contact
            addrs = getattr(c, "addresses", None) or []
            for addr in addrs:
                country = getattr(addr, "country", None)
                if country and country.strip():
                    return country.strip()

            # No country found
            return None
        except Exception:
            return None

    def _group_key_for_invoice(inv):
        y, m, q = _date_parts(getattr(inv, "date", None))
        mapping = {
            "customer": getattr(getattr(inv, "contact", None), "name", None),
            "status": getattr(inv, "status", None),
            "year": f"{y}" if y else None,
            "month": f"{y}-{m:02d}" if y and m else None,
            "quarter": f"{y}-Q{q}" if y and q else None,
            "country": _invoice_country(inv),
        }
        return {k: mapping.get(k) for k in group_by if k != "product"}

    def _group_key_for_line_item(inv, li):
        base = _group_key_for_invoice(inv)
        if "product" in group_by:
            item_code = getattr(li, "item_code", None)
            description = getattr(li, "description", None)
            if item_code and description:
                prod = f"{item_code} - {description}"
            elif item_code:
                prod = item_code
            elif description:
                prod = description
            else:
                prod = "UNKNOWN"
            base = dict(base)
            base["product"] = prod
        return base

    # Aggregation buckets
    buckets = {}

    def _ensure_bucket(key_dict):
                key_tuple = tuple((k, key_dict.get(k)) for k in group_by)
                if key_tuple not in buckets:
                    buckets[key_tuple] = {
                        "group": {k: key_dict.get(k) for k in group_by},
                        "metrics": {m: 0.0 for m in metrics},
                        "_invoice_ids": set() if "countInvoices" in metrics and ("product" in group_by or account_codes) else None,
                    }
                return buckets[key_tuple]

    if "product" in group_by or account_codes:
        # Line-item-level aggregation (used for product grouping or account code filtering)
        for inv in sales:
            line_items = getattr(inv, "line_items", []) or []
            for li in line_items:
                # Filter by item codes if specified
                if item_codes:
                    code = getattr(li, "item_code", None)
                    if code not in item_codes:
                        # allow matching by description too if codes don't match
                        desc = getattr(li, "description", None) or ""
                        if not any(str(code_or_name).lower() in desc.lower() for code_or_name in item_codes):
                            continue

                # Filter by account codes if specified (for sales revenue filtering)
                if account_codes:
                    account_code = getattr(li, "account_code", None)
                    if account_code not in account_codes:
                        continue

                # For product grouping, only include line items with valid item codes
                # This matches Xero's behavior where Sales by Item report only shows items with codes
                if "product" in group_by:
                    item_code = getattr(li, "item_code", None)
                    if not item_code or not str(item_code).strip():
                        continue

                key = _group_key_for_line_item(inv, li)
                b = _ensure_bucket(key)
                # Metrics
                if "quantity" in metrics:
                    b["metrics"]["quantity"] += float(getattr(li, "quantity", 0) or 0)
                if "total" in metrics:
                    b["metrics"]["total"] += float(getattr(li, "line_amount", 0) or 0)
                if "subtotal" in metrics:
                    b["metrics"]["subtotal"] += float(getattr(li, "line_amount", 0) or 0)
                if "tax" in metrics:
                    # Line item tax not always present; skip or estimate 0
                    b["metrics"]["tax"] += float(getattr(li, "tax_amount", 0) or 0)
                if "amountDue" in metrics:
                    # Not meaningful at line level; skip
                    pass
                if "countInvoices" in metrics and b.get("_invoice_ids") is not None and getattr(inv, "invoice_id", None) is not None:
                    b["_invoice_ids"].add(getattr(inv, "invoice_id", None))
    else:
        # Invoice-level aggregation
        for inv in sales:
            key = _group_key_for_invoice(inv)
            b = _ensure_bucket(key)
            if "countInvoices" in metrics:
                b["metrics"]["countInvoices"] += 1
            if "total" in metrics:
                b["metrics"]["total"] += float(getattr(inv, "total", 0) or 0)
            if "subtotal" in metrics:
                b["metrics"]["subtotal"] += float(getattr(inv, "sub_total", 0) or 0)
            if "tax" in metrics:
                b["metrics"]["tax"] += float(getattr(inv, "total_tax", 0) or 0)
            if "amountDue" in metrics:
                b["metrics"]["amountDue"] += float(getattr(inv, "amount_due", 0) or 0)

    # Finalize invoice counts
    rows = []
    for _, entry in buckets.items():
        if entry.get("_invoice_ids") is not None and "countInvoices" in metrics:
            entry["metrics"]["countInvoices"] = float(len(entry["_invoice_ids"]))
            entry.pop("_invoice_ids", None)
        rows.append({"group": entry["group"], "metrics": entry["metrics"]})

    result = {"groupBy": group_by, "metrics": metrics, "rows": rows}
    return {"content": [{"type": "text", "text": safe_dumps(result)}]}

async def handle_tool_call(name: str, args: Dict):
    try:
        # Proactively refresh if the stored token is expired
        try:
            import time
            tokens = load_tokens()
            if tokens and int(tokens.get("expires_at", 0)) <= int(time.time()):
                refresh_token_if_needed()
        except Exception as e:
            logger.warning(f"Token refresh check failed: {e}")

        api_client = get_xero_client()
        # Ensure the client holds the latest tokens (in case a refresh just occurred)
        tok = load_tokens()
        if tok:
            try:
                api_client.set_oauth2_token(tok)
            except TypeError:
                api_client.set_oauth2_token(tok["access_token"])
        tenant_id = load_tenant_id()
        if not tenant_id:
            return {"content": [{"type": "text", "text": "No tenant ID configured. Authenticate first."}]}
        accounting_api = AccountingApi(api_client)

        if name == "xero.list_invoices":
            return await _process_invoices_with_grouping(accounting_api, tenant_id, args)
        elif name == "xero.get_balance_sheet":
            # Optional parameters
            bs_date = _get_arg(args, "date")
            bs_periods = _get_arg(args, "periods")
            bs_timeframe = _get_arg(args, "timeframe")
            bs_tc = _get_arg(args, "trackingCategoryID", "tracking_category_id")
            bs_to = _get_arg(args, "trackingOptionID", "tracking_option_id")
            bs_std = _get_arg(args, "standardLayout", "standard_layout")
            bs_pay = _get_arg(args, "paymentsOnly", "payments_only")

            # Convert date if provided
            if isinstance(bs_date, str):
                d = _parse_iso_date(bs_date)
                bs_date = d.isoformat() if d else None

            bs_kwargs = {}
            if bs_date is not None:
                bs_kwargs["date"] = bs_date
            if bs_periods is not None:
                bs_kwargs["periods"] = bs_periods
            if bs_timeframe is not None:
                bs_kwargs["timeframe"] = bs_timeframe
            if bs_tc is not None:
                bs_kwargs["tracking_category_id"] = bs_tc
            if bs_to is not None:
                bs_kwargs["tracking_option_id"] = bs_to
            if bs_std is not None:
                bs_kwargs["standard_layout"] = bs_std
            if bs_pay is not None:
                bs_kwargs["payments_only"] = bs_pay

            balance_sheet = accounting_api.get_report_balance_sheet(tenant_id, **bs_kwargs)
            return {"content": [{"type": "text", "text": safe_dumps([rep.to_dict() for rep in balance_sheet.reports])}]}
        elif name == "xero.list_contacts":
            search_term = _get_arg(args, "searchTerm", "search_term")
            page = _get_arg(args, "page")
            modified_since = _get_arg(args, "modifiedSince", "modified_since")
            include_archived = _get_arg(args, "includeArchived", "include_archived")
            summary_only = _get_arg(args, "summaryOnly", "summary_only")
            is_customer = _get_arg(args, "isCustomer", "is_customer")
            is_supplier = _get_arg(args, "isSupplier", "is_supplier")

            # If-Modified-Since header value
            ims = None
            if isinstance(modified_since, str):
                ims = _parse_iso_datetime(modified_since)

            where_clauses = []
            if isinstance(is_customer, bool):
                where_clauses.append(f"IsCustomer=={str(is_customer).lower()}")
            if isinstance(is_supplier, bool):
                where_clauses.append(f"IsSupplier=={str(is_supplier).lower()}")
            where = " && ".join(where_clauses) if where_clauses else None

            c_kwargs = {}
            if ims is not None:
                c_kwargs["if_modified_since"] = ims
            if where:
                c_kwargs["where"] = where
            if page:
                c_kwargs["page"] = page
            if include_archived is not None:
                c_kwargs["include_archived"] = include_archived
            if summary_only is not None:
                c_kwargs["summary_only"] = summary_only
            if search_term:
                c_kwargs["search_term"] = search_term

            contacts = accounting_api.get_contacts(tenant_id, **c_kwargs)
            return {"content": [{"type": "text", "text": safe_dumps([c.to_dict() for c in contacts.contacts])}]}
        elif name == "xero.create_contacts":
            contacts_data = args.get('contacts', [])
            contacts_obj = Contacts(contacts=[Contact(**data) for data in contacts_data])
            created = accounting_api.create_contacts(tenant_id, contacts_obj)
            return {"content": [{"type": "text", "text": safe_dumps([c.to_dict() for c in created.contacts])}]}
        elif name == "xero.list_bank_transactions":
            bt_date_from = _get_arg(args, "dateFrom", "date_from")
            bt_date_to = _get_arg(args, "dateTo", "date_to")
            bt_account_id = _get_arg(args, "accountId", "account_id")
            bt_order = _get_arg(args, "order")
            bt_page = _get_arg(args, "page")

            where = _join_where(
                _xero_where_date_field("Date", bt_date_from, bt_date_to),
                (f'BankAccount.AccountID==Guid("{bt_account_id}")' if bt_account_id else "")
            )

            bt_kwargs = {}
            if where:
                bt_kwargs["where"] = where
            if bt_order:
                bt_kwargs["order"] = bt_order
            if bt_page:
                bt_kwargs["page"] = bt_page

            transactions = accounting_api.get_bank_transactions(tenant_id, **bt_kwargs)
            return {"content": [{"type": "text", "text": safe_dumps([t.to_dict() for t in transactions.bank_transactions])}]}
        elif name == "xero.create_bank_transactions":
            bank_transactions_data = args.get('bank_transactions', [])
            bank_transactions_obj = BankTransactions(bank_transactions=[BankTransaction(**data) for data in bank_transactions_data])
            created = accounting_api.create_bank_transactions(tenant_id, bank_transactions_obj)
            return {"content": [{"type": "text", "text": safe_dumps([t.to_dict() for t in created.bank_transactions])}]}
        elif name == "xero.list_accounts":
            accounts = accounting_api.get_accounts(tenant_id)
            return {"content": [{"type": "text", "text": safe_dumps([a.to_dict() for a in accounts.accounts])}]}
        elif name == "xero.list_journals":
            j_date_from = _get_arg(args, "dateFrom", "date_from")
            j_date_to = _get_arg(args, "dateTo", "date_to")
            j_order = _get_arg(args, "order")
            j_page = _get_arg(args, "page")

            where = _xero_where_date_field("JournalDate", j_date_from, j_date_to)
            j_kwargs = {}
            if where:
                j_kwargs["where"] = where
            if j_order:
                j_kwargs["order"] = j_order
            if j_page:
                j_kwargs["page"] = j_page
            journals = accounting_api.get_journals(tenant_id, **j_kwargs)
            return {"content": [{"type": "text", "text": safe_dumps([j.to_dict() for j in journals.journals])}]}
        elif name == "xero.list_organisations":
            organisations = accounting_api.get_organisations(tenant_id)
            return {"content": [{"type": "text", "text": safe_dumps([o.to_dict() for o in organisations.organisations])}]}
        elif name == "xero.list_payments":
            ps_modified_since = _get_arg(args, "modifiedSince", "modified_since")
            ps_date_from = _get_arg(args, "dateFrom", "date_from")
            ps_date_to = _get_arg(args, "dateTo", "date_to")
            ps_invoice_id = _get_arg(args, "invoiceId", "invoice_id")
            ps_account_id = _get_arg(args, "accountId", "account_id")
            ps_is_reconciled = _get_arg(args, "isReconciled", "is_reconciled")
            ps_order = _get_arg(args, "order")
            ps_page = _get_arg(args, "page")

            ims = None
            if isinstance(ps_modified_since, str):
                ims = _parse_iso_datetime(ps_modified_since)

            where = _join_where(
                _xero_where_date_field("Date", ps_date_from, ps_date_to),
                (f'Invoice.InvoiceID==Guid("{ps_invoice_id}")' if ps_invoice_id else ""),
                (f'Account.AccountID==Guid("{ps_account_id}")' if ps_account_id else ""),
                (f"IsReconciled=={str(bool(ps_is_reconciled)).lower()}" if isinstance(ps_is_reconciled, bool) else "")
            )

            pay_kwargs = {}
            if ims is not None:
                pay_kwargs["if_modified_since"] = ims
            if where:
                pay_kwargs["where"] = where
            if ps_order:
                pay_kwargs["order"] = ps_order
            if ps_page:
                pay_kwargs["page"] = ps_page

            payments = accounting_api.get_payments(tenant_id, **pay_kwargs)
            return {"content": [{"type": "text", "text": safe_dumps([p.to_dict() for p in payments.payments])}]}
        elif name == "xero.get_sales_by_product":
            # Dedicated tool for sales by product analysis
            date_from = _get_arg(args, "dateFrom", "date_from")
            date_to = _get_arg(args, "dateTo", "date_to")
            item_codes = _get_arg(args, "itemCodes", "item_codes")
            group_by_time = _get_arg(args, "groupByTime", "group_by_time")
            account_codes = _get_arg(args, "accountCodes", "account_codes")
            # Default to sales revenue account 4000 if not specified
            if not account_codes:
                account_codes = ["4000"]

            # Build group_by list
            group_by = ["product"]
            if group_by_time:
                group_by.append(group_by_time)

            # Use the common invoice processing logic with product grouping
            # Include more statuses to ensure we get sales data
            sales_args = {
                "dateFrom": date_from,
                "dateTo": date_to,
                "groupBy": group_by,
                "metrics": ["quantity", "total", "countInvoices"],
                "statuses": ["AUTHORISED", "PAID", "DRAFT", "SUBMITTED"],  # Include more statuses
                "itemCodes": item_codes,
                "accountCodes": account_codes,  # Filter by sales revenue accounts
            }

            return await _process_invoices_with_grouping(accounting_api, tenant_id, sales_args)
        elif name == "xero.get_sales_by_country":
            # Dedicated tool for sales by country analysis
            date_from = _get_arg(args, "dateFrom", "date_from")
            date_to = _get_arg(args, "dateTo", "date_to")
            group_by_time = _get_arg(args, "groupByTime", "group_by_time")
            account_codes = _get_arg(args, "accountCodes", "account_codes")
            # Default to sales revenue account 4000 if not specified
            if not account_codes:
                account_codes = ["4000"]

            # Build group_by list
            group_by = ["country"]
            if group_by_time:
                group_by.append(group_by_time)

            # Use line-item level aggregation to filter by account codes
            # This ensures we only include sales revenue, not all income
            country_args = {
                "dateFrom": date_from,
                "dateTo": date_to,
                "groupBy": group_by,
                "metrics": ["total", "countInvoices"],
                "statuses": ["AUTHORISED", "PAID", "DRAFT", "SUBMITTED"],  # Include more statuses
                "accountCodes": account_codes,  # Filter by sales revenue accounts
            }

            return await _process_invoices_with_grouping(accounting_api, tenant_id, country_args)
        elif name == "xero.list_quotes":
            q_date_from = _get_arg(args, "dateFrom", "date_from")
            q_date_to = _get_arg(args, "dateTo", "date_to")
            q_exp_from = _get_arg(args, "expiryDateFrom", "expiry_date_from")
            q_exp_to = _get_arg(args, "expiryDateTo", "expiry_date_to")
            q_contact_id = _get_arg(args, "contactId", "contact_id")
            q_statuses = _get_arg(args, "statuses")
            q_order = _get_arg(args, "order")
            q_page = _get_arg(args, "page")

            where = _join_where(
                _xero_where_date_field("Date", q_date_from, q_date_to),
                _xero_where_date_field("ExpiryDate", q_exp_from, q_exp_to),
                (f'Contact.ContactID==Guid("{q_contact_id}")' if q_contact_id else ""),
                ("(" + " || ".join([f'Status=="{s}"' for s in q_statuses]) + ")") if isinstance(q_statuses, list) and q_statuses else ""
            )

            q_kwargs = {}
            if where:
                q_kwargs["where"] = where
            if q_order:
                q_kwargs["order"] = q_order
            if q_page:
                q_kwargs["page"] = q_page

            quotes = accounting_api.get_quotes(tenant_id, **q_kwargs)
            return {"content": [{"type": "text", "text": safe_dumps([q.to_dict() for q in quotes.quotes])}]}
        return {"content": [{"type": "text", "text": f"Tool {name} not implemented"}]}
    except Exception as e:
        logger.error(f"Tool error: {str(e)}")
        return {"content": [{"type": "text", "text": f"Error: {str(e)}"}]}

# Health check
@app.get("/xero/healthz")
def healthz():
    return {"status": "ok"}

# Test endpoint for debugging country info (temporary)
@app.get("/xero/test_country_data")
async def test_country_data():
    """Test endpoint to examine country data in invoices for Q3 2025"""
    try:
        api_client = get_xero_client()
        tok = load_tokens()
        if tok:
            try:
                api_client.set_oauth2_token(tok)
            except TypeError:
                api_client.set_oauth2_token(tok["access_token"])

        tenant_id = load_tenant_id()
        if not tenant_id:
            return {"error": "No tenant ID configured"}

        accounting_api = AccountingApi(api_client)

        # Get invoices for Q3 2025
        where = 'Date >= DateTime(2025,7,1) && Date <= DateTime(2025,9,30) && Type=="ACCREC"'
        invoices = accounting_api.get_invoices(tenant_id, where=where, summary_only=False)

        inv_objs = invoices.invoices or []
        sales_invoices = [inv for inv in inv_objs if getattr(inv, "type", None) == "ACCREC"]

        # Get full contact details for country extraction
        contact_ids = list(set(
            getattr(getattr(inv, "contact", None), "contact_id", None)
            for inv in sales_invoices
            if getattr(inv, "contact", None)
        ))
        contact_ids = [cid for cid in contact_ids if cid]  # Remove None values

        # Fetch full contact details
        full_contacts = {}
        if contact_ids:
            try:
                contacts_response = accounting_api.get_contacts(
                    tenant_id,
                    i_ds=contact_ids,  # Get specific contacts by ID
                    summary_only=False  # Get full details
                )
                for contact in contacts_response.contacts or []:
                    full_contacts[contact.contact_id] = contact
                print(f"Fetched full details for {len(full_contacts)} contacts")
            except Exception as e:
                print(f"Warning: Could not fetch full contact details: {e}")

        # Analyze country data
        country_analysis = []
        for inv in sales_invoices[:10]:  # Limit to first 10 for debugging
            inv_dict = inv.to_dict()
            contact = getattr(inv, "contact", None)
            contact_id = getattr(contact, "contact_id", None) if contact else None

            # Try to get full contact details
            full_contact = full_contacts.get(contact_id) if contact_id else None

            country_info = {
                "invoice_id": getattr(inv, "invoice_id", None),
                "invoice_number": getattr(inv, "invoice_number", None),
                "date": getattr(inv, "date", None),
                "total": getattr(inv, "total", None),
                "contact_name": getattr(contact, "name", None) if contact else None,
                "contact_country": getattr(contact, "country", None) if contact else None,
                "has_full_contact": full_contact is not None,
                "addresses": []
            }

            # Check addresses from full contact if available
            if full_contact:
                addresses = getattr(full_contact, "addresses", None) or []
                for addr in addresses:
                    addr_info = {
                        "address_type": getattr(addr, "address_type", None),
                        "country": getattr(addr, "country", None),
                        "city": getattr(addr, "city", None),
                        "region": getattr(addr, "region", None)
                    }
                    country_info["addresses"].append(addr_info)
                    # Also check direct country on full contact
                    if not country_info["contact_country"]:
                        country_info["contact_country"] = getattr(full_contact, "country", None)
            elif contact:
                # Fallback to invoice-embedded contact
                addresses = getattr(contact, "addresses", None) or []
                for addr in addresses:
                    addr_info = {
                        "address_type": getattr(addr, "address_type", None),
                        "country": getattr(addr, "country", None),
                        "city": getattr(addr, "city", None),
                        "region": getattr(addr, "region", None)
                    }
                    country_info["addresses"].append(addr_info)

            country_analysis.append(country_info)

        return {
            "total_sales_invoices": len(sales_invoices),
            "sample_invoices_with_country_info": country_analysis,
            "countries_found": list(set(
                c["contact_country"] for c in country_analysis
                if c["contact_country"] and c["contact_country"].strip()
            ))
        }

    except Exception as e:
        return {"error": str(e)}


# Run the server
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)