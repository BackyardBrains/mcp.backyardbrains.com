from dotenv import load_dotenv
load_dotenv()

import logging
import os
import json
import asyncio
from typing import Dict, Any, Set, List, Tuple
import base64
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import RedirectResponse, JSONResponse
import requests
import uvicorn
from cryptography.fernet import Fernet, InvalidToken
from xero_python.accounting import AccountingApi, Contact, Contacts, BankTransaction, BankTransactions, Journal, ManualJournal, ManualJournals, Payment, Quote, Account, Organisation
from xero_python.api_client import ApiClient
from xero_python.api_client.oauth2 import OAuth2Token
from xero_python.api_client.configuration import Configuration
from urllib.parse import urlencode
from jose import jwt, JWTError
from fastapi import Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import httpx

# Machine Coordination Protocol defaults
MCP_PROTOCOL_VERSION = "2024-11-05"

# ---- Safe JSON serialization helpers ----
from datetime import date, datetime
from decimal import Decimal
from uuid import UUID
from enum import Enum
import random
import re

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


def _as_float(value: Any) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float, Decimal)):
        try:
            return float(value)
        except Exception:
            return None
    if isinstance(value, str):
        cleaned = re.sub(r"[^0-9.\-]", "", value)
        if not cleaned or cleaned in {"-", ".", "-.", ".-"}:
            return None
        try:
            return float(cleaned)
        except ValueError:
            return None
    return None


def _cell_to_dict(cell) -> Dict[str, Any]:
    data = {
        "value": getattr(cell, "value", None),
    }
    text = getattr(cell, "text", None)
    if text is not None and text != data["value"]:
        data["text"] = text
    formula = getattr(cell, "formula", None)
    if formula:
        data["formula"] = formula
    attrs = getattr(cell, "attributes", None)
    if attrs:
        attr_map = {}
        for attr in attrs:
            name = getattr(attr, "name", None)
            value = getattr(attr, "value", None)
            if name:
                attr_map[name.lower()] = value
        if attr_map:
            data["attributes"] = attr_map
    numeric = _as_float(data.get("value"))
    if numeric is not None:
        data["numericValue"] = numeric
    return data


def _row_to_dict(row) -> Dict[str, Any]:
    return {
        "rowType": getattr(row, "row_type", None),
        "title": getattr(row, "title", None),
        "cells": [_cell_to_dict(cell) for cell in (getattr(row, "cells", None) or [])],
        "rows": [_row_to_dict(child) for child in (getattr(row, "rows", None) or [])],
    }


def _report_to_dict(report) -> Dict[str, Any]:
    if report is None:
        return {}
    columns = []
    for idx, col in enumerate(getattr(report, "columns", None) or []):
        columns.append(
            {
                "title": getattr(col, "title", None) or getattr(col, "column_type", None) or f"Column {idx}",
                "columnType": getattr(col, "column_type", None),
            }
        )
    return {
        "reportName": getattr(report, "report_name", None),
        "reportTitle": getattr(report, "report_title", None),
        "reportType": getattr(report, "report_type", None),
        "reportDate": getattr(report, "report_date", None),
        "columns": columns,
        "rows": [_row_to_dict(row) for row in (getattr(report, "rows", None) or [])],
        "summary": getattr(report, "summary", None).to_dict() if getattr(report, "summary", None) else None,
    }


def _extract_contact_summary(contact) -> Dict[str, Any]:
    if contact is None:
        return {}
    data = {
        "contactId": getattr(contact, "contact_id", None),
        "name": getattr(contact, "name", None),
        "firstName": getattr(contact, "first_name", None),
        "lastName": getattr(contact, "last_name", None),
        "emailAddress": getattr(contact, "email_address", None),
        "salesPerson": getattr(contact, "sales_person", None),
        "isCustomer": getattr(contact, "is_customer", None),
        "isSupplier": getattr(contact, "is_supplier", None),
    }
    addresses = []
    for addr in getattr(contact, "addresses", None) or []:
        addr_info = {
            "type": getattr(addr, "address_type", None),
            "city": getattr(addr, "city", None),
            "region": getattr(addr, "region", None),
            "country": getattr(addr, "country", None),
        }
        addresses.append(addr_info)
    if addresses:
        data["addresses"] = addresses
        # Prefer the first address with a region/country for grouping convenience
        for addr in addresses:
            if addr.get("region"):
                data.setdefault("region", addr["region"])
            if addr.get("country"):
                data.setdefault("country", addr["country"])
    direct_country = getattr(contact, "country", None)
    if direct_country:
        data.setdefault("country", direct_country)
    return {k: v for k, v in data.items() if v not in (None, [], "")}


def _fetch_contacts_map(accounting_api, tenant_id: str, contact_ids: List[str]) -> Dict[str, Dict[str, Any]]:
    contact_ids = [cid for cid in contact_ids if cid]
    if not contact_ids:
        return {}
    results: Dict[str, Dict[str, Any]] = {}
    batch_size = 50
    for idx in range(0, len(contact_ids), batch_size):
        batch = contact_ids[idx : idx + batch_size]
        try:
            resp = accounting_api.get_contacts(
                tenant_id,
                i_ds=batch,
                summary_only=False,
            )
            for contact in getattr(resp, "contacts", None) or []:
                summary = _extract_contact_summary(contact)
                cid = summary.get("contactId")
                if cid:
                    results[cid] = summary
        except Exception as exc:
            logger.warning("Failed to fetch contact batch %s-%s: %s", idx, idx + batch_size, exc)
    return results





def _serialize_tracking_categories(categories) -> List[Dict[str, Any]]:
    output = []
    for cat in getattr(categories, "tracking_categories", None) or []:
        options = []
        # Xero SDK may expose tracking options as either `tracking_options` or `options`
        for opt in getattr(cat, "tracking_options", None) or getattr(cat, "options", None) or []:
            options.append(
                {
                    "trackingOptionId": getattr(opt, "tracking_option_id", None),
                    "name": getattr(opt, "name", None),
                    "status": getattr(opt, "status", None),
                }
            )
        output.append(
            {
                "trackingCategoryId": getattr(cat, "tracking_category_id", None),
                "name": getattr(cat, "name", None),
                "status": getattr(cat, "status", None),
                "options": options,
            }
        )
    return output








def _fetch_report_by_resource(accounting_api, tenant_id: str, resource: str, query: Dict[str, Any] | None = None):
    query_params: List[Tuple[str, Any]] = []
    if query:
        for key, value in query.items():
            if value is None:
                continue
            if isinstance(value, bool):
                query_params.append((key, str(value).lower()))
            else:
                query_params.append((key, value))
    header_params = {
        "xero-tenant-id": tenant_id,
        "Accept": accounting_api.api_client.select_header_accept(["application/json"]),
    }

    # xero-python 9.x no longer appends a trailing slash to the base URL. Ensure
    # we send a correctly formatted resource path (e.g., "/Reports/..."), so
    # the concatenation performed by `get_resource_url` produces a valid URL.
    resource_path = resource if resource.startswith("/") else f"/{resource}"

    return accounting_api.api_client.call_api(
        accounting_api.get_resource_url(resource_path),
        "GET",
        {},
        query_params,
        header_params,
        body=None,
        post_params=[],
        files={},
        response_type="ReportWithRows",
        response_model_finder=accounting_api.get_model_finder(),
        auth_settings=["OAuth2"],
        _return_http_data_only=True,
        _preload_content=True,
    )

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

def get_jwks(force_refresh: bool = False):
    global _jwks_cache
    if _jwks_cache is None or force_refresh:
        logger.info(f"Fetching JWKS from {JWKS_URL} (force_refresh={force_refresh})")
        if not JWKS_URL:
            raise HTTPException(status_code=500, detail="Auth not configured")
        resp = requests.get(JWKS_URL, timeout=5)
        resp.raise_for_status()
        _jwks_cache = resp.json()
    return _jwks_cache



def verify_jwt(token: str):
    try:
        unverified_header = jwt.get_unverified_header(token)
        
        # Check for JWE (Encrypted Token)
        if unverified_header.get("alg") == "dir":
             # This is a JWE encrypted with the client secret
             if not AUTH0_CLIENT_SECRET:
                 logger.error("Received JWE (alg=dir) but AUTH0_CLIENT_SECRET is not configured.")
                 raise HTTPException(status_code=500, detail="Server configuration error: missing client secret for JWE")
             
             try:
                 # JWE decryption
                 # We need to allow 'dir' and content encryption algs like 'A256GCM'
                 # Note: python-jose might require the secret as bytes if it's treating it as a key
                 secret_key = AUTH0_CLIENT_SECRET
                 
                 # Ensure secret is bytes for python-jose
                 if isinstance(secret_key, str):
                     secret_key = secret_key.encode('utf-8')
                     
                 # IMPORTANT: For JWE with alg='dir', the 'key' argument to jwt.decode is the direct secret.
                 # python-jose's jwt.decode handles both JWS and JWE.
                 # If decryption fails with "Signature verification failed", it might be trying to verify as JWS.
                 
                 payload = jwt.decode(
                     token,
                     secret_key,
                     algorithms=["dir", "A256GCM", "A128GCM"], 
                     audience=AUTH0_AUDIENCE,
                     issuer=AUTH0_ISSUER,
                     options={"verify_at_hash": False}
                 )
                 return payload
             except Exception as e:
                 logger.warning(f"JWE decryption with raw secret failed: {e}")
                 # Try Base64URL decoding the secret (common execution for Auth0 secrets)
                 try:
                     # Add padding for base64 decoding if needed
                     rem = len(AUTH0_CLIENT_SECRET) % 4
                     if rem > 0:
                         secret_key_b64 = AUTH0_CLIENT_SECRET + '=' * (4 - rem)
                     else:
                         secret_key_b64 = AUTH0_CLIENT_SECRET
                     
                     import base64
                     secret_key_bytes = base64.urlsafe_b64decode(secret_key_b64)
                     
                     payload = jwt.decode(
                         token,
                         secret_key_bytes,
                         algorithms=["dir", "A256GCM", "A128GCM"], 
                         audience=AUTH0_AUDIENCE,
                         issuer=AUTH0_ISSUER,
                         options={"verify_at_hash": False}
                     )
                     return payload
                 except Exception as e2:
                    logger.error(f"JWE decryption failed with both raw and ref-decoded secret. Raw error: {e}, B64 error: {e2}")
                    raise HTTPException(status_code=401, detail=f"Invalid encrypted token: {str(e2)}")

        jwks = get_jwks()
        token_kid = unverified_header.get("kid")
        
        def find_rsa_key(keys, kid):
            for key in keys:
                if key.get("kid") == kid:
                    return {
                        "kty": key.get("kty"),
                        "kid": key.get("kid"),
                        "use": key.get("use"),
                        "n": key.get("n"),
                        "e": key.get("e"),
                    }
            return None

        rsa_key = find_rsa_key(jwks.get("keys", []), token_kid)
        
        if not rsa_key:
            if token_kid:
                logger.warning(f"Key {token_kid} not found in cache. Refreshing JWKS.")
                jwks = get_jwks(force_refresh=True)
                rsa_key = find_rsa_key(jwks.get("keys", []), token_kid)
            else:
                 logger.warning(f"Token has no 'kid'. Refreshing JWKS and will try all keys.")
                 jwks = get_jwks(force_refresh=True)

        candidate_keys = []
        if rsa_key:
             candidate_keys.append(rsa_key)
        else:
            # Fallback: try ALL keys if specific key not found
            logger.info(f"No matching key found for kid={token_kid}. Trying all {len(jwks.get('keys', []))} keys.")
            candidate_keys = jwks.get("keys", [])

        if not candidate_keys:
             raise HTTPException(status_code=401, detail="No keys available for validation")

        last_error = None
        
        # Iterate through candidate keys
        for key in candidate_keys:
            try:
                # Convert JWK to RSA key format required by jose
                current_rsa_key = {
                    "kty": key.get("kty"),
                    "kid": key.get("kid"),
                    "use": key.get("use"),
                    "n": key.get("n"),
                    "e": key.get("e"),
                }
                
                # Try validating as API access token first (with audience)
                if AUTH0_AUDIENCE:
                    try:
                        payload = jwt.decode(
                            token,
                            current_rsa_key,
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
                            current_rsa_key,
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
                        current_rsa_key,
                        algorithms=ALGORITHMS,
                        issuer=AUTH0_ISSUER,
                        options={"verify_aud": False, "verify_at_hash": False}
                    )
                    if AUTH0_CLIENT_ID and payload.get("azp") == AUTH0_CLIENT_ID:
                        return payload
                except JWTError as e:
                    last_error = e
                    
            except Exception as e:
                # Keep trying other keys
                last_error = e
                continue

        # If we get here, no key worked
        available_kids = [k.get("kid") for k in jwks.get("keys", [])]
        logger.error(f"Token validation failed for kid={token_kid}. Header: {unverified_header}. Available keys: {available_kids}. Last error: {str(last_error)}")
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(last_error) if last_error else 'signature verification failed'}")
    except JWTError as e:
        raise HTTPException(status_code=401, detail=f"Invalid token: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Token validation error: {str(e)}")

def require_auth(request: Request, creds: HTTPAuthorizationCredentials = Depends(security)):
    if creds is None or creds.scheme.lower() != "bearer":
        logger.warning(
            "Missing/invalid Authorization header for %s %s",
            request.method,
            request.url.path,
        )
        raise HTTPException(
            status_code=401,
            detail="Authorization required",
            headers={
                "WWW-Authenticate": (
                    'Bearer '
                    'resource_metadata="https://mcp.backyardbrains.com/.well-known/oauth-protected-resource/xero", '
                    'scope="mcp:read:xero"'
                )
            },
        )
    try:
        return verify_jwt(creds.credentials)
    except HTTPException as exc:
        logger.warning(
            "JWT validation failed for %s %s: %s",
            request.method,
            request.url.path,
            exc.detail,
        )
        raise

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


@app.middleware("http")
async def log_requests(request: Request, call_next):
    """Lightweight request logging to debug OAuth flows without leaking tokens."""

    client_host = request.client.host if request.client else "unknown"
    query_summary = dict(request.query_params)
    auth_header = request.headers.get("authorization")

    auth_summary = "none"
    if auth_header:
        parts = auth_header.split()
        scheme = parts[0]
        token = parts[1] if len(parts) > 1 else ""
        token_hint = f"{token[:6]}...{len(token)}" if token else "missing"
        auth_summary = f"{scheme} ({token_hint})"

    logger.info(
        "Incoming %s %s from %s query=%s auth=%s",
        request.method,
        request.url.path,
        client_host,
        query_summary,
        auth_summary,
    )

    try:
        response = await call_next(request)
    except Exception as exc:
        logger.exception(
            "Request %s %s raised error: %s", request.method, request.url.path, exc
        )
        raise

    logger.info(
        "Completed %s %s with status %s",
        request.method,
        request.url.path,
        response.status_code,
    )
    return response

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
                "name": "xero_list_invoices",
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
                    { "type": "oauth2", "scopes": ["mcp:read:xero"] }
                ]
            },
            {
                "name": "xero_get_balance_sheet",
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
                    { "type": "oauth2", "scopes": ["mcp:read:xero"] }
                ]
            },
            {
                "name": "xero_get_profit_and_loss",
                "description": "Retrieve Profit & Loss (Income Statement) with comparative and tracking options.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "fromDate": {"type": "string", "description": "Start date (YYYY-MM-DD)"},
                        "toDate": {"type": "string", "description": "End date (YYYY-MM-DD)"},
                        "periods": {"type": "integer", "description": "Number of comparative periods"},
                        "timeframe": {"type": "string", "enum": ["MONTH", "QUARTER", "YEAR"], "description": "Comparative timeframe"},
                        "trackingCategoryID": {"type": "string", "description": "Primary tracking category ID"},
                        "trackingOptionID": {"type": "string", "description": "Primary tracking option ID"},
                        "trackingCategoryID2": {"type": "string", "description": "Secondary tracking category ID"},
                        "trackingOptionID2": {"type": "string", "description": "Secondary tracking option ID"},
                        "standardLayout": {"type": "boolean", "description": "Use standard layout"},
                        "paymentsOnly": {"type": "boolean", "description": "Cash basis (payments only)"}
                    }
                },
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["mcp:read:xero"] }
                ]
            },
            {
                "name": "xero_get_cash_summary",
                "description": "Retrieve Cash Summary report for near-term cash position and movements.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "fromDate": {"type": "string", "description": "Start date (YYYY-MM-DD)"},
                        "toDate": {"type": "string", "description": "End date (YYYY-MM-DD)"},
                        "periods": {"type": "integer", "description": "Number of comparative periods"},
                        "timeframe": {"type": "string", "enum": ["MONTH", "QUARTER", "YEAR"], "description": "Comparative timeframe"}
                    }
                },
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["mcp:read:xero"] }
                ]
            },

            {
                "name": "xero_list_contacts",
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
                    { "type": "oauth2", "scopes": ["mcp:read:xero"] }
                ]
            },
            {
                "name": "xero_create_contacts",
                "description": "Creates one or more contacts",
                "inputSchema": {"type": "object", "properties": {"contacts": {"type": "array", "items": {"type": "object"}}}},
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["mcp:write:xero"] }
                ]
            },
            {
                "name": "xero_list_bank_transactions",
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
                    { "type": "oauth2", "scopes": ["mcp:read:xero"] }
                ]
            },
            {
                "name": "xero_create_bank_transactions",
                "description": "Creates one or more bank transactions",
                "inputSchema": {"type": "object", "properties": {"bank_transactions": {"type": "array", "items": {"type": "object"}}}},
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["mcp:write:xero"] }
                ]
            },
            {
                "name": "xero_list_accounts",
                "description": "Retrieves the full chart of accounts",
                "inputSchema": {"type": "object", "properties": {}},
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["mcp:read:xero"] }
                ]
            },
            {
                "name": "xero_list_manual_journals",
                "description": "Retrieve manual journals with optional filters.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "dateFrom": {"type": "string", "description": "JournalDate start (YYYY-MM-DD)"},
                        "dateTo": {"type": "string", "description": "JournalDate end (YYYY-MM-DD)"},
                        "where": {"type": "string", "description": "Xero where clause to filter manual journals"},
                        "order": {"type": "string"},
                        "page": {"type": "integer", "minimum": 1}
                    }
                },
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["mcp:read:xero"] }
                ]
            },
            {
                "name": "xero_list_organisations",
                "description": "Retrieves Xero organisation details",
                "inputSchema": {"type": "object", "properties": {}},
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["mcp:read:xero"] }
                ]
            },
            {
                "name": "xero_list_payments",
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
                    { "type": "oauth2", "scopes": ["mcp:read:xero"] }
                ]
            },

            {
                "name": "xero_list_tracking_categories",
                "description": "List tracking categories and available options.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "includeArchived": {"type": "boolean", "description": "Include archived categories"},
                        "order": {"type": "string", "description": "Order clause"}
                    }
                },
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["mcp:read:xero"] }
                ]
            },


            {
                "name": "xero_list_quotes",
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
                    { "type": "oauth2", "scopes": ["mcp:read:xero"] }
                ]
            },
            {
                "name": "xero_get_account_transactions",
                "description": "Retrieve Account Transactions report for any account (Bank, Asset, Liability, Expense, Revenue, Equity) over a date range.",
                "inputSchema": {
                    "type": "object",
                    "required": ["accountCode"],
                    "properties": {
                        "accountCode": {"type": "string", "description": "Account code from chart of accounts (e.g., '1200' for AR, '4000' for Sales)"},
                        "dateFrom": {"type": "string", "description": "Start date (YYYY-MM-DD)"},
                        "dateTo": {"type": "string", "description": "End date (YYYY-MM-DD)"}
                    }
                },
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["mcp:read:xero"] }
                ]
            },
            {
                "name": "xero_list_items",
                "description": "Retrieve items (products/services) with details like cost price and sales price.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "updatedSince": {"type": "string", "description": "Filter by updated date (ISO)"}
                    }
                },
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["mcp:read:xero"] }
                ]
            },
            {
                "name": "xero_list_bills",
                "description": "Retrieve bills (Accounts Payable invoices) with filtering for due dates and status.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "statuses": {"type": "array", "items": {"type": "string"}, "description": "Bill statuses (e.g. AUTHORISED, PAID)"},
                        "dueDateTo": {"type": "string", "description": "Find bills due on or before this date (YYYY-MM-DD)"},
                        "overdue": {"type": "boolean", "description": "Convenience: Find bills due before today"},
                        "dateFrom": {"type": "string", "description": "Bill date start"},
                        "dateTo": {"type": "string", "description": "Bill date end"},
                        "page": {"type": "integer", "minimum": 1},
                        "order": {"type": "string"}
                    }
                },
                "securitySchemes": [
                    { "type": "oauth2", "scopes": ["mcp:read:xero"] }
                ]
            }
        ]
    }

# MCP Endpoint
MCP_BASE_URL = os.environ.get("MCP_BASE_URL", "https://mcp.backyardbrains.com")


@app.get("/.well-known/mcp.json")
def mcp_manifest():
    """Public MCP discovery manifest used by OpenAI/Anthropic clients."""
    manifest = {
        "name": "Backyard Brains Xero MCP",
        "version": "1.0.0",
        "description": "Machine Coordination Protocol server exposing Backyard Brains Xero data tools.",
        "protocol": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": {
                "list": {},
                "call": {},
            }
        },
        "endpoints": {
            "http": {
                "url": f"{MCP_BASE_URL}/xero/mcp"
            }
        },
        "authentication": {
            "type": "oauth2",
            "authorizationUrl": f"{MCP_BASE_URL}/xero/authorize",
            "tokenUrl": f"{MCP_BASE_URL}/xero/token",
            "scopes": PRM.get("scopes_supported", []),
            **({"audience": AUTH0_AUDIENCE} if AUTH0_AUDIENCE else {}),
        },
        "resources": [],
    }
    return JSONResponse(manifest)


@app.get("/xero/mcp")
async def mcp_endpoint_get(request: Request, _=Depends(require_auth)):
    """
    Handle GET requests to the MCP endpoint (e.g. health checks).
    """
    return {"status": "ok", "message": "Xero MCP endpoint. Use POST for JSON-RPC."}


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
                "protocolVersion": MCP_PROTOCOL_VERSION,
                "serverInfo": {"name": "xero-mcp", "version": "1.0.0"},
                "capabilities": {
                    "tools": {
                        "list": {},
                        "call": {},
                    }
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
    "resource": "https://mcp.backyardbrains.com/xero", 
    "authorization_servers": [f"https://{AUTH0_DOMAIN}/"],  # issuer has trailing slash
    "scopes_supported": ["mcp:read:xero", "mcp:write:xero"],
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
    # Optimize summary_only: default to True unless we specifically need line items
    # We need line items if:
    # 1. We are grouping by 'product'
    # 2. We are filtering by item_codes or account_codes (which are on line items)
    # 3. No grouping is requested AND include_line_items is True
    need_line_items = False
    if not group_by and include_line_items:
        need_line_items = True
    elif group_by and ("product" in group_by):
        need_line_items = True
    elif item_codes or account_codes:
        need_line_items = True

    inv_kwargs["summary_only"] = not need_line_items
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
            loop = asyncio.get_running_loop()
            tasks = []

            def fetch_contacts_batch(ids):
                return accounting_api.get_contacts(
                    tenant_id,
                    i_ds=ids,
                    summary_only=False
                )

            for i in range(0, len(contact_ids), batch_size):
                batch_ids = contact_ids[i:i + batch_size]
                tasks.append(loop.run_in_executor(None, fetch_contacts_batch, batch_ids))
            
            # Wait for all batches
            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                for res in results:
                    if isinstance(res, Exception):
                        logger.warning(f"Failed to fetch contact batch: {res}")
                    else:
                        for contact in res.contacts or []:
                            full_contacts[contact.contact_id] = contact

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
        loop = asyncio.get_running_loop()
        tasks = []

        def fetch_invoices_batch(ids):
            return accounting_api.get_invoices(
                tenant_id,
                i_ds=ids,
                summary_only=False
            )

        for i in range(0, len(invoice_ids), batch_size):
            batch_ids = invoice_ids[i:i + batch_size]
            tasks.append(loop.run_in_executor(None, fetch_invoices_batch, batch_ids))
        
        # Wait for all batches
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, Exception):
                    logger.warning(f"Error fetching invoice batch: {res}")
                else:
                    for inv in res.invoices or []:
                        full_invoices[inv.invoice_id] = inv

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

            # No country found - log for debugging
            logger.warning(f"No country found for invoice {getattr(inv, 'invoice_id', 'UNKNOWN')} contact {getattr(c, 'name', 'UNKNOWN')}")
            return None
        except Exception as e:
            logger.warning(f"Error extracting country for invoice {getattr(inv, 'invoice_id', 'UNKNOWN')}: {e}")
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

    if "product" in group_by:
        # Line-item-level aggregation (used for product grouping)
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

    # Debug logging
    logger.info(f"Grouping by {group_by} resulted in {len(rows)} rows")
    if "country" in group_by and len(rows) == 0:
        logger.warning("No rows found for country grouping - checking bucket keys")
        bucket_keys = list(buckets.keys())
        logger.warning(f"Bucket keys: {bucket_keys[:5]}...")  # Show first 5

    result = {"groupBy": group_by, "metrics": metrics, "rows": rows}
    return {"content": [{"type": "text", "text": safe_dumps(result)}]}

_KNOWN_TOOL_NAMES: Set[str] = {tool["name"] for tool in _list_tools_payload()["tools"]}

_TOOL_NAME_ALIASES = {
    "xero.list_invoices": "xero_list_invoices",
    "xero.get_balance_sheet": "xero_get_balance_sheet",
    "xero.get_profit_and_loss": "xero_get_profit_and_loss",
    "xero.get_profit_and_loss": "xero_get_profit_and_loss",
    "xero.list_contacts": "xero_list_contacts",
    "xero.create_contacts": "xero_create_contacts",
    "xero.list_bank_transactions": "xero_list_bank_transactions",
    "xero.create_bank_transactions": "xero_create_bank_transactions",
    "xero.list_accounts": "xero_list_accounts",
    "xero.list_manual_journals": "xero_list_manual_journals",
    "xero.list_organisations": "xero_list_organisations",
    "xero.list_payments": "xero_list_payments",

    "xero.list_tracking_categories": "xero_list_tracking_categories",

    "xero.list_quotes": "xero_list_quotes",
    "xero.list_items": "xero_list_items",
    "xero.list_bills": "xero_list_bills",
}

async def handle_tool_call(name: str, args: Dict):
    if name in _TOOL_NAME_ALIASES:
        name = _TOOL_NAME_ALIASES[name]

    if not name or name not in _KNOWN_TOOL_NAMES:
        return {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": f"Unknown tool '{name}'. Available tools: {sorted(_KNOWN_TOOL_NAMES)}"
                }
            ],
            "metadata": {"reason": "unknownTool"}
        }
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
            return {
                "isError": True,
                "content": [
                    {
                        "type": "text",
                        "text": "No tenant ID configured. Authenticate through /xero/auth before calling tools."
                    }
                ],
                "metadata": {"reason": "missingTenantId"}
            }
        accounting_api = AccountingApi(api_client)

        if name == "xero_list_invoices":
            return await _process_invoices_with_grouping(accounting_api, tenant_id, args)
        elif name == "xero_get_balance_sheet":
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
        elif name == "xero_get_profit_and_loss":
            pl_from = _get_arg(args, "fromDate", "from_date")
            pl_to = _get_arg(args, "toDate", "to_date")
            pl_periods = _get_arg(args, "periods")
            pl_timeframe = _get_arg(args, "timeframe")
            pl_tc1 = _get_arg(args, "trackingCategoryID", "tracking_category_id")
            pl_to1 = _get_arg(args, "trackingOptionID", "tracking_option_id")
            pl_tc2 = _get_arg(args, "trackingCategoryID2", "tracking_category_id2")
            pl_to2 = _get_arg(args, "trackingOptionID2", "tracking_option_id2")
            pl_std = _get_arg(args, "standardLayout", "standard_layout")
            pl_pay = _get_arg(args, "paymentsOnly", "payments_only")

            if isinstance(pl_from, str):
                d = _parse_iso_date(pl_from)
                pl_from = d.isoformat() if d else pl_from
            if isinstance(pl_to, str):
                d = _parse_iso_date(pl_to)
                pl_to = d.isoformat() if d else pl_to

            pl_kwargs = {}
            if pl_from is not None:
                pl_kwargs["from_date"] = pl_from
            if pl_to is not None:
                pl_kwargs["to_date"] = pl_to
            if pl_periods is not None:
                pl_kwargs["periods"] = pl_periods
            if pl_timeframe is not None:
                pl_kwargs["timeframe"] = pl_timeframe
            if pl_tc1 is not None:
                pl_kwargs["tracking_category_id"] = pl_tc1
            if pl_tc2 is not None:
                pl_kwargs["tracking_category_id2"] = pl_tc2
            if pl_to1 is not None:
                pl_kwargs["tracking_option_id"] = pl_to1
            if pl_to2 is not None:
                pl_kwargs["tracking_option_id2"] = pl_to2
            if pl_std is not None:
                pl_kwargs["standard_layout"] = pl_std
            if pl_pay is not None:
                pl_kwargs["payments_only"] = pl_pay

            pl_report = accounting_api.get_report_profit_and_loss(tenant_id, **pl_kwargs)
            return {"content": [{"type": "text", "text": safe_dumps(_report_to_dict(pl_report.reports[0]))}]}
            pl_report = accounting_api.get_report_profit_and_loss(tenant_id, **pl_kwargs)
            return {"content": [{"type": "text", "text": safe_dumps(_report_to_dict(pl_report.reports[0]))}]}

        elif name == "xero_list_contacts":
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
        elif name == "xero_create_contacts":
            contacts_data = args.get('contacts', [])
            contacts_obj = Contacts(contacts=[Contact(**data) for data in contacts_data])
            created = accounting_api.create_contacts(tenant_id, contacts_obj)
            return {"content": [{"type": "text", "text": safe_dumps([c.to_dict() for c in created.contacts])}]}
        elif name == "xero_list_bank_transactions":
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

            if bt_page:
                bt_kwargs["page"] = bt_page

            transactions = accounting_api.get_bank_transactions(tenant_id, **bt_kwargs)
            return {"content": [{"type": "text", "text": safe_dumps([t.to_dict() for t in transactions.bank_transactions])}]}
        elif name == "xero_create_bank_transactions":
            bank_transactions_data = args.get('bank_transactions', [])
            bank_transactions_obj = BankTransactions(bank_transactions=[BankTransaction(**data) for data in bank_transactions_data])
            created = accounting_api.create_bank_transactions(tenant_id, bank_transactions_obj)
            return {"content": [{"type": "text", "text": safe_dumps([t.to_dict() for t in created.bank_transactions])}]}
        elif name == "xero_list_accounts":
            accounts = accounting_api.get_accounts(tenant_id)
            return {"content": [{"type": "text", "text": safe_dumps([a.to_dict() for a in accounts.accounts])}]}
        elif name == "xero_list_manual_journals":
            mj_date_from = _get_arg(args, "dateFrom", "date_from")
            mj_date_to = _get_arg(args, "dateTo", "date_to")
            mj_where = _get_arg(args, "where")
            mj_order = _get_arg(args, "order")
            mj_page = _get_arg(args, "page")

            where = _join_where(
                mj_where if isinstance(mj_where, str) and mj_where.strip() else "",
                _xero_where_date_field("JournalDate", mj_date_from, mj_date_to),
            )

            mj_kwargs = {}
            if where:
                mj_kwargs["where"] = where
            if mj_order:
                mj_kwargs["order"] = mj_order
            if mj_page:
                mj_kwargs["page"] = mj_page

            manual_journals = accounting_api.get_manual_journals(tenant_id, **mj_kwargs)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": safe_dumps([j.to_dict() for j in (manual_journals.manual_journals or [])]),
                    }
                ]
            }
        elif name == "xero_list_organisations":
            organisations = accounting_api.get_organisations(tenant_id)
            return {"content": [{"type": "text", "text": safe_dumps([o.to_dict() for o in organisations.organisations])}]}
        elif name == "xero_list_payments":
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

        elif name == "xero_list_tracking_categories":
            include_archived = _get_arg(args, "includeArchived", "include_archived")
            order = _get_arg(args, "order")
            tc_kwargs = {}
            if include_archived is not None:
                tc_kwargs["include_archived"] = include_archived
            if order:
                tc_kwargs["order"] = order
            categories = accounting_api.get_tracking_categories(tenant_id, **tc_kwargs)
            return {"content": [{"type": "text", "text": safe_dumps(_serialize_tracking_categories(categories))}]}



        elif name == "xero_list_quotes":
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
        elif name == "xero_get_account_transactions":
            # Get all transactions affecting a specific account
            account_code = _get_arg(args, "accountCode", "account_code")
            if not account_code:
                return {
                    "isError": True,
                    "content": [{"type": "text", "text": "accountCode is required"}],
                    "metadata": {"reason": "missingParameter"}
                }
            
            date_from = _get_arg(args, "dateFrom", "date_from")
            date_to = _get_arg(args, "dateTo", "date_to")
            page = _get_arg(args, "page")
            
            # First, get the account details to validate and get account ID
            accounts_response = accounting_api.get_accounts(tenant_id, where=f'Code=="{account_code}"')
            if not accounts_response.accounts:
                return {
                    "isError": True,
                    "content": [{"type": "text", "text": f"Account {account_code} not found"}],
                    "metadata": {"reason": "accountNotFound"}
                }
            
            account = accounts_response.accounts[0]
            account_id = getattr(account, "account_id", None)

            # Use the Account Transactions Report which works for ALL accounts
            query = {
                "account": account_id,
            }
            if date_from:
                query["fromDate"] = date_from
            if date_to:
                query["toDate"] = date_to
            
            # Note: The report endpoint doesn't support standard pagination like 'page' parameter in the same way as list endpoints.
            # It returns the full report.
            
            try:
                report_data = _fetch_report_by_resource(accounting_api, tenant_id, "Reports/AccountTransactions", query)
                # report_data is a tuple (data, status, headers) or just data depending on _return_http_data_only
                # _fetch_report_by_resource uses _return_http_data_only=True, so it returns the model object (ReportWithRows)
                
                # The SDK returns a Reports object containing a list of Report objects
                if hasattr(report_data, "reports") and report_data.reports:
                    report = report_data.reports[0]
                    return {"content": [{"type": "text", "text": safe_dumps(_report_to_dict(report))}]}
                else:
                     return {"content": [{"type": "text", "text": safe_dumps({})}]}

            except Exception as e:
                logger.exception("Failed to fetch Account Transactions report")
                return {
                    "isError": True,
                    "content": [{"type": "text", "text": f"Failed to fetch report: {str(e)}"}],
                    "metadata": {"reason": "reportError"}
                }
        elif name == "xero_list_items":
            updated_since = _get_arg(args, "updatedSince", "updated_since")
            i_kwargs = {}
            if updated_since:
                if isinstance(updated_since, str):
                    d = _parse_iso_datetime(updated_since)
                    if d:
                        i_kwargs["if_modified_since"] = d
            
            items = accounting_api.get_items(tenant_id, **i_kwargs)
            return {"content": [{"type": "text", "text": safe_dumps([i.to_dict() for i in items.items])}]}
        elif name == "xero_list_bills":
            # Specialized tool for Bills (ACCPAY invoices)
            b_status = _get_arg(args, "statuses")
            if not b_status:
                b_status = ["AUTHORISED"] # Default to approved bills
            
            b_due_date_to = _get_arg(args, "dueDateTo", "due_date_to")
            b_date_from = _get_arg(args, "dateFrom", "date_from")
            b_date_to = _get_arg(args, "dateTo", "date_to")
            b_overdue = bool(_get_arg(args, "overdue", default=False))
            b_page = _get_arg(args, "page")
            b_order = _get_arg(args, "order")

            where_clauses = ['Type=="ACCPAY"']
            
            if isinstance(b_status, list) and b_status:
                where_clauses.append("(" + " || ".join([f'Status=="{s}"' for s in b_status]) + ")")
            
            if b_due_date_to:
                # Find bills due on or before this date
                d = _parse_iso_date(b_due_date_to)
                if d:
                    # Xero API doesn't support DueDate <= X directly in all cases, but let's try standard filter
                    # Actually DueDate is filterable.
                    where_clauses.append(f'DueDate <= DateTime({d.year},{d.month},{d.day})')
            
            if b_overdue:
                # Find bills due before TODAY
                import datetime
                today = datetime.date.today()
                where_clauses.append(f'DueDate < DateTime({today.year},{today.month},{today.day})')

            if b_date_from or b_date_to:
                where_clauses.append(_xero_where_date_range(b_date_from, b_date_to))

            b_kwargs = {"where": " && ".join(where_clauses)}
            if b_page:
                b_kwargs["page"] = b_page
            if b_order:
                b_kwargs["order"] = b_order
            else:
                b_kwargs["order"] = "DueDate ASC" # Default sort by due date for bills

            bills = accounting_api.get_invoices(tenant_id, **b_kwargs)
            return {"content": [{"type": "text", "text": safe_dumps([b.to_dict() for b in bills.invoices])}]}

        return {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": f"Tool {name} not implemented"
                }
            ],
            "metadata": {"reason": "notImplemented"}
        }
    except Exception as e:
        logger.exception("Tool error during %s", name)
        return {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": f"Error while executing {name}: {str(e)}"
                }
            ],
            "metadata": {"reason": "exception", "exceptionType": type(e).__name__}
        }

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