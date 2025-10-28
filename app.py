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
    auth_url = "https://login.xero.com/identity/connect/authorize?" + requests.utils.urlencode(params)
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

# MCP Endpoint
@app.post("/mcp")
async def mcp_endpoint(request: Request):
    body = await request.json()
    method = body.get("method", "").lower()
    
    if method in ["", "discover", "tools/list"]:
        return {
            "tools": [
                {
                    "name": "xero.list_invoices",
                    "description": "Retrieves sales invoices or purchase bills",
                    "input_schema": {"type": "object", "properties": {}},
                    "output": {"content": [{"type": "text", "text": "string"}]}
                },
                {
                    "name": "xero.get_balance_sheet",
                    "description": "Retrieves report for balancesheet",
                    "input_schema": {"type": "object", "properties": {}},
                    "output": {"content": [{"type": "text", "text": "string"}]}
                },
                {
                    "name": "xero.list_contacts",
                    "description": "Retrieves all contacts (customers/suppliers)",
                    "input_schema": {"type": "object", "properties": {}},
                    "output": {"content": [{"type": "text", "text": "string"}]}
                },
                {
                    "name": "xero.create_contacts",
                    "description": "Creates one or more contacts",
                    "input_schema": {"type": "object", "properties": {"contacts": {"type": "array"}}},
                    "output": {"content": [{"type": "text", "text": "string"}]}
                },
                {
                    "name": "xero.list_bank_transactions",
                    "description": "Retrieves bank transactions",
                    "input_schema": {"type": "object", "properties": {}},
                    "output": {"content": [{"type": "text", "text": "string"}]}
                },
                {
                    "name": "xero.create_bank_transactions",
                    "description": "Creates one or more bank transactions",
                    "input_schema": {"type": "object", "properties": {"bank_transactions": {"type": "array"}}},
                    "output": {"content": [{"type": "text", "text": "string"}]}
                },
                {
                    "name": "xero.list_accounts",
                    "description": "Retrieves the full chart of accounts",
                    "input_schema": {"type": "object", "properties": {}},
                    "output": {"content": [{"type": "text", "text": "string"}]}
                },
                {
                    "name": "xero.list_journals",
                    "description": "Retrieves journals",
                    "input_schema": {"type": "object", "properties": {}},
                    "output": {"content": [{"type": "text", "text": "string"}]}
                },
                {
                    "name": "xero.list_organisations",
                    "description": "Retrieves Xero organisation details",
                    "input_schema": {"type": "object", "properties": {}},
                    "output": {"content": [{"type": "text", "text": "string"}]}
                },
                {
                    "name": "xero.list_payments",
                    "description": "Retrieves payments",
                    "input_schema": {"type": "object", "properties": {}},
                    "output": {"content": [{"type": "text", "text": "string"}]}
                },
                {
                    "name": "xero.list_quotes",
                    "description": "Retrieves quotes",
                    "input_schema": {"type": "object", "properties": {}},
                    "output": {"content": [{"type": "text", "text": "string"}]}
                },
            ]
        }
    
    elif method in ["tools/call", "call_tool"]:
        tool_name = body.get("params", {}).get("name")
        args = body.get("params", {}).get("arguments", {})
        return await handle_tool_call(tool_name, args)
    
    return {"error": "Method not found"}

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
@app.get("/healthz")
def healthz():
    return {"status": "ok"}

# Run the server
if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)