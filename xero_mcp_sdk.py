#
# xero_mcp_sdk.py
#
# Refactored Xero MCP implementation using the model-context-protocol SDK.
#
import os
import json
import logging
import asyncio
from typing import Dict, Any, List, Optional, Tuple, Set
from datetime import datetime, date, time
from decimal import Decimal
from enum import Enum
from uuid import UUID
import re

from fastapi import FastAPI, HTTPException, Depends, APIRouter
from cryptography.fernet import Fernet, InvalidToken

from xero_python.accounting import AccountingApi, Contact, Contacts, BankTransaction, BankTransactions, ManualJournals, Quote, Account, Organisation
from xero_python.api_client import ApiClient
from xero_python.api_client.oauth2 import OAuth2Token
from xero_python.api_client.configuration import Configuration

from mcp.server import MCPServer
from mcp.server.fastapi import mcp_api_router

from auth import require_xero_auth

# --- Start of copied utils from utils.py ---

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Machine Coordination Protocol defaults
MCP_PROTOCOL_VERSION = "2024-11-05"

def _json_default(o):
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    if isinstance(o, Decimal):
        return float(o)
    if isinstance(o, UUID):
        return str(o)
    if isinstance(o, Enum):
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
        cleaned = re.sub(r"[^0-9.\\-]", "", value)
        if not cleaned or cleaned in {"-", ".", "-.", ".-"}:
            return None
        try:
            return float(cleaned)
        except ValueError:
            return None
    return None

# --- End of copied utils ---

# --- Start of copied helpers from xero_mcp.py ---

# Environment variables
XERO_CLIENT_ID = os.environ.get("XERO_CLIENT_ID")
XERO_CLIENT_SECRET = os.environ.get("XERO_CLIENT_SECRET")
TOKEN_ENC_KEY = os.environ.get("TOKEN_ENC_KEY")
TOKEN_STORE_PATH = os.environ.get("TOKEN_STORE_PATH", ".xero_tokens.enc")
TENANT_FILE = os.environ.get("TENANT_FILE", "tenant_id.txt")

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
    try:
        if tokens and "expires_at" not in tokens and "expires_in" in tokens:
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

def get_xero_client():
    cfg = Configuration(
        oauth2_token=OAuth2Token(client_id=XERO_CLIENT_ID, client_secret=XERO_CLIENT_SECRET),
        debug=False,
    )
    client = ApiClient(configuration=cfg)

    @client.oauth2_token_getter
    def _getter():
        return load_tokens() or {}

    @client.oauth2_token_saver
    def _saver(token):
        save_tokens(token)

    tok = load_tokens()
    if tok:
        try:
            client.set_oauth2_token(tok)
        except TypeError:
            client.set_oauth2_token(tok["access_token"])

    return client

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
            return datetime.combine(d, time.min)
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

def _join_where(*clauses: str) -> str | None:
    parts = [c for c in clauses if c]
    return " && ".join(parts) if parts else None

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
    
def _row_to_dict(row) -> Dict[str, Any]:
    return {
        "rowType": getattr(row, "row_type", None),
        "title": getattr(row, "title", None),
        "cells": [_cell_to_dict(cell) for cell in (getattr(row, "cells", None) or [])],
        "rows": [_row_to_dict(child) for child in (getattr(row, "rows", None) or [])],
    }

def _cell_to_dict(cell) -> Dict[str, Any]:
    data = {
        "value": getattr(cell, "value", None),
    }
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

def _serialize_tracking_categories(categories) -> List[Dict[str, Any]]:
    output = []
    for cat in getattr(categories, "tracking_categories", None) or []:
        options = []
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

async def _process_invoices_with_grouping(accounting_api, tenant_id, args: Dict) -> Dict:
    date_from = args.get("dateFrom")
    date_to = args.get("dateTo")
    contact_id = args.get("contactId")
    statuses = args.get("statuses")
    order = args.get("order")
    page = args.get("page")
    group_by = args.get("groupBy")
    metrics = args.get("metrics")
    item_codes = args.get("itemCodes")
    include_line_items = args.get("includeLineItems", True)

    where = _join_where(
        _xero_where_date_range(date_from, date_to),
        f'Contact.ContactID==Guid("{contact_id}")' if contact_id else "",
        'Type=="ACCREC"',
        (" + ".join([f'Status=="{s}"' for s in statuses]) + ")") if isinstance(statuses, list) and statuses else ""
    )

    inv_kwargs = {}
    if order: inv_kwargs["order"] = order
    if page: inv_kwargs["page"] = page
    if where: inv_kwargs["where"] = where

    logger.info(f"Fetching invoices with filters: {inv_kwargs}")
    invoices = await asyncio.to_thread(accounting_api.get_invoices, tenant_id, **inv_kwargs)
    
    inv_objs = invoices.invoices or []
    logger.info(f"Found {len(inv_objs)} total invoices (ACCREC)")

    if not group_by:
        result = [inv.to_dict() for inv in inv_objs]
        if not include_line_items:
            for r in result: r.pop("line_items", None)
        return {"content": [{"type": "text", "text": safe_dumps(result)}]}

    buckets = {}
    for inv in inv_objs:
        key_parts = []
        for group in group_by:
            if group == "status": key_parts.append(inv.status)
            elif group == "customer": key_parts.append(inv.contact.name)
        key = tuple(key_parts)
        buckets.setdefault(key, {"count": 0, "total": 0.0})
        buckets[key]["count"] += 1
        buckets[key]["total"] += inv.total
    
    rows = [{"group": dict(zip(group_by, k)), "metrics": v} for k, v in buckets.items()]
    result = {"groupBy": group_by, "metrics": metrics or ["count", "total"], "rows": rows}
    return {"content": [{"type": "text", "text": safe_dumps(result)}]}


# --- End of copied helpers ---

server = MCPServer(
    title="Xero MCP SDK Server",
    description="MCP Server for Xero using the Python SDK.",
    version="1.0.0-sdk"
)

# --- Tool Definitions ---

TOOL_SCHEMAS = {
    "xero_list_invoices": {
        "description": "List or summarize invoices with filters (date, contact, status) and grouping.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dateFrom": {"type": "string", "description": "ISO date start (YYYY-MM-DD)"},
                "dateTo": {"type": "string", "description": "ISO date end (YYYY-MM-DD)"},
                "contactId": {"type": "string", "description": "Xero ContactID (UUID)"},
                "statuses": {"type": "array", "items": {"type": "string"}, "description": "Invoice statuses (e.g., AUTHORISED, PAID)"},
                "order": {"type": "string", "description": "Order clause, e.g. Date DESC"},
                "page": {"type": "integer", "minimum": 1, "description": "Page number (Xero pagination)"},
                "groupBy": {"type": "array", "items": {"type": "string", "enum": ["product", "country", "customer", "status", "month", "quarter", "year"]}},
                "metrics": {"type": "array", "items": {"type": "string", "enum": ["countInvoices", "quantity", "subtotal", "tax", "total", "amountDue"]}},
                "itemCodes": {"type": "array", "items": {"type": "string"}, "description": "Only include line items with these item codes"},
                "includeLineItems": {"type": "boolean", "default": True, "description": "Return full line items in results (when not summarizing)"}
            }
        }
    },
    "xero_get_balance_sheet": {
        "description": "Retrieve Balance Sheet with optional parameters.",
        "input_schema": { "type": "object", "properties": { "date": {"type": "string", "description": "Report date (YYYY-MM-DD)"}, "periods": {"type": "integer"}, "timeframe": {"type": "string", "enum": ["MONTH", "QUARTER", "YEAR"]}, "trackingCategoryID": {"type": "string"}, "trackingOptionID": {"type": "string"}, "standardLayout": {"type": "boolean"}, "paymentsOnly": {"type": "boolean"} } }
    },
    "xero_get_profit_and_loss": {
        "description": "Retrieve Profit & Loss (Income Statement) with comparative and tracking options.",
        "input_schema": { "type": "object", "properties": { "fromDate": {"type": "string"}, "toDate": {"type": "string"}, "periods": {"type": "integer", "minimum": 1, "maximum": 11, "description": "Number of comparative periods (1-11)"}, "timeframe": {"type": "string", "enum": ["MONTH", "QUARTER", "YEAR"]}, "trackingCategoryID": {"type": "string"}, "trackingOptionID": {"type": "string"}, "trackingCategoryID2": {"type": "string"}, "trackingOptionID2": {"type": "string"}, "standardLayout": {"type": "boolean"}, "paymentsOnly": {"type": "boolean"} } }
    },
    "xero_get_cash_summary": {
        "description": "Retrieve Cash Summary report for near-term cash position and movements.",
        "input_schema": { "type": "object", "properties": { "fromDate": {"type": "string"}, "toDate": {"type": "string"} } }
    },
    "xero_list_contacts": {
        "description": "Retrieve contacts with optional filters and pagination.",
        "input_schema": { "type": "object", "properties": { "searchTerm": {"type": "string"}, "page": {"type": "integer"}, "modifiedSince": {"type": "string"}, "includeArchived": {"type": "boolean"}, "summaryOnly": {"type": "boolean"}, "isCustomer": {"type": "boolean"}, "isSupplier": {"type": "boolean"} } }
    },
    "xero_create_contacts": {
        "description": "Creates one or more contacts",
        "input_schema": {"type": "object", "properties": {"contacts": {"type": "array", "items": {"type": "object"}}}}
    },
    "xero_list_bank_transactions": {
        "description": "Retrieve bank transactions with filters.",
        "input_schema": { "type": "object", "properties": { "dateFrom": {"type": "string"}, "dateTo": {"type": "string"}, "accountId": {"type": "string"}, "order": {"type": "string"}, "page": {"type": "integer"} } }
    },
    "xero_create_bank_transactions": {
        "description": "Creates one or more bank transactions",
        "input_schema": {"type": "object", "properties": {"bank_transactions": {"type": "array", "items": {"type": "object"}}}}
    },
    "xero_list_accounts": {
        "description": "Retrieves the full chart of accounts",
        "input_schema": {"type": "object", "properties": {}}
    },
    "xero_list_manual_journals": {
        "description": "Retrieve manual journals with optional filters.",
        "input_schema": { "type": "object", "properties": { "dateFrom": {"type": "string"}, "dateTo": {"type": "string"}, "where": {"type": "string"}, "order": {"type": "string"}, "page": {"type": "integer"} } }
    },
    "xero_list_organisations": {
        "description": "Retrieves Xero organisation details",
        "input_schema": {"type": "object", "properties": {}}
    },
    "xero_list_payments": {
        "description": "Retrieve payments with optional filters.",
        "input_schema": { "type": "object", "properties": { "modifiedSince": {"type": "string"}, "dateFrom": {"type": "string"}, "dateTo": {"type": "string"}, "invoiceId": {"type": "string"}, "accountId": {"type": "string"}, "isReconciled": {"type": "boolean"}, "order": {"type": "string"}, "page": {"type": "integer"} } }
    },
    "xero_list_tracking_categories": {
        "description": "List tracking categories and available options.",
        "input_schema": { "type": "object", "properties": { "includeArchived": {"type": "boolean"}, "order": {"type": "string"} } }
    },
    "xero_list_quotes": {
        "description": "Retrieve quotes with optional filters.",
        "input_schema": { "type": "object", "properties": { "dateFrom": {"type": "string"}, "dateTo": {"type": "string"}, "expiryDateFrom": {"type": "string"}, "expiryDateTo": {"type": "string"}, "contactId": {"type": "string"}, "statuses": {"type": "array", "items": {"type": "string"}}, "order": {"type": "string"}, "page": {"type": "integer"} } }
    },
    "xero_list_items": {
        "description": "Retrieve items (products/services) with details like cost price and sales price.",
        "input_schema": { "type": "object", "properties": { "updatedSince": {"type": "string"} } }
    },
    "xero_list_bills": {
        "description": "Retrieve bills (Accounts Payable invoices) with filtering for due dates and status.",
        "input_schema": { "type": "object", "properties": { "statuses": {"type": "array", "items": {"type": "string"}}, "dueDateTo": {"type": "string"}, "overdue": {"type": "boolean"}, "dateFrom": {"type": "string"}, "dateTo": {"type": "string"}, "page": {"type": "integer"}, "order": {"type": "string"} } }
    }
}

def tenant_id_dependency() -> str:
    tenant_id = load_tenant_id()
    if not tenant_id:
        raise HTTPException(status_code=403, detail="Xero tenant ID not configured. Please complete OAuth flow.")
    return tenant_id

def accounting_api_dependency() -> AccountingApi:
    client = get_xero_client()
    return AccountingApi(client)

@server.tool(**TOOL_SCHEMAS["xero_list_invoices"])
async def xero_list_invoices(*, accounting_api: AccountingApi = Depends(accounting_api_dependency), tenant_id: str = Depends(tenant_id_dependency), **kwargs):
    return await _process_invoices_with_grouping(accounting_api, tenant_id, kwargs)

@server.tool(**TOOL_SCHEMAS["xero_get_balance_sheet"])
async def xero_get_balance_sheet(*, accounting_api: AccountingApi = Depends(accounting_api_dependency), tenant_id: str = Depends(tenant_id_dependency), **kwargs):
    bs_kwargs = {k: v for k, v in kwargs.items() if v is not None}
    if 'date' in bs_kwargs and isinstance(bs_kwargs['date'], str):
        d = _parse_iso_date(bs_kwargs['date'])
        bs_kwargs['date'] = d.isoformat() if d else None
    
    balance_sheet = await asyncio.to_thread(accounting_api.get_report_balance_sheet, tenant_id, **bs_kwargs)
    return {"content": [{"type": "text", "text": safe_dumps([rep.to_dict() for rep in balance_sheet.reports])}]}

@server.tool(**TOOL_SCHEMAS["xero_get_profit_and_loss"])
async def xero_get_profit_and_loss(*, accounting_api: AccountingApi = Depends(accounting_api_dependency), tenant_id: str = Depends(tenant_id_dependency), **kwargs):
    pl_kwargs = {k: v for k, v in kwargs.items() if v is not None}
    if 'fromDate' in pl_kwargs: pl_kwargs['from_date'] = pl_kwargs.pop('fromDate')
    if 'toDate' in pl_kwargs: pl_kwargs['to_date'] = pl_kwargs.pop('toDate')

    pl_report = await asyncio.to_thread(accounting_api.get_report_profit_and_loss, tenant_id, **pl_kwargs)
    return {"content": [{"type": "text", "text": safe_dumps(_report_to_dict(pl_report.reports[0]))}]}

@server.tool(**TOOL_SCHEMAS["xero_get_cash_summary"])
async def xero_get_cash_summary(*, accounting_api: AccountingApi = Depends(accounting_api_dependency), tenant_id: str = Depends(tenant_id_dependency), **kwargs):
    cs_kwargs = {k: v for k, v in kwargs.items() if v is not None}
    if 'fromDate' in cs_kwargs: cs_kwargs['from_date'] = cs_kwargs.pop('fromDate')
    if 'toDate' in cs_kwargs: cs_kwargs['to_date'] = cs_kwargs.pop('toDate')
    
    cash_summary = await asyncio.to_thread(accounting_api.get_report_cash_summary, tenant_id, **cs_kwargs)
    return {"content": [{"type": "text", "text": safe_dumps(_report_to_dict(cash_summary.reports[0]))}]}

@server.tool(**TOOL_SCHEMAS["xero_list_contacts"])
async def xero_list_contacts(*, accounting_api: AccountingApi = Depends(accounting_api_dependency), tenant_id: str = Depends(tenant_id_dependency), **kwargs):
    c_kwargs = {k: v for k, v in kwargs.items() if v is not None}
    if 'modifiedSince' in c_kwargs:
        c_kwargs['if_modified_since'] = _parse_iso_datetime(c_kwargs.pop('modifiedSince'))
    
    where_clauses = []
    if c_kwargs.pop('isCustomer', None): where_clauses.append("IsCustomer==true")
    if c_kwargs.pop('isSupplier', None): where_clauses.append("IsSupplier==true")
    if where_clauses: c_kwargs['where'] = " && ".join(where_clauses)

    contacts = await asyncio.to_thread(accounting_api.get_contacts, tenant_id, **c_kwargs)
    return {"content": [{"type": "text", "text": safe_dumps([c.to_dict() for c in contacts.contacts])}]}

@server.tool(**TOOL_SCHEMAS["xero_create_contacts"])
async def xero_create_contacts(*, contacts: List[Dict], accounting_api: AccountingApi = Depends(accounting_api_dependency), tenant_id: str = Depends(tenant_id_dependency)):
    contacts_obj = Contacts(contacts=[Contact(**data) for data in contacts])
    created = await asyncio.to_thread(accounting_api.create_contacts, tenant_id, contacts_obj)
    return {"content": [{"type": "text", "text": safe_dumps([c.to_dict() for c in created.contacts])}]}

@server.tool(**TOOL_SCHEMAS["xero_list_bank_transactions"])
async def xero_list_bank_transactions(*, accounting_api: AccountingApi = Depends(accounting_api_dependency), tenant_id: str = Depends(tenant_id_dependency), **kwargs):
    bt_kwargs = {k: v for k, v in kwargs.items() if v is not None}
    date_from = bt_kwargs.pop('dateFrom', None)
    date_to = bt_kwargs.pop('dateTo', None)
    account_id = bt_kwargs.pop('accountId', None)
    
    where = _join_where(
        _xero_where_date_field("Date", date_from, date_to),
        (f'BankAccount.AccountID==Guid("{account_id}")' if account_id else "")
    )
    if where: bt_kwargs['where'] = where

    transactions = await asyncio.to_thread(accounting_api.get_bank_transactions, tenant_id, **bt_kwargs)
    return {"content": [{"type": "text", "text": safe_dumps([t.to_dict() for t in transactions.bank_transactions])}]}

@server.tool(**TOOL_SCHEMAS["xero_create_bank_transactions"])
async def xero_create_bank_transactions(*, bank_transactions: List[Dict], accounting_api: AccountingApi = Depends(accounting_api_dependency), tenant_id: str = Depends(tenant_id_dependency)):
    bank_transactions_obj = BankTransactions(bank_transactions=[BankTransaction(**data) for data in bank_transactions])
    created = await asyncio.to_thread(accounting_api.create_bank_transactions, tenant_id, bank_transactions_obj)
    return {"content": [{"type": "text", "text": safe_dumps([t.to_dict() for t in created.bank_transactions])}]}

@server.tool(**TOOL_SCHEMAS["xero_list_accounts"])
async def xero_list_accounts(*, accounting_api: AccountingApi = Depends(accounting_api_dependency), tenant_id: str = Depends(tenant_id_dependency)):
    accounts = await asyncio.to_thread(accounting_api.get_accounts, tenant_id)
    return {"content": [{"type": "text", "text": safe_dumps([a.to_dict() for a in accounts.accounts])}]}

@server.tool(**TOOL_SCHEMAS["xero_list_manual_journals"])
async def xero_list_manual_journals(*, accounting_api: AccountingApi = Depends(accounting_api_dependency), tenant_id: str = Depends(tenant_id_dependency), **kwargs):
    mj_kwargs = {k: v for k, v in kwargs.items() if v is not None}
    where_parts = []
    if 'where' in mj_kwargs: where_parts.append(mj_kwargs.pop('where'))
    date_from = mj_kwargs.pop('dateFrom', None)
    date_to = mj_kwargs.pop('dateTo', None)
    date_filter = _xero_where_date_field("Date", date_from, date_to)
    if date_filter: where_parts.append(date_filter)
    if where_parts: mj_kwargs['where'] = " && ".join(where_parts)
    
    manual_journals = await asyncio.to_thread(accounting_api.get_manual_journals, tenant_id, **mj_kwargs)
    return {"content": [{"type": "text", "text": safe_dumps([j.to_dict() for j in (manual_journals.manual_journals or [])])}]}

@server.tool(**TOOL_SCHEMAS["xero_list_organisations"])
async def xero_list_organisations(*, accounting_api: AccountingApi = Depends(accounting_api_dependency), tenant_id: str = Depends(tenant_id_dependency)):
    organisations = await asyncio.to_thread(accounting_api.get_organisations, tenant_id)
    return {"content": [{"type": "text", "text": safe_dumps([o.to_dict() for o in organisations.organisations])}]}

@server.tool(**TOOL_SCHEMAS["xero_list_payments"])
async def xero_list_payments(*, accounting_api: AccountingApi = Depends(accounting_api_dependency), tenant_id: str = Depends(tenant_id_dependency), **kwargs):
    p_kwargs = {k: v for k, v in kwargs.items() if v is not None}
    where_parts = []
    if 'isReconciled' in p_kwargs: where_parts.append(f"IsReconciled=={str(p_kwargs.pop('isReconciled')).lower()}")
    if 'invoiceId' in p_kwargs: where_parts.append(f'Invoice.InvoiceID==Guid("{p_kwargs.pop("invoiceId")}")')
    if 'accountId' in p_kwargs: where_parts.append(f'Account.AccountID==Guid("{p_kwargs.pop("accountId")}")')
    date_from = p_kwargs.pop('dateFrom', None)
    date_to = p_kwargs.pop('dateTo', None)
    date_filter = _xero_where_date_field("Date", date_from, date_to)
    if date_filter: where_parts.append(date_filter)
    if where_parts: p_kwargs['where'] = " && ".join(where_parts)
    if 'modifiedSince' in p_kwargs:
        p_kwargs['if_modified_since'] = _parse_iso_datetime(p_kwargs.pop('modifiedSince'))

    payments = await asyncio.to_thread(accounting_api.get_payments, tenant_id, **p_kwargs)
    return {"content": [{"type": "text", "text": safe_dumps([p.to_dict() for p in payments.payments])}]}

@server.tool(**TOOL_SCHEMAS["xero_list_tracking_categories"])
async def xero_list_tracking_categories(*, accounting_api: AccountingApi = Depends(accounting_api_dependency), tenant_id: str = Depends(tenant_id_dependency), **kwargs):
    tc_kwargs = {k: v for k, v in kwargs.items() if v is not None}
    categories = await asyncio.to_thread(accounting_api.get_tracking_categories, tenant_id, **tc_kwargs)
    return {"content": [{"type": "text", "text": safe_dumps(_serialize_tracking_categories(categories))}]}

@server.tool(**TOOL_SCHEMAS["xero_list_quotes"])
async def xero_list_quotes(*, accounting_api: AccountingApi = Depends(accounting_api_dependency), tenant_id: str = Depends(tenant_id_dependency), **kwargs):
    q_kwargs = {k: v for k, v in kwargs.items() if v is not None}
    where_parts = []
    quotes = await asyncio.to_thread(accounting_api.get_quotes, tenant_id, **q_kwargs)
    return {"content": [{"type": "text", "text": safe_dumps([q.to_dict() for q in quotes.quotes])}]}

@server.tool(**TOOL_SCHEMAS["xero_list_items"])
async def xero_list_items(*, accounting_api: AccountingApi = Depends(accounting_api_dependency), tenant_id: str = Depends(tenant_id_dependency), **kwargs):
    i_kwargs = {k: v for k, v in kwargs.items() if v is not None}
    if 'updatedSince' in i_kwargs:
        i_kwargs['if_modified_since'] = _parse_iso_datetime(i_kwargs.pop('updatedSince'))
    items = await asyncio.to_thread(accounting_api.get_items, tenant_id, **i_kwargs)
    return {"content": [{"type": "text", "text": safe_dumps([i.to_dict() for i in items.items])}]}

@server.tool(**TOOL_SCHEMAS["xero_list_bills"])
async def xero_list_bills(*, accounting_api: AccountingApi = Depends(accounting_api_dependency), tenant_id: str = Depends(tenant_id_dependency), **kwargs):
    b_kwargs = {k: v for k, v in kwargs.items() if v is not None}
    where_clauses = ['Type=="ACCPAY"']
    statuses = b_kwargs.pop('statuses', ["AUTHORISED"])
    if statuses:
        where_clauses.append("(" + " || ".join([f'Status==\"{s}\"' for s in statuses]) + ")")
    if b_kwargs.pop('overdue', False):
        today = date.today()
        where_clauses.append(f'DueDate < DateTime({today.year},{today.month},{today.day})')
    b_kwargs['where'] = " && ".join(where_clauses)
    
    bills = await asyncio.to_thread(accounting_api.get_invoices, tenant_id, **b_kwargs)
    return {"content": [{"type": "text", "text": safe_dumps([b.to_dict() for b in bills.invoices])}]}

# --- Router Setup ---
router = APIRouter()

mcp_router = mcp_api_router(
    server,
    "/mcp",
    dependencies=[Depends(require_xero_auth)],
    json_dumps_default=_json_default,
)

router.include_router(mcp_router)

sdk_app = FastAPI(title="Xero MCP SDK", version="1.0.0")
sdk_app.include_router(router)
