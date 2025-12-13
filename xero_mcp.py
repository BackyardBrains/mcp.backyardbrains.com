import os
import json
import logging
import asyncio
import requests
from typing import Dict, Any, List, Tuple, Set
from urllib.parse import urlencode
from datetime import datetime, date

from fastapi import HTTPException, Request, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.responses import RedirectResponse, JSONResponse
from jose import jwt, JWTError
from cryptography.fernet import Fernet, InvalidToken

from xero_python.accounting import AccountingApi, Contact, Contacts, BankTransaction, BankTransactions, Journal, ManualJournal, ManualJournals, Payment, Quote, Account, Organisation
from xero_python.api_client import ApiClient
from xero_python.api_client.oauth2 import OAuth2Token
from xero_python.api_client.configuration import Configuration
from xero_python.exceptions.http_status_exceptions import HTTPStatusException

from utils import MCP_PROTOCOL_VERSION, safe_dumps, _as_float, _rpc_result, _rpc_error, logger

from auth import require_xero_auth

# Environment variables
XERO_CLIENT_ID = os.environ.get("XERO_CLIENT_ID")
XERO_CLIENT_SECRET = os.environ.get("XERO_CLIENT_SECRET")
XERO_REDIRECT_URI = os.environ.get("XERO_REDIRECT_URI")
# XERO_SCOPES is now imported or we can keep it here if it's Xero specific but auth.py doesn't have it.
# Wait, auth.py is generic. XERO_SCOPES should stay here.
XERO_SCOPES = os.environ.get("XERO_SCOPES")

# Encryption setup
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

def save_tenant_id(tenant_id: str):
    with open(TENANT_FILE, 'w') as f:
        f.write(tenant_id)


def safe_exception_message(exc: Exception) -> str:
    """Return a safe string representation of an exception without triggering nested errors."""
    try:
        return str(exc)
    except Exception:
        try:
            return exc.__class__.__name__
        except Exception:
            return "UnknownException"

def refresh_token_if_needed():
    tokens = load_tokens()
    if not tokens:
        return
    refresh_url = "https://identity.xero.com/connect/token"
    response = requests.post(refresh_url, data={
        "grant_type": "refresh_token",
        "refresh_token": tokens['refresh_token']
    }, auth=(XERO_CLIENT_ID, XERO_CLIENT_SECRET))
    if response.status_code == 200:
        new_tokens = response.json()
        save_tokens(new_tokens)

def _token_getter():
    return load_tokens() or {}

def _token_saver(token):
    try:
        if isinstance(token, OAuth2Token):
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

    @client.oauth2_token_getter
    def _getter():
        return _token_getter()

    @client.oauth2_token_saver
    def _saver(token):
        _token_saver(token)

    tok = load_tokens()
    if tok:
        try:
            client.set_oauth2_token(tok)
        except TypeError:
            client.set_oauth2_token(tok["access_token"])

    _xero_api_client = client
    return _xero_api_client


def _initialize_payload():
    """Standard MCP initialize response for Xero."""
    return {
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": {"listChanged": False},
            "resources": {"listChanged": False, "subscribe": False},
            "prompts": {"listChanged": False},
            "logging": {},
        },
        "serverInfo": {"name": "xero-mcp", "version": "1.0.0"},
    }

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
    resource_path = resource if resource.startswith("/") else f"/{resource}"
    logger.info("Calling Xero report resource: path=%s query_params=%s", resource_path, query_params)
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

async def _process_invoices_with_grouping(accounting_api, tenant_id, args: Dict) -> Dict:
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
        'Type=="ACCREC"',
        ("(" + " || ".join([f'Status=="{s}"' for s in statuses]) + ")") if isinstance(statuses, list) and statuses else ""
    )

    inv_kwargs = {}
    if order:
        inv_kwargs["order"] = order
    if page:
        inv_kwargs["page"] = page

    need_line_items = False
    if not group_by and include_line_items:
        need_line_items = True
    elif group_by and ("product" in group_by):
        need_line_items = True
    elif item_codes or account_codes:
        need_line_items = True

    inv_kwargs["summary_only"] = not need_line_items

    where = _join_where(
        _xero_where_date_range(date_from, date_to),
        _xero_where_contact(contact_id),
        "" if inv_kwargs["summary_only"] else 'Type=="ACCREC"',
        ("(" + " || ".join([f'Status=="{s}"' for s in statuses]) + ")") if isinstance(statuses, list) and statuses else ""
    )

    if where:
        inv_kwargs["where"] = where
        if inv_kwargs["summary_only"]:
            logger.info("Disabling summary_only because filters are present (unsupported by Xero)")
            inv_kwargs["summary_only"] = False
    logger.info(f"Fetching invoices with filters: {inv_kwargs}")
    invoices = accounting_api.get_invoices(tenant_id, **inv_kwargs)

    inv_objs = invoices.invoices or []
    logger.info(f"Found {len(inv_objs)} total invoices (pre-filter)")

    sales_invoices = [inv for inv in inv_objs if getattr(inv, "type", None) == "ACCREC"]
    logger.info(f"Filtered to {len(sales_invoices)} sales invoices (ACCREC)")
    
    contact_ids = list(set(
        getattr(getattr(inv, "contact", None), "contact_id", None)
        for inv in sales_invoices
        if getattr(inv, "contact", None)
    ))
    contact_ids = [cid for cid in contact_ids if cid]

    full_contacts = {}
    if contact_ids:
        try:
            batch_size = 50
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

    if group_by is None and summarize_by:
        group_by = [summarize_by]
    if isinstance(group_by, str):
        group_by = [group_by]
    if not isinstance(group_by, list):
        group_by = []
    if not metrics:
        metrics = ["total"] + (["quantity"] if "product" in group_by else [])

    if not group_by:
        if include_line_items:
            return {"content": [{"type": "text", "text": safe_dumps([inv.to_dict() for inv in sales_invoices])}]}
        else:
            slim = []
            for inv in sales_invoices:
                d = inv.to_dict()
                d.pop("line_items", None)
                slim.append(d)
            return {"content": [{"type": "text", "text": safe_dumps(slim)}]}

    sales = sales_invoices

    if "product" in group_by:
        full_invoices = {}
        invoice_ids = [getattr(inv, "invoice_id", None) for inv in sales if getattr(inv, "invoice_id", None)]

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
        
        if tasks:
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, Exception):
                    logger.warning(f"Error fetching invoice batch: {res}")
                else:
                    for inv in res.invoices or []:
                        full_invoices[inv.invoice_id] = inv

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
            full_contact = full_contacts.get(contact_id) if contact_id else None
            if full_contact:
                country = getattr(full_contact, "country", None)
                if country and country.strip():
                    return country.strip()
                addrs = getattr(full_contact, "addresses", None) or []
                for addr in addrs:
                    country = getattr(addr, "country", None)
                    if country and country.strip():
                        return country.strip()

            country = getattr(c, "country", None)
            if country and country.strip():
                return country.strip()
            addrs = getattr(c, "addresses", None) or []
            for addr in addrs:
                country = getattr(addr, "country", None)
                if country and country.strip():
                    return country.strip()
            return None
        except Exception as e:
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
        for inv in sales:
            line_items = getattr(inv, "line_items", []) or []
            for li in line_items:
                if item_codes:
                    code = getattr(li, "item_code", None)
                    if code not in item_codes:
                        desc = getattr(li, "description", None) or ""
                        if not any(str(code_or_name).lower() in desc.lower() for code_or_name in item_codes):
                            continue
                if account_codes:
                    account_code = getattr(li, "account_code", None)
                    if account_code not in account_codes:
                        continue
                if "product" in group_by:
                    item_code = getattr(li, "item_code", None)
                    if not item_code or not str(item_code).strip():
                        continue

                key = _group_key_for_line_item(inv, li)
                b = _ensure_bucket(key)
                if "quantity" in metrics:
                    b["metrics"]["quantity"] += float(getattr(li, "quantity", 0) or 0)
                if "total" in metrics:
                    b["metrics"]["total"] += float(getattr(li, "line_amount", 0) or 0)
                if "subtotal" in metrics:
                    b["metrics"]["subtotal"] += float(getattr(li, "line_amount", 0) or 0)
                if "tax" in metrics:
                    b["metrics"]["tax"] += float(getattr(li, "tax_amount", 0) or 0)
                if "countInvoices" in metrics and b.get("_invoice_ids") is not None and getattr(inv, "invoice_id", None) is not None:
                    b["_invoice_ids"].add(getattr(inv, "invoice_id", None))
    else:
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

    rows = []
    for _, entry in buckets.items():
        if entry.get("_invoice_ids") is not None and "countInvoices" in metrics:
            entry["metrics"]["countInvoices"] = float(len(entry["_invoice_ids"]))
            entry.pop("_invoice_ids", None)
        rows.append({"group": entry["group"], "metrics": entry["metrics"]})

    result = {"groupBy": group_by, "metrics": metrics, "rows": rows}
    return {"content": [{"type": "text", "text": safe_dumps(result)}]}

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
                _xero_where_date_field("Date", mj_date_from, mj_date_to),
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
                    "httpStatus": 400,
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
                    "httpStatus": 404,
                    "content": [{"type": "text", "text": f"Account {account_code} not found"}],
                    "metadata": {"reason": "accountNotFound"}
                }
            
            account = accounts_response.accounts[0]
            account_id = getattr(account, "account_id", None)

            logger.info(
                "Fetching Account Transactions report for account_code=%s account_id=%s date_from=%s date_to=%s page=%s",
                account_code,
                account_id,
                date_from,
                date_to,
                page,
            )

            if not account_id:
                return {
                    "isError": True,
                    "httpStatus": 400,
                    "content": [{"type": "text", "text": "Account found but missing account_id"}],
                    "metadata": {"reason": "accountIdMissing"},
                }

            # Use the Account Transactions Report. Xero expects the AccountID in the URL path,
            # not as a query parameter, otherwise the upstream API returns 404.
            query = {}
            if date_from:
                query["fromDate"] = date_from
            if date_to:
                query["toDate"] = date_to

            logger.info(
                "Account Transactions query params prepared: %s",
                safe_dumps(query),
            )
            
            # Note: The report endpoint doesn't support standard pagination like 'page' parameter in the same way as list endpoints.
            # It returns the full report.
            
            try:
                resource_path = f"Reports/AccountTransactions/{account_id}"
                report_data = _fetch_report_by_resource(accounting_api, tenant_id, resource_path, query)
                # report_data is a tuple (data, status, headers) or just data depending on _return_http_data_only
                # _fetch_report_by_resource uses _return_http_data_only=True, so it returns the model object (ReportWithRows)

                # The SDK returns a Reports object containing a list of Report objects
                if hasattr(report_data, "reports") and report_data.reports:
                    report = report_data.reports[0]
                    return {"content": [{"type": "text", "text": safe_dumps(_report_to_dict(report))}]}
                else:
                    return {"content": [{"type": "text", "text": safe_dumps({})}]}

            except HTTPStatusException as e:
                headers = getattr(e, "headers", {}) or {}
                correlation_id = headers.get("Xero-Correlation-Id") or headers.get("xero-correlation-id")
                logger.warning(
                    "HTTP error fetching Account Transactions report: status=%s correlation_id=%s headers=%s body=%s",
                    getattr(e, "status", None),
                    correlation_id,
                    headers,
                    getattr(e, "body", None),
                )
                message = safe_exception_message(e)
                logger.warning(
                    "Failed to fetch Account Transactions report: status=%s correlation_id=%s", getattr(e, "status", None), correlation_id
                )
                return {
                    "isError": True,
                    "httpStatus": getattr(e, "status", 502),
                    "content": [{"type": "text", "text": f"Failed to fetch report: {message}"}],
                    "metadata": {"reason": "reportError", "statusCode": getattr(e, "status", None), "correlationId": correlation_id}
                }
            except Exception as e:
                logger.exception("Failed to fetch Account Transactions report")
                return {
                    "isError": True,
                    "httpStatus": 502,
                    "content": [{"type": "text", "text": f"Failed to fetch report: {safe_exception_message(e)}"}],
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
                    "text": f"Error while executing {name}: {safe_exception_message(e)}"
                }
            ],
            "metadata": {"reason": "exception", "exceptionType": type(e).__name__}
        }

# ---- Router Setup ----
from fastapi import APIRouter

router = APIRouter()

@router.get("/")
@router.get("")
def xero_index():
    """Basic index endpoint so /xero/ doesn't 404 behind nginx."""
    return {
        "service": "xero-mcp",
        "status": "ok",
        "endpoints": {
            "health": "/xero/healthz",
            "mcp": "/xero/mcp",
            "auth": "/xero/auth",
        },
    }

@router.post("/")
@router.post("")
async def xero_index_post(request: Request, payload: Dict = Depends(require_xero_auth)):
    """
    Handle MCP JSON-RPC requests at the root /xero/ endpoint.
    Delegates to the same logic as /xero/mcp for convenience.
    """
    return await handle_mcp_request(request, payload)

@router.get("/healthz")
def xero_healthz():
    return {"status": "ok", "service": "xero"}

@router.get("/auth")
def xero_auth():
    """Redirect to Xero authorization page"""
    # Manually construct the OAuth2 authorization URL
    # Xero OAuth2 endpoint
    auth_url = "https://login.xero.com/identity/connect/authorize"
    
    params = {
        "response_type": "code",
        "client_id": XERO_CLIENT_ID,
        "redirect_uri": XERO_REDIRECT_URI,
        "scope": XERO_SCOPES,
    }
    
    authorization_url = f"{auth_url}?{urlencode(params)}"
    return RedirectResponse(url=authorization_url)

@router.get("/callback")
def xero_callback(code: str = None, state: str = None):
    if not code:
        raise HTTPException(status_code=400, detail="Missing code in callback")
    
    try:
        # Exchange code for token by calling Xero's token endpoint directly
        token_url = "https://identity.xero.com/connect/token"
        token_data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": XERO_REDIRECT_URI,
        }
        
        auth_header = requests.auth.HTTPBasicAuth(XERO_CLIENT_ID, XERO_CLIENT_SECRET)
        response = requests.post(token_url, data=token_data, auth=auth_header, timeout=10)
        response.raise_for_status()
        token = response.json()
    except Exception as e:
        logger.error(f"Xero token exchange failed: {e}")
        raise HTTPException(status_code=400, detail=f"Token exchange failed: {safe_exception_message(e)}")

    if not token:
        raise HTTPException(status_code=400, detail="Failed to retrieve token")
    
    save_tokens(token)
    
    # Get and save tenant ID
    try:
        # Create a client with the new token to fetch connections
        cfg = Configuration(
            oauth2_token=OAuth2Token(client_id=XERO_CLIENT_ID, client_secret=XERO_CLIENT_SECRET),
            debug=False,
        )
        api_client = ApiClient(configuration=cfg)
        api_client.set_oauth2_token(token)
        
        identity_api = api_client.identity_api
        connections = identity_api.get_connections()
        if connections:
            tenant_id = connections[0].tenant_id
            save_tenant_id(tenant_id)
            return JSONResponse(content={"status": "success", "tenant_id": tenant_id, "message": "Xero authentication successful. You can now close this window."})
        else:
             return JSONResponse(content={"status": "warning", "message": "Authentication successful but no Xero tenants found."})
    except Exception as e:
        logger.error(f"Failed to fetch tenant ID: {e}")
        return JSONResponse(content={"status": "success", "message": "Xero authentication successful, but failed to auto-fetch tenant ID. It will be fetched on first use if possible."})

@router.post("/mcp")
async def handle_mcp_request(request: Request, payload: Dict = Depends(require_xero_auth)):
    """
    Standard MCP endpoint for Xero tools.
    JSON-RPC 2.0
    """
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid JSON body")

    rpc_id = body.get("id")
    method = body.get("method")
    params = body.get("params", {})

    if method == "initialize":
        return _rpc_result(rpc_id, _initialize_payload())

    elif method == "ping":
        return _rpc_result(rpc_id, {"status": "ok"})

    elif method == "tools/list":
        return _rpc_result(rpc_id, _list_tools_payload())
    
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        result = await handle_tool_call(name, args)
        if isinstance(result, dict) and result.get("isError"):
            status = int(result.get("httpStatus", 502))
            return JSONResponse(status_code=status, content=_rpc_result(rpc_id, result))
        return _rpc_result(rpc_id, result)

    elif method == "resources/list":
        return _rpc_result(rpc_id, {"resources": []})
    
    elif method == "resources/read":
        return _rpc_result(rpc_id, {"contents": []})

    elif method == "prompts/list":
        return _rpc_result(rpc_id, {"prompts": []})

    elif method == "prompts/get":
         return _rpc_result(rpc_id, {"messages": []})

    else:
        return _rpc_error(rpc_id, -32601, f"Method {method} not found")



