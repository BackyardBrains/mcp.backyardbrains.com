import os
import logging
import mysql.connector
import phpserialize
from typing import Dict, Any, List, Optional
from fastapi import APIRouter, HTTPException, Request, Depends
from fastapi.responses import JSONResponse

from utils import MCP_PROTOCOL_VERSION, _rpc_result, _rpc_error, logger, safe_dumps
from auth import require_mysql_auth

# Environment variables
DB_HOST = os.getenv('DB_HOST')
DB_USER = os.getenv('DB_USER')
DB_PASSWORD = os.getenv('DB_PASSWORD')
DB_NAME = os.getenv('DB_NAME')

router = APIRouter()

@router.get("/")
@router.get("")
def mysql_index():
    """Basic index endpoint so /mysql/ doesn't 404."""
    return {
        "service": "mysql-mcp",
        "status": "ok",
        "endpoints": {
            "health": "/mysql/healthz",
            "mcp": "/mysql/mcp",
        },
    }

@router.get("/healthz")
def mysql_healthz():
    return {"status": "ok", "service": "mysql"}

def get_db_connection():
    if not all([DB_HOST, DB_USER, DB_PASSWORD, DB_NAME]):
        raise ValueError("Missing database configuration in environment variables")
    return mysql.connector.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME
    )

def _deserialize_php(value: Any) -> Any:
    """Attempt to deserialize if it looks like PHP serialized data."""
    try:
        if value and isinstance(value, str) and (value.startswith('a:') or value.startswith('O:') or value.startswith('s:') or value.startswith('i:') or value.startswith('d:') or value.startswith('b:')):
            # phpserialize requires bytes
            deserialized = phpserialize.loads(value.encode('utf-8'))
            
            # If it's a dictionary (associative array), flatten it
            if isinstance(deserialized, dict):
                result = {}
                for sub_key, sub_value in deserialized.items():
                    # Decode bytes keys/values to strings if needed
                    k = sub_key.decode('utf-8') if isinstance(sub_key, bytes) else str(sub_key)
                    v = sub_value.decode('utf-8') if isinstance(sub_value, bytes) else str(sub_value)
                    result[f"{k}"] = v
                return result
            else:
                 return deserialized
        return value
    except Exception:
        # If deserialization fails, just keep original value
        return value

def get_forms():
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        # Forms are stored in wp_posts with post_type 'forminator_forms'
        cursor.execute("SELECT ID as id, post_title as name FROM wp_posts WHERE post_type = 'forminator_forms'")
        forms = cursor.fetchall()
        return forms
    finally:
        conn.close()

def get_entries(form_id):
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        
        # Hardcoded table names based on inspection
        entries_table = "wp_frmt_form_entry"
        meta_table = "wp_frmt_form_entry_meta"
        
        # Fetch entries
        query = f"""
            SELECT e.entry_id, e.date_created, m.meta_key, m.meta_value
            FROM {entries_table} e
            JOIN {meta_table} m ON e.entry_id = m.entry_id
            WHERE e.form_id = %s
            ORDER BY e.date_created ASC
        """
        cursor.execute(query, (form_id,))
        rows = cursor.fetchall()
        
        # Process rows into a list of dicts
        entries = {}
        for row in rows:
            eid = row['entry_id']
            if eid not in entries:
                entries[eid] = {
                    'entry_id': eid, 
                    'date_created': row['date_created'].isoformat() if hasattr(row['date_created'], 'isoformat') else str(row['date_created'])
                }
            
            key = row['meta_key']
            value = row['meta_value']
            
            deserialized = _deserialize_php(value)
            if isinstance(deserialized, dict):
                for k, v in deserialized.items():
                    entries[eid][f"{key}_{k}"] = v
            else:
                entries[eid][key] = deserialized
            
        return list(entries.values())
    finally:
        conn.close()

def get_entry_by_id(entry_id):
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        
        entries_table = "wp_frmt_form_entry"
        meta_table = "wp_frmt_form_entry_meta"
        
        query = f"""
            SELECT e.entry_id, e.date_created, e.form_id, m.meta_key, m.meta_value
            FROM {entries_table} e
            JOIN {meta_table} m ON e.entry_id = m.entry_id
            WHERE e.entry_id = %s
        """
        cursor.execute(query, (entry_id,))
        rows = cursor.fetchall()
        
        if not rows:
            return None
            
        # Process rows
        entry = {
            'entry_id': entry_id, 
            'date_created': rows[0]['date_created'].isoformat() if hasattr(rows[0]['date_created'], 'isoformat') else str(rows[0]['date_created']),
            'form_id': rows[0]['form_id']
        }
        
        for row in rows:
            key = row['meta_key']
            value = row['meta_value']
            
            deserialized = _deserialize_php(value)
            if isinstance(deserialized, dict):
                for k, v in deserialized.items():
                    entry[f"{key}_{k}"] = v
            else:
                entry[key] = deserialized
                
        return entry
    finally:
        conn.close()

def execute_query(query: str, params: tuple = None):
    conn = get_db_connection()
    try:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query, params)
        if query.strip().lower().startswith("select"):
            return cursor.fetchall()
        else:
            conn.commit()
            return {"affected_rows": cursor.rowcount}
    finally:
        conn.close()

def _initialize_payload():
    return {
        "protocolVersion": MCP_PROTOCOL_VERSION,
        "capabilities": {
            "tools": {"listChanged": False},
            "resources": {"listChanged": False, "subscribe": False},
            "prompts": {"listChanged": False},
            "logging": {},
        },
        "serverInfo": {"name": "mysql-mcp", "version": "1.0.0"},
    }

def _list_mysql_tools():
    return {
        "tools": [
            {
                "name": "mysql_query",
                "description": "Execute a generic MySQL query",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "query": {"type": "string", "description": "SQL query to execute"}
                    },
                    "required": ["query"]
                }
            },
            {
                "name": "mysql_get_forms",
                "description": "List Forminator forms from wp_posts",
                "inputSchema": {"type": "object", "properties": {}}
            },
            {
                "name": "mysql_get_entries",
                "description": "Fetch entries for a specific Forminator form",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "form_id": {"type": "integer", "description": "ID of the form"}
                    },
                    "required": ["form_id"]
                }
            },
            {
                "name": "mysql_get_entry_by_id",
                "description": "Fetch a single Forminator entry by ID",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "entry_id": {"type": "integer", "description": "ID of the entry"}
                    },
                    "required": ["entry_id"]
                }
            }
        ]
    }

async def handle_mysql_tool_call(name: str, args: Dict):
    try:
        if name == "mysql_query":
            query = args.get("query")
            result = execute_query(query)
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
        elif name == "mysql_get_forms":
            result = get_forms()
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
        elif name == "mysql_get_entries":
            form_id = args.get("form_id")
            result = get_entries(form_id)
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
        elif name == "mysql_get_entry_by_id":
            entry_id = args.get("entry_id")
            result = get_entry_by_id(entry_id)
            return {"content": [{"type": "text", "text": safe_dumps(result)}]}
        else:
            return {"isError": True, "content": [{"type": "text", "text": f"Unknown tool: {name}"}]}
    except Exception as e:
        logger.error(f"Error executing MySQL tool {name}: {e}")
        return {
            "isError": True,
            "content": [{"type": "text", "text": f"Error executing {name}: {str(e)}"}],
            "metadata": {"reason": "exception", "exceptionType": type(e).__name__}
        }

@router.post("/mcp")
async def handle_mysql_mcp(request: Request, payload: Dict = Depends(require_mysql_auth)):
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
        return _rpc_result(rpc_id, _list_mysql_tools())
    elif method == "tools/call":
        name = params.get("name")
        args = params.get("arguments", {})
        result = await handle_mysql_tool_call(name, args)
        return _rpc_result(rpc_id, result)
    else:
        return _rpc_error(rpc_id, -32601, f"Method {method} not found")
