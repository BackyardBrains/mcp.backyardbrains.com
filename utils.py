import json
import logging
import re
from datetime import date, datetime
from decimal import Decimal
from enum import Enum
from typing import Any, Dict
from uuid import UUID

# Machine Coordination Protocol defaults
MCP_PROTOCOL_VERSION = "2024-11-05"

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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

def _rpc_result(rpc_id: Any, result: Dict[str, Any]):
    return {"jsonrpc": "2.0", "id": rpc_id, "result": result}

def _rpc_error(rpc_id: Any, code: int, message: str, data: Any = None):
    err = {"code": code, "message": message}
    if data is not None:
        err["data"] = data
    return {"jsonrpc": "2.0", "id": rpc_id, "error": err}
