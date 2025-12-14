import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Callable, Dict, List, Union

import pytest
import pytest_asyncio

sys.path.append(str(Path(__file__).resolve().parents[1]))

import xero_mcp

REQUIRED_TOOLS: set[str] = {
    "xero_get_balance_sheet",
    "xero_get_profit_and_loss",
    "xero_get_cash_summary",
    "xero_list_accounts",
    "xero_list_contacts",
    "xero_list_invoices",
    "xero_list_bills",
    "xero_list_payments",
    "xero_list_bank_transactions",
    "xero_list_manual_journals",
    "xero_list_tracking_categories",
    "xero_list_quotes",
    "xero_list_items",
}

# Known-broken or temporarily disabled tools with explicit accountability to avoid
# accumulating silent debt. Each entry must include a reason, an owner, and either an
# expiry date or ticket reference.
QUARANTINED_TOOLS = []
QUARANTINED_TOOL_NAMES: set[str] = {entry["name"] for entry in QUARANTINED_TOOLS}

FIXTURE_DIR = Path(__file__).parent / "fixtures"
CONTRACT_DIR = FIXTURE_DIR / "contracts"
SMOKE_DIR = FIXTURE_DIR / "smoke"

GUID_RE = re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}")
DATE_RE = re.compile(r"\d{4}-\d{2}-\d{2}")
DATETIME_RE = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(:\d{2}(\.\d+)?)?(Z|[+-]\d{2}:?\d{2})?")


@pytest.fixture(scope="session")
def recorded_responses() -> Dict[str, Any]:
    path = SMOKE_DIR / "responses.json"
    if path.exists():
        return json.loads(path.read_text(encoding="utf-8"))
    return {}


@pytest.fixture(scope="session")
def is_smoke() -> bool:
    return os.environ.get("XERO_SMOKE") == "1"


@pytest.fixture(autouse=True)
def patch_handle_tool_call(
    monkeypatch: pytest.MonkeyPatch,
    recorded_responses: Dict[str, Any],
    is_smoke: bool,
):
    if is_smoke:
        return

    def _fake_handle(tool_name: str, args: Dict[str, Any]):
        payload = recorded_responses.get(tool_name)
        if payload is not None:
            return payload
        return {
            "isError": True,
            "content": [
                {
                    "type": "text",
                    "text": json.dumps({"error": "missing fixture", "tool": tool_name}),
                }
            ],
            "metadata": {"reason": "missingFixture"},
        }

    monkeypatch.setattr(xero_mcp, "handle_tool_call", _fake_handle)
    return _fake_handle


def decode_tool_payload(response: Dict[str, Any]) -> Union[Dict[str, Any], List[Any]]:
    if not isinstance(response, dict):
        return {"error": "unexpected-response", "raw": response}
    if response.get("isError"):
        return {"isError": True, "content": response.get("content"), "metadata": response.get("metadata")}

    content = response.get("content") or []
    text = None
    if content and isinstance(content, list) and isinstance(content[0], dict):
        text = content[0].get("text")
    if text is None:
        return {"error": "missing-content"}
    try:
        payload = json.loads(text)
    except Exception:
        return {"raw": text}
    return payload


def sanitize_for_snapshot(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: sanitize_for_snapshot(value[k]) for k in sorted(value.keys())}
    if isinstance(value, list):
        return [sanitize_for_snapshot(v) for v in value]
    if isinstance(value, str):
        if GUID_RE.search(value):
            return "<guid>"
        if DATETIME_RE.fullmatch(value):
            return "<datetime>"
        if DATE_RE.fullmatch(value):
            return "<date>"
        return value
    if isinstance(value, (int, float)):
        return "<number>"
    if isinstance(value, bool):
        return value
    if value is None:
        return None
    return str(type(value).__name__)


def stable_keys(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: stable_keys(value[k]) for k in sorted(value.keys())}
    if isinstance(value, list):
        return [stable_keys(v) for v in value]
    return value


@pytest_asyncio.fixture
async def call_tool(is_smoke: bool) -> Callable[[str, Dict[str, Any]], Any]:
    async def _call(name: str, args: Dict[str, Any]):
        result = xero_mcp.handle_tool_call(name, args)
        if hasattr(result, "__await__"):
            return await result
        return result

    return _call
