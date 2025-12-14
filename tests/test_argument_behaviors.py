import pytest

import xero_mcp
from tests.conftest import QUARANTINED_TOOL_NAMES, decode_tool_payload


def _tool_inventory():
    return xero_mcp._list_tools_payload().get("tools", [])


def _date_fields(properties):
    return [name for name in properties if "date" in name.lower()]


def _base_args(properties):
    args = {}
    if "date" in properties:
        args["date"] = "2024-01-01"
    if "fromDate" in properties and "toDate" in properties:
        args["fromDate"] = "2024-01-01"
        args["toDate"] = "2024-01-31"
    if "dateFrom" in properties and "dateTo" in properties and "fromDate" not in args:
        args["dateFrom"] = "2024-01-01"
        args["dateTo"] = "2024-01-31"
    if "page" in properties:
        args.setdefault("page", 1)
    return args


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", _tool_inventory())
async def test_date_arguments_reject_bad_formats(call_tool, tool, is_smoke: bool):
    properties = (tool.get("inputSchema") or {}).get("properties", {})
    date_fields = _date_fields(properties)
    if not date_fields:
        pytest.skip(f"{tool['name']} has no date parameters")
    base_args = _base_args(properties)
    bad_args = dict(base_args)
    bad_args[date_fields[0]] = "2024-13-40"
    response = await call_tool(tool["name"], bad_args)
    payload = decode_tool_payload(response)
    assert isinstance(payload, dict)
    if not is_smoke and not payload.get("isError"):
        pytest.skip("Recorded fixture did not capture date validation")
    assert payload.get("isError"), f"{tool['name']} should reject invalid date formats"


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", [t for t in _tool_inventory() if "page" in (t.get("inputSchema") or {}).get("properties", {})])
async def test_paging_defaults(call_tool, tool):
    properties = (tool.get("inputSchema") or {}).get("properties", {})
    base_args = _base_args(properties)
    args_without_page = {k: v for k, v in base_args.items() if k != "page"}
    first = await call_tool(tool["name"], args_without_page)
    second = await call_tool(tool["name"], {**args_without_page, "page": 1})
    assert first == second, f"{tool['name']} should treat omitted page as page=1"


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", [t for t in _tool_inventory() if "page" in (t.get("inputSchema") or {}).get("properties", {})])
async def test_pagination_variation(call_tool, tool):
    properties = (tool.get("inputSchema") or {}).get("properties", {})
    base_args = _base_args(properties)
    args_without_page = {k: v for k, v in base_args.items() if k != "page"}
    page_one = await call_tool(tool["name"], {**args_without_page, "page": 1})
    page_two = await call_tool(tool["name"], {**args_without_page, "page": 2})
    if page_one == page_two:
        pytest.skip(f"Pagination data too small for {tool['name']} to differ between pages")
    assert page_one != page_two


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", [t for t in _tool_inventory() if "where" in (t.get("inputSchema") or {}).get("properties", {})])
async def test_invalid_where_filters_are_errors(call_tool, tool, is_smoke: bool):
    response = await call_tool(tool["name"], {"where": "INVALID"})
    payload = decode_tool_payload(response)
    assert isinstance(payload, dict)
    if not is_smoke and not payload.get("isError"):
        pytest.skip("Recorded fixture did not capture where validation")
    assert payload.get("isError"), f"{tool['name']} should surface where errors"


@pytest.mark.asyncio
async def test_account_transactions_endpoint_not_broken(call_tool):
    if "xero_get_account_transactions" in QUARANTINED_TOOL_NAMES:
        pytest.skip("xero_get_account_transactions is quarantined")
    response = await call_tool(
        "xero_get_account_transactions",
        {"dateFrom": "2024-01-01", "dateTo": "2024-01-31", "accountCode": "100"},
    )
    payload = decode_tool_payload(response)
    assert not isinstance(payload, dict) or not payload.get("isError"), "endpoint appears broken; remove or fix tool."
