import json
import os

import pytest

from tests.conftest import CONTRACT_DIR, REQUIRED_TOOLS, decode_tool_payload, sanitize_for_snapshot


def _load_snapshot(name: str):
    path = CONTRACT_DIR / f"{name}.shape.json"
    if not path.exists():
        pytest.skip(f"No contract snapshot for {name}")
    return json.loads(path.read_text(encoding="utf-8"))


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", sorted(REQUIRED_TOOLS))
async def test_tool_shapes_are_stable(call_tool, tool_name: str):
    response = await call_tool(tool_name, {})
    payload = decode_tool_payload(response)
    if isinstance(payload, dict) and payload.get("isError"):
        pytest.fail(f"{tool_name} returned error instead of data: {payload}")

    sanitized = sanitize_for_snapshot(payload)

    snapshot = _load_snapshot(tool_name)
    if sanitized != snapshot:
        if os.environ.get("UPDATE_CONTRACTS") == "1":
            CONTRACT_DIR.mkdir(parents=True, exist_ok=True)
            path = CONTRACT_DIR / f"{tool_name}.shape.json"
            path.write_text(json.dumps(sanitized, indent=2, sort_keys=True), encoding="utf-8")
            pytest.skip(f"Updated contract snapshot for {tool_name}")
        assert (
            sanitized == snapshot
        ), f"Contract drift for {tool_name}. Expected {json.dumps(snapshot, indent=2)} got {json.dumps(sanitized, indent=2)}"


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", [
    "xero_get_balance_sheet",
    "xero_get_profit_and_loss",
    "xero_get_cash_summary",
])
async def test_reports_are_deterministic(call_tool, tool_name: str):
    first = decode_tool_payload(await call_tool(tool_name, {}))
    second = decode_tool_payload(await call_tool(tool_name, {}))
    payload_one = sanitize_for_snapshot(first)
    payload_two = sanitize_for_snapshot(second)
    assert payload_one == payload_two, f"Report output for {tool_name} is not deterministic"
