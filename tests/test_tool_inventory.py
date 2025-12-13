import json
from datetime import date
from pathlib import Path

import pytest

import xero_mcp
from tests.conftest import (
    CONTRACT_DIR,
    QUARANTINED_TOOL_NAMES,
    QUARANTINED_TOOLS,
    REQUIRED_TOOLS,
    sanitize_for_snapshot,
    stable_keys,
)

TOOL_INVENTORY_PATH = Path(__file__).parent / "fixtures" / "tool_inventory.json"


def _write_inventory(tools):
    TOOL_INVENTORY_PATH.parent.mkdir(parents=True, exist_ok=True)
    payload = [{"name": t["name"], "schema": t.get("inputSchema", {})} for t in tools]
    normalized = stable_keys(payload)
    TOOL_INVENTORY_PATH.write_text(json.dumps(normalized, indent=2, sort_keys=True), encoding="utf-8")


def _quarantine_metadata_complete(entry: dict) -> bool:
    has_reason = bool(entry.get("reason"))
    has_owner = bool(entry.get("owner"))
    has_ticket = bool(entry.get("ticket"))
    has_expiry_or_ticket = bool(entry.get("expires") or has_ticket)
    return has_reason and has_owner and has_expiry_or_ticket and has_ticket


@pytest.mark.asyncio
async def test_tool_inventory_includes_required_tools():
    tool_payload = xero_mcp._list_tools_payload()
    tools = tool_payload.get("tools", [])
    names = {t.get("name") for t in tools}
    _write_inventory(tools)

    missing = (REQUIRED_TOOLS - QUARANTINED_TOOL_NAMES) - names
    quarantined_missing = QUARANTINED_TOOL_NAMES - names

    assert not missing, f"Missing required tools: {sorted(missing)}"
    if quarantined_missing:
        pytest.skip(f"Quarantined tools absent (info only): {sorted(quarantined_missing)}")


@pytest.mark.asyncio
async def test_no_duplicate_tool_names():
    tool_payload = xero_mcp._list_tools_payload()
    tools = tool_payload.get("tools", [])
    names = [t.get("name") for t in tools]
    duplicates = {name for name in names if names.count(name) > 1}
    assert not duplicates, f"Duplicate tool declarations detected: {sorted(duplicates)}"


def test_quarantined_tools_have_accountability():
    incomplete = [entry for entry in QUARANTINED_TOOLS if not _quarantine_metadata_complete(entry)]
    assert not incomplete, f"Quarantined tools missing metadata: {incomplete}"

    expired = []
    for entry in QUARANTINED_TOOLS:
        expiry = entry.get("expires")
        if not expiry:
            continue
        try:
            expiry_date = date.fromisoformat(expiry)
        except ValueError:
            pytest.fail(f"Invalid expiry format for {entry.get('name')}: {expiry}")
        if expiry_date < date.today():
            expired.append({"name": entry.get("name"), "expired": expiry})

    assert not expired, f"Expired quarantines detected: {expired}"


@pytest.mark.asyncio
async def test_contract_snapshots_exist_for_listed_tools():
    tool_payload = xero_mcp._list_tools_payload()
    for tool in tool_payload.get("tools", []):
        name = tool.get("name")
        snapshot = CONTRACT_DIR / f"{name}.shape.json"
        if name not in REQUIRED_TOOLS:
            if not snapshot.exists():
                pytest.skip(f"Contract snapshot missing for non-required tool {name}")
            continue
        assert snapshot.exists(), f"Contract snapshot missing for {name}"
        data = json.loads(snapshot.read_text(encoding="utf-8"))
        assert sanitize_for_snapshot(data) == data, "Snapshot should already be sanitized"
