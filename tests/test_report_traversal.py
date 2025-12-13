import pytest

from tests.conftest import decode_tool_payload


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", [
    "xero_get_balance_sheet",
    "xero_get_profit_and_loss",
    "xero_get_cash_summary",
])
async def test_report_rows_traversable(call_tool, tool_name: str):
    payload = decode_tool_payload(await call_tool(tool_name, {}))
    reports = payload if isinstance(payload, list) else payload.get("reports", [])
    for report in reports:
        rows = report.get("rows", [])
        assert isinstance(rows, list)
        _walk_rows(rows)


def _walk_rows(rows, depth=0):
    assert isinstance(rows, list)
    for row in rows:
        if "rows" in row and row["rows"] is not None:
            assert isinstance(row["rows"], list)
            _walk_rows(row["rows"], depth + 1)
        if "cells" in row and row["cells"] is not None:
            assert isinstance(row["cells"], list)
            for cell in row["cells"]:
                assert isinstance(cell, dict)
                assert "value" in cell
