import json
from datetime import datetime

import pytest

import xero_mcp


class DummyAccount:
    def __init__(self, code: str):
        self.code = code

    def to_dict(self):
        return {"code": self.code}


class DummyLine:
    def __init__(self, account_code: str):
        self.account_code = account_code

    def to_dict(self):
        return {"accountCode": self.account_code}


class DummyJournal:
    def __init__(self, account_code: str):
        self.journal_lines = [DummyLine(account_code)]
        self.journal_date = datetime(2024, 1, 5)

    def to_dict(self):
        return {"journalID": "j-1", "journal_date": str(self.journal_date.date())}


class DummyInvoice:
    def __init__(self, account_code: str):
        self.line_items = [DummyLine(account_code)]
        self.type = "ACCPAY"

    def to_dict(self):
        return {
            "invoiceID": "inv-1",
            "type": self.type,
            "line_items": [li.to_dict() for li in self.line_items],
        }


class StubAccountingApi:
    def __init__(self):
        self.accounts = [DummyAccount("200")]
        self.invoices = [DummyInvoice("200")]
        self.journals = [DummyJournal("200")]

    def get_accounts(self, tenant_id: str, **kwargs):
        return type("AccResp", (object,), {"accounts": self.accounts})

    def get_invoices(self, tenant_id: str, **kwargs):
        return type("InvResp", (object,), {"invoices": self.invoices})

    def get_journals(self, tenant_id: str, **kwargs):
        return type("JourResp", (object,), {"journals": self.journals})


@pytest.mark.asyncio
async def test_filter_rows_by_account_codes_filters_nested():
    rows = [
        {
            "rowType": "Section",
            "rows": [
                {
                    "rowType": "Row",
                    "cells": [
                        {"attributes": {"accountcode": "200"}},
                        {"value": "Sample"},
                    ],
                }
            ],
        }
    ]

    filtered = xero_mcp._filter_rows_by_account_codes(rows, ["200"])
    assert filtered and filtered[0].get("rows")

    filtered_missing = xero_mcp._filter_rows_by_account_codes(rows, ["999"])
    assert filtered_missing == []


@pytest.mark.asyncio
async def test_drill_down_accounts_only(monkeypatch: pytest.MonkeyPatch):
    api = StubAccountingApi()
    section = {
        "title": "Revenue",
        "rowType": "Section",
        "rows": [{"cells": [{"attributes": {"accountcode": "200"}}]}],
    }

    result = await xero_mcp._drill_down_section(api, "tenant", section, {}, "accounts", include_tx=False)
    assert "subAccounts" in result
    assert result["subAccounts"][0]["code"] == "200"


@pytest.mark.asyncio
async def test_drill_down_transactions(monkeypatch: pytest.MonkeyPatch):
    api = StubAccountingApi()

    async def fake_process(_api, tenant_id, args):
        return {"content": [{"type": "text", "text": json.dumps([{"invoiceID": "inv-1"}])}]}

    monkeypatch.setattr(xero_mcp, "_process_invoices_with_grouping", fake_process)

    section = {
        "title": "Expenses",
        "rowType": "Section",
        "rows": [{"cells": [{"attributes": {"accountcode": "200"}}]}],
    }

    args = {"fromDate": "2024-01-01", "toDate": "2024-01-31", "includeTransactions": True}
    result = await xero_mcp._drill_down_section(api, "tenant", section, args, "transactions", include_tx=True)

    assert "transactions" in result
    assert result["transactions"]
    assert result.get("journals")
