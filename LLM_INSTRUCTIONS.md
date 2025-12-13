# BYB Xero MCP Integration Instructions

## Core Policy: Official Data Only

**All financial data must come exclusively from BYB Xero MCP tools. Never fabricate, estimate, or infer any accounting figures.**

### Available MCP Tools
`xero_list_invoices`, `xero_list_payments`, `xero_list_bank_transactions`, `xero_get_balance_sheet`, `xero_get_profit_and_loss`, `xero_list_accounts`, `xero_list_contacts`, `xero_list_tracking_categories`, `xero_list_manual_journals`, `xero_list_items`, `xero_list_bills`

### Mandatory Response When Data Unavailable
**"I don't have the data to answer that."**

### Data Integrity Rules
1. All figures must be directly sourced from BYB Xero MCP responses
2. Derived calculations allowed ONLY when both inputs are verified from Xero
3. No rounding, estimation, or synthetic data permitted
4. When tool calls fail or return empty, explicitly state the limitation
5. Always include: "These figures were retrieved directly from BYB Xero data."

---

## Tracking Categories

**BYB uses 2 tracking categories:**
1. **"Who Pays"** - Grant accounting
2. **"project"** - Project/conference tracking

**Always retrieve IDs first:**
```
Tool: xero_list_tracking_categories
Returns: trackingCategoryID and trackingOptionID (UUIDs)
```
**Never hardcode tracking IDs** - retrieve dynamically.

---

## Sales by Country

**Tool:** `xero_list_invoices`

**Example:**
```json
{
  "dateFrom": "2025-01-01",
  "dateTo": "2025-03-31",
  "groupBy": ["country"],
  "metrics": ["total", "countInvoices"],
  "statuses": ["PAID", "AUTHORISED"]
}
```

**Returns:** Revenue totals and invoice counts grouped by customer country

**Key Points:**
- Use ISO dates: `YYYY-MM-DD`
- Filter by `statuses` to exclude drafts/voids
- Combine dimensions: `["country", "month"]` for time-series
- For grant-specific: use `xero_get_profit_and_loss` with "Who Pays" tracking ID

---

## Sales by Product

**Tool:** `xero_list_invoices`

**Example:**
```json
{
  "dateFrom": "2025-01-01",
  "dateTo": "2025-03-31",
  "groupBy": ["product"],
  "metrics": ["quantity", "subtotal", "countInvoices"],
  "statuses": ["PAID", "AUTHORISED"]
}
```

**Returns:** Quantity sold, revenue, and invoice count per product

**Key Points:**
- `quantity` = units sold
- `subtotal` = pre-tax revenue
- `total` = revenue with tax
- Filter specific items: `"itemCodes": ["PROD-001"]`
- Multi-dimensional: `["product", "month"]` for trends

---

## Grant Analysis (Using "Who Pays" Tracking)

**Tool:** `xero_get_profit_and_loss`

**Workflow:**
1. Get tracking ID: `xero_list_tracking_categories` → find "Who Pays" → note `trackingCategoryId`
2. Query P&L filtered by tracking category:
```json
{
  "fromDate": "2025-01-01",
  "toDate": "2025-03-31",
  "trackingCategoryID": "xxx-id-xxx",
  "trackingOptionID": "xxx-grant-id-xxx"
}
```

**Returns:** Income and expenses specific to that grant.

---

## Project/Conference Analysis (Using "project" Tracking)

**Tool:** `xero_get_profit_and_loss`

**Conference spending example:**
```json
{
  "fromDate": "2025-11-01",
  "toDate": "2025-11-30",
  "trackingCategoryID": "xxx-project-id-xxx",
  "trackingOptionID": "xxx-conference-id-xxx"
}
```

**Returns:** Income and expenses for the specific project/conference.

---

## Product Margins

**Tool:** `xero_list_items`

**Example:**
```json
{}
```

**Returns:** Product catalog with `SalesDetails.UnitPrice` and `PurchaseDetails.UnitPrice`

**Key Points:**
- Calculate margins: `(SalesPrice - CostPrice) / SalesPrice`
- Identify high-margin vs low-margin products
- Filter with `updatedSince` for recent changes

---

## Finding Old/Overdue Bills

**Tool:** `xero_list_bills`

**Example (Overdue bills):**
```json
{
  "overdue": true,
  "statuses": ["AUTHORISED"]
}
```

**Example (Bills due before specific date):**
```json
{
  "dueDateTo": "2025-10-01",
  "statuses": ["AUTHORISED"]
}
```

**Returns:** Bills (ACCPAY invoices) filtered by status and due date

**Key Points:**
- `overdue: true` finds bills due before today
- `dueDateTo` finds bills due on or before a specific date
- Default status is `["AUTHORISED"]` (unpaid bills)
- Sorted by `DueDate ASC` by default

---

## Quick Reference

| Query | Tool | Key Parameters |
|-------|------|----------------|
| Sales by country | `xero_list_invoices` | `groupBy: ["country"]` |
| Sales by product | `xero_list_invoices` | `groupBy: ["product"]`, `metrics: ["quantity", "total"]` |
| Top customers | `xero_list_invoices` | `groupBy: ["customer"]` |
| Monthly trend | `xero_list_invoices` | `groupBy: ["month"]` |
| Grant profitability | `xero_get_profit_and_loss` | `trackingCategoryID`, `trackingOptionID` |
| Conference spending | `xero_get_profit_and_loss` | `trackingCategoryID`, `trackingOptionID` |
| P&L | `xero_get_profit_and_loss` | `fromDate`, `toDate` |
| Balance sheet | `xero_get_balance_sheet` | `date: "YYYY-MM-DD"` |
| Product margins | `xero_list_items` | None required |
| Overdue bills | `xero_list_bills` | `overdue: true` |

---

## Metrics Guide
- `total` = invoice total with tax
- `subtotal` = before tax
- `quantity` = items sold
- `countInvoices` = number of invoices

---

## Ethical Requirements

1. Preserve audit integrity - no data modification
2. Only BYB Xero verified records are authoritative
3. No "inferred," "sample," or "representative" data
4. Every result must state it came from BYB Xero
5. No illustrative figures in accounting context
6. When unavailable: "I don't have the data to answer that."

**This standard is non-negotiable for audit reliability.**

---

**Authentication:** OAuth2 via Auth0 with `mcp:read:xero` scope.
