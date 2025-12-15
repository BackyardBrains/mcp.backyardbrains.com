# Python Xero MCP Server for BYB

This is a Model Context Protocol (MCP) server for integrating with Xero accounting API using Python and FastAPI.

## Prerequisites
- Python 3.8+
- Xero Developer Account with API credentials

## Running the Server

```bash
cd /var/www/mcp.backyardbrains.com
source ./venv/bin/activate
uvicorn app:app --host 0.0.0.0 --port 8087 --log-level info
```

---

# 📊 LLM USAGE GUIDE: Key Xero Reports & Tracking Categories

This section explains how to use the Xero MCP tools to get common financial reports and how to leverage tracking categories for detailed analysis.

## 🏷️ Tracking Categories Overview

**Backyard Brains uses 2 tracking categories:**

1. **"Who Pays"** - Grant accounting (charges to grants vs. direct funds charged)
2. **"project"** - Project tracking (conferences, etc.)

**How to get tracking category IDs:**
```
Use: xero_list_tracking_categories

This returns all tracking categories with their IDs and options. You'll need the trackingCategoryID for filtering reports.
```

---

## 📈 Top Sales Reports

### 1. Sales by Country for a Time Period

**Purpose:** Analyze revenue by customer country over a specific date range.

**Tool:** `xero_list_invoices`

**Example Request:**
```json
{
  "dateFrom": "2025-01-01",
  "dateTo": "2025-03-31",
  "groupBy": ["country"],
  "metrics": ["total", "countInvoices"],
  "statuses": ["PAID", "AUTHORISED"]
}
```

**What it returns:** Revenue totals and invoice counts grouped by customer country.

**With Tracking Category (e.g., by grant):**
```json
{
  "dateFrom": "2025-01-01",
  "dateTo": "2025-03-31",
  "groupBy": ["country"],
  "metrics": ["total"]
}
```
Then filter invoices manually by looking at tracking data in line items, or use `xero_get_profit_and_loss` for grant-specific analysis.

---

### 2. Sales by Product for a Time Period

**Purpose:** Analyze which products/items sold best during a period.

**Tool:** `xero_list_invoices`

**Example Request:**
```json
{
  "dateFrom": "2025-01-01",
  "dateTo": "2025-03-31",
  "groupBy": ["product"],
  "metrics": ["quantity", "subtotal", "countInvoices"],
  "statuses": ["PAID", "AUTHORISED"],
  "includeLineItems": true
}
```

**What it returns:** Shows quantity sold, revenue, and invoice count for each product/item code.

**To filter specific products only:**
```json
{
  "dateFrom": "2025-01-01",
  "dateTo": "2025-03-31",
  "groupBy": ["product"],
  "metrics": ["quantity", "subtotal"],
  "itemCodes": ["PROD-001", "PROD-002"]
}
```

---

### 3. Sales by Customer for a Time Period

**Purpose:** Identify top customers by revenue.

**Tool:** `xero_list_invoices`

**Example Request:**
```json
{
  "dateFrom": "2025-01-01",
  "dateTo": "2025-03-31",
  "groupBy": ["customer"],
  "metrics": ["total", "countInvoices"],
  "statuses": ["PAID", "AUTHORISED"]
}
```

**What it returns:** Revenue and invoice counts per customer, ranked by total.

---

### 4. Multi-Dimensional Analysis

**Purpose:** Combine multiple dimensions for deep insights.

**Example: Sales by Product AND Country:**
```json
{
  "dateFrom": "2025-01-01",
  "dateTo": "2025-03-31",
  "groupBy": ["product", "country"],
  "metrics": ["quantity", "total"]
}
```

**Example: Sales by Month AND Product:**
```json
{
  "dateFrom": "2025-01-01",
  "dateTo": "2025-12-31",
  "groupBy": ["month", "product"],
  "metrics": ["quantity", "subtotal"]
}
```

---

## 💰 Grant & Project Tracking Reports

### 5. Revenue/Expenses by Grant (Using "Who Pays" Tracking)

**Purpose:** See all revenue and expenses for each grant or funding source.

**Tool:** `xero_get_profit_and_loss`

**First, get the tracking category ID:**
```json
Use: xero_list_tracking_categories
Find "Who Pays" and note its trackingCategoryId
```

**Example Request:**
```json
{
  "trackingCategoryID": "xxx-tracking-category-id-xxx",
  "fromDate": "2025-01-01",
  "toDate": "2025-03-31"
}
```

**What it returns:**
- Income and Expenses for the grant
- Net Profit/Loss for the grant

**To analyze a specific grant only:**
```json
{
  "trackingCategoryID": "xxx-tracking-category-id-xxx",
  "trackingOptionID": "xxx-grant-option-id-xxx",
  "fromDate": "2025-01-01",
  "toDate": "2025-03-31"
}
```

---

### 6. Revenue/Expenses by Project (Using "project" Tracking)

**Purpose:** Track spending and revenue for specific projects (e.g., conferences).

**Tool:** `xero_get_profit_and_loss`

**Example Request (all projects):**
```json
{
  "trackingCategoryID": "xxx-project-tracking-id-xxx",
  "fromDate": "2025-01-01",
  "toDate": "2025-12-31"
}
```

**Example Request (conference spending only):**
```json
```json
{
  "trackingCategoryID": "xxx-project-tracking-id-xxx",
  "trackingOptionID": "xxx-conference-option-id-xxx",
  "fromDate": "2025-11-01",
  "toDate": "2025-11-30"
}
```


---

## 📊 Financial Statement Reports

### 7. Profit & Loss (Income Statement)

**Purpose:** Overall financial performance for a period.

**Tool:** `xero_get_profit_and_loss`

**Basic Request:**
```json
{
  "fromDate": "2025-01-01",
  "toDate": "2025-03-31"
}
```

**With Tracking Category Filter (e.g., specific grant):**
```json
{
  "fromDate": "2025-01-01",
  "toDate": "2025-03-31",
  "trackingCategoryID": "xxx-tracking-category-id-xxx",
  "trackingOptionID": "xxx-specific-option-id-xxx"
}
```

**With Comparative Periods:**
```json
{
  "fromDate": "2025-07-01",
  "toDate": "2025-09-30",
  "periods": 4,
  "timeframe": "QUARTER"
}
```
Shows Q3 2025 compared to previous 4 quarters.

**Drill-down by account/transactions:**
```json
{
  "fromDate": "2025-01-01",
  "toDate": "2025-03-31",
  "detailLevel": "transactions",
  "includeTransactions": true,
  "accountCodes": ["200"]
}
```
Returns standard P&L rows plus `subDetails` that include matching sub-accounts, linked invoices/bills, and journals filtered to the same account codes. Chain the account codes into `xero_get_journals` for an even deeper ledger view.

---

### 8. Balance Sheet

**Purpose:** Financial position at a specific date.

**Tool:** `xero_get_balance_sheet`

**Basic Request:**
```json
{
  "date": "2025-03-31"
}
```

**With Tracking Category:**
```json
{
  "date": "2025-03-31",
  "trackingCategoryID": "xxx-tracking-category-id-xxx",
  "trackingOptionID": "xxx-option-id-xxx"
}
```

---

### 9. Product Catalog (Items)

**Purpose:** Retrieve product/service catalog with cost and sales prices for margin analysis.

**Tool:** `xero_list_items`

**Example:**
```json
{}
```

**What it returns:** All items with:
- `Code` - Item code
- `Name` - Item description
- `SalesDetails.UnitPrice` - Sales price
- `PurchaseDetails.UnitPrice` - Cost price
- Inventory tracking settings

**For margin analysis:**
Calculate: `(SalesPrice - CostPrice) / SalesPrice * 100` for margin percentage.


### 10. Bills (Accounts Payable)

**Purpose:** Find unpaid or overdue bills to manage cash flow.

**Tool:** `xero_list_bills`

**Example (All overdue bills):**
```json
{
  "overdue": true,
  "statuses": ["AUTHORISED"]
}
```

**Example (Bills due before a specific date):**
```json
{
  "dueDateTo": "2025-10-01",
  "statuses": ["AUTHORISED"]
}
```

**What it returns:**
- Bills (ACCPAY invoices) matching your filters
- Sorted by due date (oldest first)
- Includes contact, amount, and due date info

**Common use cases:**
- "Show me all overdue bills" → `{"overdue": true}`
- "Bills due in the next 30 days" → Use `dueDateTo` with date 30 days from now
- "Show paid bills from last month" → `{"statuses": ["PAID"], "dateFrom": "2025-10-01", "dateTo": "2025-10-31"}`

---

## 🎯 Quick Reference: Most Common Use Cases

| What You Want | Tool to Use | Key Parameters |
|---------------|-------------|----------------|
| **Sales by country** | `xero_list_invoices` | `groupBy: ["country"]`, `metrics: ["total"]` |
| **Sales by product** | `xero_list_invoices` | `groupBy: ["product"]`, `metrics: ["quantity", "total"]` |
| **Top customers** | `xero_list_invoices` | `groupBy: ["customer"]`, `metrics: ["total"]` |
| **Monthly sales trend** | `xero_list_invoices` | `groupBy: ["month"]`, `metrics: ["total"]` |
| **Grant profitability** | `xero_get_profit_and_loss` | `trackingCategoryID`, `trackingOptionID` |
| **Conference spending** | `xero_get_profit_and_loss` | `trackingCategoryID`, `trackingOptionID` |
| **P&L for grant** | `xero_get_profit_and_loss` | `trackingCategoryID`, `trackingOptionID` |
| **Overall P&L** | `xero_get_profit_and_loss` | `fromDate`, `toDate` |
| **Balance sheet** | `xero_get_balance_sheet` | `date: "YYYY-MM-DD"` |
| **Product margins** | `xero_list_items` | None required |
| **Overdue bills** | `xero_list_bills` | `overdue: true` |
| **Old bills (30+ days)** | `xero_list_bills` | `dueDateTo: "[30 days ago]"` |

---

## 💡 Pro Tips for LLMs

1. **Always use ISO date format:** `YYYY-MM-DD` (e.g., "2025-03-31")

2. **Get tracking IDs first:** Before filtering by tracking categories, call `xero_list_tracking_categories` to get the correct UUIDs.

3. **Multi-dimensional grouping is powerful:** You can combine multiple dimensions like `["month", "product", "country"]` for deep analysis.

4. **Filter by invoice status:** Use `"statuses": ["PAID", "AUTHORISED"]` to exclude drafts and voided invoices.

5. **Use metrics wisely:**
   - `total` = full invoice total (with tax)
   - `subtotal` = before tax
   - `quantity` = items sold
   - `countInvoices` = number of invoices

6. **Tracking profitability vs. P&L:**
   - Use `xero_get_profit_and_loss` with tracking filters for grant/project analysis

7. **Pagination:** Most list tools support `page` parameter for large datasets.

---

## 🔧 Other Useful Tools

- `xero_list_contacts` - Get customer/supplier details
- `xero_create_contacts` - Create new contacts
- `xero_list_bank_transactions` - Bank account transactions
- `xero_create_bank_transactions` - Create bank transactions
- `xero_list_payments` - Payment records
- `xero_list_accounts` - Chart of accounts
- `xero_list_manual_journals` - Manual journals with flexible filtering
- `xero_get_cash_summary` - Retrieve Cash Summary report
- `xero_list_organisations` - Get organisation details
- `xero_list_quotes` - Retrieve quotes


---

**Need help?** All tools support OAuth2 authentication via Auth0. Ensure you have `mcp:read:xero` scope for read operations.
