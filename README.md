# MCP Xero HTTP Server

![](https://badge.mcpx.dev?type=server "MCP Server")
[![smithery badge](https://smithery.ai/badge/@john-zhang-dev/xero-mcp)](https://smithery.ai/server/@john-zhang-dev/xero-mcp)

Production-ready HTTP-hosted MCP server exposing Xero tools under `/xero/*`.

## Get Started

1. Make sure [node](https://nodejs.org) and [Claude Desktop](https://claude.ai/download) are installed.

2. Create an OAuth 2.0 app in Xero to get a _CLIENT_ID_ and _CLIENT_SECRET_.

   - Create a free Xero user account (if you don't have one)
   - Login to Xero Developer center https://developer.xero.com/app/manage/
   - Click New app
   - Enter a name for your app
   - Select Web app
   - Provide a valid URL (can be anything valid eg. https://www.myapp.com)
   - Enter redirect URI: `https://mcp.backyardbrains.com/xero/callback` (for prod) or `http://localhost:8087/xero/callback` (for local)
   - Tick to Accept the Terms & Conditions and click Create app
   - On the left-hand side of the screen select Configuration
   - Click Generate a secret

3. To register in ChatGPT: Settings → Apps & Connectors → Create → URL: `https://mcp.backyardbrains.com/xero/mcp`.

   ```json
   {
     "mcpServers": {
       "xero-mcp": {
         "command": "npx",
         "args": ["-y", "xero-mcp@latest"],
         "env": {
           "XERO_CLIENT_ID": "YOUR_CLIENT_ID",
           "XERO_CLIENT_SECRET": "YOUR_CLIENT_SECRET",
           "XERO_REDIRECT_URI": "http://localhost:5000/callback"
         }
       }
     }
   }
   ```

4. Restart Claude Desktop

5. First call will require OAuth: approve Xero; the server stores encrypted tokens.

## HTTP Endpoints

- `GET /xero/healthz` → `{"status":"ok"}`
- `POST /xero/mcp` → MCP JSON request; supports SSE when `Accept: text/event-stream` or `params.stream=true`.
- `GET /xero/callback` → Xero OAuth2 callback.

Auth: optional Bearer header using `MCP_SHARED_SECRET`.

### Sample curl

```bash
curl -sS https://mcp.backyardbrains.com/xero/healthz

curl -sS -X POST \
  -H 'content-type: application/json' \
  -H 'authorization: Bearer ${MCP_SHARED_SECRET}' \
  https://mcp.backyardbrains.com/xero/mcp \
  -d '{"method":"discover"}'
```

### Manual verification checklist

- GET `/xero/healthz` returns `{ "status": "ok" }`.
- POST `/xero/mcp` discover returns tool list with `xero.*` tools.
- Complete OAuth and confirm tokens are written to `TOKEN_STORE_PATH` (encrypted).
- Call `xero.list_invoices` with no params returns a page of invoices.
- Call `xero.get_balance_sheet` with a date returns balance sheet report.

   **Privacy alert: after completing the Xero OAuth2 flow, your Xero data may go through the LLM that you use. If you are doing testing you should authorize to your [Xero Demo Company](https://central.xero.com/s/article/Use-the-demo-company).**

## Tools

The server currently exposes:
  - `xero.list_invoices`
  - `xero.get_invoice`
  - `xero.list_contacts`
  - `xero.get_balance_sheet`

- `create_bank_transactions`

  Creates one or more spent or received money transaction

- `create_contacts`

  Creates one or multiple contacts in a Xero organisation

- `get_balance_sheet`

  Retrieves report for balancesheet

- `list_accounts`

  Retrieves the full chart of accounts

- `list_bank_transactions`

  Retrieves any spent or received money transactions

- `list_contacts`

  Retrieves all contacts in a Xero organisation

- `list_invoices`

  Retrieves sales invoices or purchase bills

- `list_journals`

  Retrieves journals

- `list_organisations`

  Retrieves Xero organisation details

- `list_payments`

  Retrieves payments for invoices and credit notes

- `list_quotes`

  Retrieves sales quotes

## Examples

- "Visualize my financial position over the last month"

    <img src="https://github.com/john-zhang-dev/assets/blob/main/xero-mcp/demo1.jpg?raw=true" width=50% height=50%>

- "Track my spendings over last week"

    <img src="https://github.com/john-zhang-dev/assets/blob/main/xero-mcp/demo2.jpg?raw=true" width=50% height=50%>

- "Add all transactions from the monthly statement into my revenue account (account code 201) as receive money"

## Deploy (non-Docker)

- Provision a Node 20 environment on your server.
- Set environment variables (e.g., in a systemd unit or your shell):
  - XERO_CLIENT_ID, XERO_CLIENT_SECRET, XERO_REDIRECT_URI=https://mcp.backyardbrains.com/xero/callback
  - TOKEN_ENC_KEY (32-byte base64), TOKEN_STORE_PATH
  - MCP_SHARED_SECRET (optional)
- Clone repo, run `npm ci && npm run build`.
- Start: `node build/index.js` (wrap with pm2/systemd).
- Route `https://mcp.backyardbrains.com/xero/*` to this server (via your existing reverse proxy).

## Troubleshooting

- 401 from Xero: refresh tokens may be expired; re-auth via consent flow.
- 429 rate limit: the server retries with backoff; consider reducing calls.
- SSE not negotiated: ensure `Accept: text/event-stream` or `params.stream=true`.
