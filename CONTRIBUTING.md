# Contributing

- Use Node 20, npm 10.
- Run: `npm ci && npm run build && npm test` before pushing.
- Do not log secrets; never print tokens or client secrets.
- Open PRs against `main`. CI must pass. Conventional commits preferred.

## Local dev

- Copy `.env.example` to `.env` and set:
  - XERO_CLIENT_ID, XERO_CLIENT_SECRET, XERO_REDIRECT_URI
  - TOKEN_ENC_KEY (base64 32 bytes)
  - MCP_SHARED_SECRET (optional)
- Start: `npm run start:dev` then call `POST /xero/mcp`.

## Release

- Tag with `vX.Y.Z` to publish image to GHCR.
