# Simple Xero MCP Server

This is a basic Model Context Protocol (MCP) server for integrating with Xero accounting API using Python and FastAPI.

## Features
- MCP endpoint for tool discovery and calls
- Basic Xero tools: list_invoices, get_balance_sheet
- Health check endpoint
- Stub for authentication

## Prerequisites
- Python 3.8+
- Xero Developer Account with API credentials

To run:

cd /var/www/mcp.backyardbrains.com
source ./venv/bin/activate
uvicorn app:app --host 0.0.0.0 --port 8087 --log-level info