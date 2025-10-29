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

/etc/nginx/sites-available/mcp.backyardbrains.com
server {
    if ($host = mcp.backyardbrains.com) {
        return 301 https://$host$request_uri;
    } # managed by Certbot


  listen 80;
  server_name mcp.backyardbrains.com;
  return 301 https://$host$request_uri;


}

server {
  listen 443 ssl http2;
  server_name mcp.backyardbrains.com;

  # Optional: small cap for safety
  client_max_body_size 1m;

  # Health check (optional explicit path)
  location = /xero/healthz {
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_pass http://127.0.0.1:8087;
  }

  # Route all /xero/* to the MCP server
  location /xero/ {
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_http_version 1.1;
    proxy_read_timeout 300s;
    proxy_pass http://127.0.0.1:8087;
  }

    ssl_certificate /etc/letsencrypt/live/mcp.backyardbrains.com/fullchain.pem; # managed by Certbot
    ssl_certificate_key /etc/letsencrypt/live/mcp.backyardbrains.com/privkey.pem; # managed by Certbot
}

To run:

cd /var/www/mcp.backyardbrains.com
source ./venv/bin/activate
uvicorn app:app --host 0.0.0.0 --port 8087 --log-level info