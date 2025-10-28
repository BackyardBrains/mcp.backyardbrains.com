import http from 'http';
import { startHttpServer } from '../src/http/server.js';

describe('MCP POST /xero/mcp', () => {
  let server: http.Server;
  beforeAll(() => {
    process.env.NODE_ENV = 'test';
    server = startHttpServer();
  });
  afterAll(() => {
    server.close();
  });

  it('returns tool list on discover', async () => {
    const res = await fetch('http://localhost:8087/xero/mcp', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ method: 'discover' }),
    });
    expect(res.status).toBe(200);
    const body = await res.json();
    const names = (body.tools || []).map((t: any) => t.name);
    expect(names).toEqual(expect.arrayContaining([
      'xero.list_invoices',
      'xero.get_invoice',
      'xero.list_contacts',
      'xero.get_balance_sheet',
    ]));
  });
});


