import http from 'http';
import { startHttpServer } from '../src/http/server.js';

describe('MCP HTTP', () => {
  let server: http.Server;
  beforeAll(() => {
    process.env.NODE_ENV = 'test';
    process.env.PORT = '8089';
    server = startHttpServer();
  });
  afterAll(() => {
    server.close();
  });

  it('healthz returns ok', async () => {
    const res = await fetch('http://localhost:8089/xero/healthz');
    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body.status).toBe('ok');
  });
});


