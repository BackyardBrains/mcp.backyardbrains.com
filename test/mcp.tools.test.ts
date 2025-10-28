import { listTools } from '../src/mcp/router.js';

describe('MCP tools', () => {
  it('includes required xero.* tools', () => {
    const names = listTools().map(t => t.name).sort();
    expect(names).toEqual(expect.arrayContaining([
      'xero.list_invoices',
      'xero.get_invoice',
      'xero.list_contacts',
      'xero.get_balance_sheet',
    ]));
  });
});


