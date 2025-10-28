import { z } from "zod";
import { Xero } from "../xero/XeroClient.js";
import { withBackoff } from "../Utils/backoff.js";

const ListInvoicesInput = z.object({
  status: z.enum(["DRAFT", "SUBMITTED", "AUTHORISED", "PAID"]).optional(),
  modifiedAfter: z.string().datetime().optional(),
  page: z.number().int().positive().optional(),
});

const XeroListInvoices = {
  requestSchema: {
    name: "xero.list_invoices",
    description: "List invoices",
    inputSchema: { type: "object", properties: {} },
    output: { content: [{ type: "text", text: z.string() }] },
  },
  requestHandler: async (request: any) => {
    const args = ListInvoicesInput.safeParse(request.params.arguments || {});
    if (!args.success) {
      return { content: [{ type: "text", text: "Invalid arguments" }] } as any;
    }
    const tenantId = Xero.activeTenantId()!!;
    const accounting = Xero.getClient().accountingApi;
    const where = args.data.status ? `Status==\"${args.data.status}\"` : undefined;
    const ifModifiedSince = args.data.modifiedAfter ? new Date(args.data.modifiedAfter) : undefined;
    const response: any = await withBackoff(() =>
      // Overload with optional params; satisfy type using explicit any for untyped SDK
      (accounting.getInvoices as any)(tenantId, ifModifiedSince, where, undefined, undefined, args.data.page)
    );
    const invoices = response.body?.invoices || [];
    return { content: [{ type: "text", text: JSON.stringify(invoices) }] };
  },
};

const GetInvoiceInput = z.object({ invoiceId: z.string().min(1) });
const XeroGetInvoice = {
  requestSchema: {
    name: "xero.get_invoice",
    description: "Get a single invoice by ID",
    inputSchema: { type: "object", properties: {} },
    output: { content: [{ type: "text", text: z.string() }] },
  },
  requestHandler: async (request: any) => {
    const parsed = GetInvoiceInput.safeParse(request.params.arguments || {});
    if (!parsed.success) {
      return { content: [{ type: "text", text: "invoiceId is required" }] } as any;
    }
    const { invoiceId } = parsed.data;
    const tenantId = Xero.activeTenantId()!!;
    const response = await withBackoff(() => Xero.getClient().accountingApi.getInvoice(tenantId, invoiceId));
    return { content: [{ type: "text", text: JSON.stringify(response.body.invoices?.[0] || null) }] };
  },
};

const ListContactsInput = z.object({ search: z.string().optional(), page: z.number().int().positive().optional() });
const XeroListContacts = {
  requestSchema: {
    name: "xero.list_contacts",
    description: "List contacts",
    inputSchema: { type: "object", properties: {} },
    output: { content: [{ type: "text", text: z.string() }] },
  },
  requestHandler: async (request: any) => {
    const args = ListContactsInput.safeParse(request.params.arguments || {});
    if (!args.success) {
      return { content: [{ type: "text", text: "Invalid arguments" }] } as any;
    }
    const tenantId = Xero.activeTenantId()!!;
    const where = args.data.search ? `Name.Contains(\"${args.data.search}\")` : undefined;
    const response = await withBackoff(() =>
      Xero.getClient().accountingApi.getContacts(tenantId, undefined, where, undefined, undefined, args.data.page)
    );
    const contacts = response.body.contacts || [];
    return { content: [{ type: "text", text: JSON.stringify(contacts) }] };
  },
};

const GetBalanceSheetInput = z.object({ date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional() });
const XeroGetBalanceSheet = {
  requestSchema: {
    name: "xero.get_balance_sheet",
    description: "Get balance sheet as of date",
    inputSchema: { type: "object", properties: {} },
    output: { content: [{ type: "text", text: z.string() }] },
  },
  requestHandler: async (request: any) => {
    const args = GetBalanceSheetInput.safeParse(request.params.arguments || {});
    if (!args.success) {
      return { content: [{ type: "text", text: "Invalid arguments" }] } as any;
    }
    const tenantId = Xero.activeTenantId()!!;
    const response = await withBackoff(() =>
      Xero.getClient().accountingApi.getReportBalanceSheet(tenantId, args.data.date)
    );
    const reports = response.body.reports || [];
    return { content: [{ type: "text", text: JSON.stringify(reports) }] };
  },
};

export const McpToolsFactory = (function () {
  const tools = [
    XeroListInvoices,
    XeroGetInvoice,
    XeroListContacts,
    XeroGetBalanceSheet,
  ];
  return {
    getAllTools() {
      return tools.slice();
    },
    findToolByName(name: string) {
      return tools.find((t) => t.requestSchema.name === name);
    },
  };
})();


