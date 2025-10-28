import { IMcpServerTool } from "../../Tools/IMcpServerTool.js";
import { z } from "zod";
import { Xero } from "../../xero/XeroClient.js";
import { withBackoff } from "../../Utils/backoff.js";

const Input = z.object({ invoiceId: z.string().min(1) });

export const XeroGetInvoice: IMcpServerTool = {
  requestSchema: {
    name: "xero.get_invoice",
    description: "Get a single invoice by ID",
    inputSchema: { type: "object", properties: {} },
    output: { content: [{ type: "text", text: z.string() }] },
  },
  requestHandler: async (request) => {
    const parsed = Input.safeParse(request.params.arguments || {});
    if (!parsed.success) {
      return { content: [{ type: "text", text: "invoiceId is required" }] } as any;
    }
    const { invoiceId } = parsed.data;
    const tenantId = Xero.activeTenantId()!!;
    const response = await withBackoff(() => Xero.xeroClient.accountingApi.getInvoice(tenantId, invoiceId));
    return { content: [{ type: "text", text: JSON.stringify(response.body.invoices?.[0] || null) }] };
  },
};


