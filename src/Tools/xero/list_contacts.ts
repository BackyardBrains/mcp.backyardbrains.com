import { IMcpServerTool } from "../../Tools/IMcpServerTool.js";
import { z } from "zod";
import { Xero } from "../../xero/XeroClient.js";
import { withBackoff } from "../../Utils/backoff.js";

const Input = z.object({ search: z.string().optional(), page: z.number().int().positive().optional() });

export const XeroListContacts: IMcpServerTool = {
  requestSchema: {
    name: "xero.list_contacts",
    description: "List contacts",
    inputSchema: { type: "object", properties: {} },
    output: { content: [{ type: "text", text: z.string() }] },
  },
  requestHandler: async (request) => {
    const args = Input.safeParse(request.params.arguments || {});
    if (!args.success) {
      return { content: [{ type: "text", text: "Invalid arguments" }] } as any;
    }
    const tenantId = Xero.activeTenantId()!!;
    const where = args.data.search ? `Name.Contains(\\\"${args.data.search}\\\")` : undefined;
    const response = await withBackoff(() =>
      Xero.xeroClient.accountingApi.getContacts(
        tenantId,
        undefined,
        where,
        undefined,
        undefined,
        args.data.page
      )
    );
    const contacts = response.body.contacts || [];
    return { content: [{ type: "text", text: JSON.stringify(contacts) }] };
  },
};


