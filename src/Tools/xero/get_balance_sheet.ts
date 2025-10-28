import { IMcpServerTool } from "../../Tools/IMcpServerTool.js";
import { z } from "zod";
import { Xero } from "../../xero/XeroClient.js";
import { withBackoff } from "../../Utils/backoff.js";

const Input = z.object({ date: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional() });

export const XeroGetBalanceSheet: IMcpServerTool = {
  requestSchema: {
    name: "xero.get_balance_sheet",
    description: "Get balance sheet as of date",
    inputSchema: { type: "object", properties: {} },
    output: { content: [{ type: "text", text: z.string() }] },
  },
  requestHandler: async (request) => {
    const args = Input.safeParse(request.params.arguments || {});
    if (!args.success) {
      return { content: [{ type: "text", text: "Invalid arguments" }] } as any;
    }
    const tenantId = Xero.activeTenantId()!!;
    const response = await withBackoff(() =>
      Xero.xeroClient.accountingApi.getReportBalanceSheet(tenantId, args.data.date)
    );
    const reports = response.body.reports || [];
    return { content: [{ type: "text", text: JSON.stringify(reports) }] };
  },
};


