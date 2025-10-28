import { McpToolsFactory } from "./tools.js";
import { Xero } from "../xero/XeroClient.js";

export function listTools() {
  return McpToolsFactory.getAllTools().map((t) => t.requestSchema);
}

export async function handleMcpCall(name: string, args: any) {
  const request: any = {
    jsonrpc: "2.0",
    id: null,
    method: "tools/call",
    params: { name, arguments: args, stream: false },
  };
  try {
    if (!Xero.isAuthenticated()) {
      return { content: [{ type: "text", text: "You must authenticate with Xero first" }] } as any;
    }
    const tool = McpToolsFactory.findToolByName(request.params.name);
    if (!tool) {
      return { content: [{ type: "text", text: `Error: Tool not found: ${name}` }] } as any;
    }
    await Xero.refreshIfNeeded();
    const res = await tool.requestHandler(request as any);
    await Xero.persistTokens();
    return res;
  } catch (error: any) {
    const message = (error?.message || String(error)).replace(/(client_secret|refresh_token|access_token)=[^&\s]+/gi, "$1=[REDACTED]");
    return { content: [{ type: "text", text: message }] } as any;
  }
}


