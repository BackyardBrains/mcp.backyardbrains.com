import http, { IncomingMessage, ServerResponse } from "http";
import url from "url";
import { handleMcpCall, listTools } from "../mcp/router.js";
import { getConsentUrl, loadPersistedTokens, persistTokens } from "../xero/XeroClient.js";

type JsonValue = any;

function readRequestBody(req: IncomingMessage, limitBytes: number): Promise<string> {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => {
      size += chunk.length;
      if (size > limitBytes) {
        reject(new Error("Request entity too large"));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sendJson(res: ServerResponse, status: number, body: JsonValue) {
  const data = JSON.stringify(body);
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json; charset=utf-8");
  res.setHeader("Content-Length", Buffer.byteLength(data));
  res.end(data);
}

function sendText(res: ServerResponse, status: number, text: string) {
  res.statusCode = status;
  res.setHeader("Content-Type", "text/plain; charset=utf-8");
  res.setHeader("Content-Length", Buffer.byteLength(text));
  res.end(text);
}

function isHttps(req: IncomingMessage): boolean {
  const xfProto = req.headers["x-forwarded-proto"];
  if (Array.isArray(xfProto)) return xfProto[0] === "https";
  if (typeof xfProto === "string") return xfProto === "https";
  return (req.socket as any).encrypted === true;
}

function requireHttps(req: IncomingMessage, res: ServerResponse): boolean {
  if (process.env.NODE_ENV === "production" && !isHttps(req)) {
    sendJson(res, 400, { error: "HTTPS required" });
    return false;
  }
  return true;
}

function requireBearerAuth(req: IncomingMessage, res: ServerResponse): boolean {
  const shared = process.env.MCP_SHARED_SECRET;
  if (!shared) return true;
  const header = Array.isArray(req.headers.authorization)
    ? req.headers.authorization[0]
    : req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (token !== shared) {
    sendJson(res, 401, { error: "Unauthorized" });
    return false;
  }
  return true;
}

type RateBucket = { tokens: number; lastRefillMs: number };
const rateBuckets = new Map<string, RateBucket>();
const RATE_LIMIT = Number(process.env.RATE_LIMIT_REQUESTS_PER_MINUTE || 60);

function rateLimit(req: IncomingMessage, res: ServerResponse): boolean {
  const ip = (req.socket.remoteAddress || "unknown").toString();
  const now = Date.now();
  const refillIntervalMs = 60_000;
  const capacity = RATE_LIMIT;
  let bucket = rateBuckets.get(ip);
  if (!bucket) {
    bucket = { tokens: capacity, lastRefillMs: now };
    rateBuckets.set(ip, bucket);
  }
  const elapsed = now - bucket.lastRefillMs;
  if (elapsed > refillIntervalMs) {
    bucket.tokens = capacity;
    bucket.lastRefillMs = now;
  }
  if (bucket.tokens <= 0) {
    sendJson(res, 429, { error: "Too Many Requests" });
    return false;
  }
  bucket.tokens -= 1;
  return true;
}

function jsonLogger(req: IncomingMessage, res: ServerResponse, start: number, extra?: Record<string, any>) {
  const durationMs = Date.now() - start;
  const record = {
    ts: new Date().toISOString(),
    method: req.method,
    path: req.url,
    status: res.statusCode,
    durationMs,
    ...extra,
  };
  console.log(JSON.stringify(record));
}

function redactHeaders(headers: http.IncomingHttpHeaders): Record<string, any> {
  const out: Record<string, any> = {};
  for (const [key, value] of Object.entries(headers)) {
    if (key.toLowerCase() === "authorization") {
      out[key] = "REDACTED";
    } else {
      out[key] = value;
    }
  }
  return out;
}

async function handleHealthz(_req: IncomingMessage, res: ServerResponse) {
  sendJson(res, 200, { status: "ok" });
}

async function handleAuth(_req: IncomingMessage, res: ServerResponse) {
  const url = await getConsentUrl();
  res.statusCode = 302;
  res.setHeader("Location", url);
  res.end();
}

async function handleCallback(req: IncomingMessage, res: ServerResponse) {
  try {
    const fullUrl = req.url || "/xero/callback";
    const tokenSet = await loadPersistedTokens(fullUrl);
    await persistTokens();
    sendText(res, 200, "Authenticated with Xero. You can close this window.");
  } catch (_err) {
    sendText(res, 500, "Authentication failed");
  }
}

async function handleMcp(req: IncomingMessage, res: ServerResponse) {
  const start = Date.now();
  if (!requireHttps(req, res)) return;
  if (!requireBearerAuth(req, res)) return;
  if (!rateLimit(req, res)) return;

  try {
    const bodyText = await readRequestBody(req, 1024 * 1024);
    if (process.env.MCP_DEBUG === "1") {
      const preview = bodyText.length > 1000 ? bodyText.slice(0, 1000) + "…" : bodyText;
      console.log(
        JSON.stringify({
          ts: new Date().toISOString(),
          event: "mcp_request",
          method: req.method,
          url: req.url,
          headers: redactHeaders(req.headers),
          bodyPreview: preview,
          bodyBytes: Buffer.byteLength(bodyText || ""),
        })
      );
    }
    let body: any = {};
    try {
      body = bodyText ? JSON.parse(bodyText) : {};
    } catch (_e) {
      body = {};
    }
    const method = String(body.method || body.type || "").toLowerCase();
    const id = body.id ?? null;

    const sendResult = (result: any) => {
      sendJson(res, 200, { jsonrpc: "2.0", id, result });
    };
    const sendError = (code: number, message: string, data?: any) => {
      sendJson(res, 200, { jsonrpc: "2.0", id, error: { code, message, data } });
    };
    if (method === "initialize") {
      const requestedVersion = body.params?.protocolVersion || "2025-06-18";
      const result = {
        protocolVersion: requestedVersion,
        capabilities: {},
        serverInfo: { name: "mcp-xero-http-server", version: "1.3.0" },
      };
      sendResult(result);
      jsonLogger(req, res, start, { mcpMethod: method });
      return;
    }
    if (method === "" || method === "discover" || method === "tools/list" || method === "actions/list") {
      const tools = listTools();
      sendResult({ tools });
      jsonLogger(req, res, start, { mcpMethod: method || "tools/list" });
      return;
    }
    if (
      method === "tools/call" ||
      method === "call_tool" ||
      method === "actions/call" ||
      method === "call_action"
    ) {
      const name = body.params?.name || body.name;
      const args = body.params?.arguments || body.arguments || {};
      const result = await handleMcpCall(name, args);
      sendResult(result);
      jsonLogger(req, res, start, { mcpMethod: method, toolName: name });
      return;
    }
    // JSON-RPC method not found
    sendError(-32601, "Method not found");
    jsonLogger(req, res, start, { mcpMethod: method || "unknown" });
  } catch (_err) {
    // On parse/runtime errors, reply with JSON-RPC parse error
    sendJson(res, 200, { jsonrpc: "2.0", id: null, error: { code: -32700, message: "Parse error" } });
  }
}

function notFound(_req: IncomingMessage, res: ServerResponse) {
  sendJson(res, 404, { error: "Not Found" });
}

export function startHttpServer() {
  const server = http.createServer(async (req, res) => {
    const start = Date.now();
    try {
      const parsed = url.parse(req.url || "");
      // Basic HEAD/OPTIONS support to satisfy various HTTP clients
      if (
        (req.method === "OPTIONS" || req.method === "HEAD") &&
        (parsed.pathname === "/xero" ||
          parsed.pathname === "/xero/" ||
          parsed.pathname === "/xero/mcp")
      ) {
        res.statusCode = req.method === "HEAD" ? 200 : 204;
        res.setHeader("Allow", "GET,POST,HEAD,OPTIONS");
        res.end();
        jsonLogger(req, res, start);
        return;
      }
      if (req.method === "GET" && parsed.pathname === "/xero/healthz") {
        return handleHealthz(req, res);
      }
      if (req.method === "GET" && parsed.pathname === "/xero/auth") {
        return handleAuth(req, res);
      }
      if (req.method === "GET" && parsed.pathname === "/xero/callback") {
        return handleCallback(req, res);
      }
      // Accept MCP at /xero/mcp (primary)
      if (req.method === "POST" && parsed.pathname === "/xero/mcp") {
        return handleMcp(req, res);
      }
      // Also accept POSTs directly to /xero and /xero/ for clients that don't append /mcp
      if (
        req.method === "POST" && (parsed.pathname === "/xero" || parsed.pathname === "/xero/")
      ) {
        return handleMcp(req, res);
      }
      // Friendly index for GET /xero and /xero/
      if (
        req.method === "GET" && (parsed.pathname === "/xero" || parsed.pathname === "/xero/")
      ) {
        return sendText(
          res,
          200,
          "Xero MCP server is running. POST MCP requests to /xero/mcp or /xero/."
        );
      }
      return notFound(req, res);
    } finally {
      jsonLogger(req, res, start);
    }
  });
  const port = Number(process.env.PORT || 8087);
  server.listen(port, () => {
    console.error(`HTTP server listening on :${port}`);
  });
  return server;
}


