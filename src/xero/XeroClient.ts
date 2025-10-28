import { XeroClient } from "xero-node";
import crypto from "crypto";
import fs from "fs";
import path from "path";

const defaultScopes = "offline_access openid profile accounting.transactions.read accounting.contacts.read accounting.journals.read accounting.reports.read";
function readEnv() {
  return {
    clientId: process.env.XERO_CLIENT_ID || "",
    clientSecret: process.env.XERO_CLIENT_SECRET || "",
    redirectUrl: process.env.XERO_REDIRECT_URI || "",
    scopes: (process.env.XERO_SCOPES || defaultScopes).split(" "),
  };
}

const TOKEN_STORE_PATH = process.env.TOKEN_STORE_PATH || path.join(process.cwd(), ".xero_tokens.enc");
const ENC_KEY = process.env.TOKEN_ENC_KEY || ""; // 32 bytes base64 recommended

function encrypt(plaintext: string): Buffer {
  if (!ENC_KEY) throw new Error("TOKEN_ENC_KEY is required for token encryption");
  const key = Buffer.from(ENC_KEY, "base64");
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ciphertext]);
}

function decrypt(blob: Buffer): string {
  const key = Buffer.from(ENC_KEY, "base64");
  const iv = blob.subarray(0, 12);
  const tag = blob.subarray(12, 28);
  const ciphertext = blob.subarray(28);
  const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(tag);
  const plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]).toString("utf8");
  return plaintext;
}

class XeroApi {
  xeroClient: XeroClient | undefined;
  private _activeTenantId: string | undefined;

  constructor() {}

  private ensureClient(): XeroClient {
    if (this.xeroClient) return this.xeroClient;
    const { clientId, clientSecret, redirectUrl, scopes } = readEnv();
    if (!clientId || !clientSecret || !redirectUrl) {
      throw new Error("Xero not configured. Set XERO_CLIENT_ID, XERO_CLIENT_SECRET, XERO_REDIRECT_URI.");
    }
    this.xeroClient = new XeroClient({ clientId, clientSecret, redirectUris: [redirectUrl], scopes });
    return this.xeroClient;
  }

  getClient(): XeroClient {
    return this.ensureClient();
  }

  async loadTokensIfPresent() {
    try {
      if (!fs.existsSync(TOKEN_STORE_PATH)) return;
      const client = this.ensureClient();
      const enc = fs.readFileSync(TOKEN_STORE_PATH);
      const json = decrypt(enc);
      const tokenSet = JSON.parse(json);
      client.setTokenSet(tokenSet);
      await client.updateTenants();
      if (!this._activeTenantId && client.tenants.length > 0) {
        this._activeTenantId = client.tenants[0].tenantId;
      }
    } catch {
      // ignore when not configured for local startup
    }
  }

  async persistTokens() {
    if (!this.xeroClient) return;
    const tokenSet = this.xeroClient.readTokenSet();
    if (!tokenSet) return;
    const json = JSON.stringify(tokenSet);
    const enc = encrypt(json);
    fs.writeFileSync(TOKEN_STORE_PATH, enc);
  }

  async refreshIfNeeded() {
    if (!this.xeroClient) return;
    const tokenSet = this.xeroClient.readTokenSet();
    if (!tokenSet) return;
    const expiresAt = (tokenSet as any).expires_at;
    if (expiresAt && Date.now() > expiresAt - 60_000) {
      await this.xeroClient.refreshToken();
      await this.persistTokens();
    }
  }

  isAuthenticated() {
    try {
      const client = this.ensureClient();
      return client.readTokenSet() ? true : false;
    } catch {
      return false;
    }
  }

  activeTenantId() {
    return this._activeTenantId;
  }

  setActiveTenantId(tenantId: string) {
    this._activeTenantId = tenantId;
  }
}

export const Xero = new XeroApi();

export async function getConsentUrl() {
  return await Xero.getClient().buildConsentUrl();
}

export async function loadPersistedTokens(callbackUrlWithQuery: string) {
  const client = Xero.getClient();
  const tokenSet = await client.apiCallback(callbackUrlWithQuery);
  client.setTokenSet(tokenSet);
  await client.updateTenants();
  if (client.tenants.length > 0) {
    Xero.setActiveTenantId(client.tenants[0].tenantId);
  }
  await Xero.persistTokens();
  return tokenSet;
}

export async function persistTokens() {
  await Xero.persistTokens();
}


