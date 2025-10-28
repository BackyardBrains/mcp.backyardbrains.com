#!/usr/bin/env node
import 'dotenv/config';
import { startHttpServer } from "./http/server.js";
import { Xero } from "./xero/XeroClient.js";

async function main() {
  await Xero.loadTokensIfPresent();
  startHttpServer();
}

main().catch((error) => {
  console.error("Failed to start server:", error);
  process.exit(1);
});